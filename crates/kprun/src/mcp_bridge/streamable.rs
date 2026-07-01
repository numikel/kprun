//! Streamable HTTP transport (MCP 2025-03-26+): one POST per client message;
//! each response is plain JSON or a per-response SSE stream.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use kprun_core::{KprunError, Result};

use super::sse::SseParser;
use super::{emit_rpc_error, http_err, write_frame, BridgeConfig};

pub enum InitOutcome {
    /// 2xx — response not yet forwarded; pass to `finish_initialize`.
    Ready(ureq::http::Response<ureq::Body>),
    /// 401/403 — auth failure; never triggers legacy fallback.
    Unauthorized(u16),
    /// Other 4xx — pre-2025-03-26 server; caller may fall back to HTTP+SSE.
    FallbackToLegacy(u16),
}

enum PostOutcome {
    Done,
    SessionExpired,
}

pub struct Session {
    post_agent: ureq::Agent,
    url: String,
    headers: Vec<(String, String)>,
    session_id: Option<String>,
    protocol_version: Option<String>,
    /// Raw initialize frame, kept byte-for-byte for transparent re-init.
    init_frame: String,
}

impl Session {
    pub fn new(cfg: &BridgeConfig, init_frame: String) -> Self {
        let post_agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_connect(Some(Duration::from_secs(10)))
            .timeout_global(Some(cfg.timeout))
            .build()
            .into();
        Session {
            post_agent,
            url: cfg.url.clone(),
            headers: cfg.headers.clone(),
            session_id: None,
            protocol_version: None,
            init_frame,
        }
    }

    fn post_raw(&self, frame: &str) -> Result<ureq::http::Response<ureq::Body>> {
        let mut req = self
            .post_agent
            .post(&self.url)
            .header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json");
        for (name, value) in &self.headers {
            req = req.header(name.as_str(), value.as_str());
        }
        if let Some(sid) = &self.session_id {
            req = req.header("Mcp-Session-Id", sid.as_str());
        }
        if let Some(version) = &self.protocol_version {
            req = req.header("MCP-Protocol-Version", version.as_str());
        }
        req.send(frame).map_err(http_err)
    }

    pub fn initialize(&mut self) -> Result<InitOutcome> {
        let frame = self.init_frame.clone();
        let resp = self.post_raw(&frame)?;
        let status = resp.status().as_u16();
        match status {
            200..=299 => Ok(InitOutcome::Ready(resp)),
            401 | 403 => Ok(InitOutcome::Unauthorized(status)),
            400..=499 => Ok(InitOutcome::FallbackToLegacy(status)),
            _ => Err(KprunError::Other(format!(
                "initialize failed: HTTP {status}"
            ))),
        }
    }

    /// Capture session id + negotiated protocol version, then forward the
    /// initialize response to stdout.
    pub fn finish_initialize(&mut self, mut resp: ureq::http::Response<ureq::Body>) -> Result<()> {
        self.capture_session(&resp);
        let mime = resp.body().mime_type().unwrap_or("").to_string();
        if mime.starts_with("text/event-stream") {
            let reader = resp.body_mut().as_reader();
            for event in SseParser::new(reader) {
                let event = event?;
                if event.data.is_empty() {
                    continue;
                }
                self.capture_protocol_version(&event.data);
                write_frame(&event.data);
            }
        } else {
            let text = resp.body_mut().read_to_string().map_err(http_err)?;
            let text = text.trim_end();
            if !text.is_empty() {
                self.capture_protocol_version(text);
                write_frame(text);
            }
        }
        Ok(())
    }

    fn capture_session(&mut self, resp: &ureq::http::Response<ureq::Body>) {
        if let Some(sid) = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
        {
            self.session_id = Some(sid.to_string());
        }
    }

    /// Transport metadata only: the negotiated version feeds the
    /// MCP-Protocol-Version request header. The frame itself is forwarded
    /// verbatim regardless.
    fn capture_protocol_version(&mut self, frame: &str) {
        if self.protocol_version.is_some() {
            return;
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(frame) {
            if let Some(version) = value
                .pointer("/result/protocolVersion")
                .and_then(|v| v.as_str())
            {
                self.protocol_version = Some(version.to_string());
            }
        }
    }

    /// POST one client frame and forward whatever comes back. Survives
    /// individual request failures (JSON-RPC -32603 + stderr detail).
    pub fn handle_frame(&mut self, frame: &str) {
        for attempt in 0..2 {
            match self.post_and_forward(frame) {
                Ok(PostOutcome::Done) => return,
                Ok(PostOutcome::SessionExpired) if attempt == 0 => {
                    // Spec MUST: 404 on a session-carrying request → new
                    // InitializeRequest, then retry the original frame.
                    if let Err(e) = self.reinitialize() {
                        eprintln!("kprun mcp: session re-initialization failed: {e}");
                        break;
                    }
                }
                Ok(PostOutcome::SessionExpired) => {
                    eprintln!("kprun mcp: session expired again after re-initialization");
                    break;
                }
                Err(e) => {
                    eprintln!("kprun mcp: request failed: {e}");
                    break;
                }
            }
        }
        emit_rpc_error(frame, "kprun mcp: upstream request failed");
    }

    fn post_and_forward(&mut self, frame: &str) -> Result<PostOutcome> {
        let mut resp = self.post_raw(frame)?;
        let status = resp.status().as_u16();
        if status == 404 && self.session_id.is_some() {
            return Ok(PostOutcome::SessionExpired);
        }
        if status == 202 {
            return Ok(PostOutcome::Done); // accepted notification/response
        }
        if !(200..300).contains(&status) {
            return Err(KprunError::Other(format!("upstream HTTP {status}")));
        }
        let mime = resp.body().mime_type().unwrap_or("").to_string();
        if mime.starts_with("text/event-stream") {
            let reader = resp.body_mut().as_reader();
            for event in SseParser::new(reader) {
                let event = event?;
                if !event.data.is_empty() {
                    write_frame(&event.data);
                }
            }
        } else {
            let text = resp.body_mut().read_to_string().map_err(http_err)?;
            let text = text.trim_end();
            if !text.is_empty() {
                write_frame(text);
            }
        }
        Ok(PostOutcome::Done)
    }

    fn reinitialize(&mut self) -> Result<()> {
        self.session_id = None;
        let frame = self.init_frame.clone();
        let mut resp = self.post_raw(&frame)?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(KprunError::Other(format!(
                "re-initialize failed: HTTP {status}"
            )));
        }
        self.capture_session(&resp);
        // Drain without forwarding: the client never re-sent initialize.
        let _ = resp.body_mut().read_to_vec();
        Ok(())
    }

    /// Optional server→client stream: GET the endpoint as text/event-stream.
    /// Servers that offer no stream answer 405 — the thread ends quietly.
    /// A dropped stream reconnects with Last-Event-ID until shutdown.
    pub fn spawn_server_stream(&self, cfg: &BridgeConfig, shutdown: Arc<AtomicBool>) {
        // Long-lived stream: connect timeout only, no global timeout.
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_connect(Some(Duration::from_secs(10)))
            .build()
            .into();
        let url = cfg.url.clone();
        let headers = self.headers.clone();
        let session_id = self.session_id.clone();
        std::thread::spawn(move || {
            let mut last_event_id: Option<String> = None;
            loop {
                if shutdown.load(Ordering::Relaxed) {
                    return;
                }
                let mut req = agent.get(&url).header("Accept", "text/event-stream");
                for (name, value) in &headers {
                    req = req.header(name.as_str(), value.as_str());
                }
                if let Some(sid) = &session_id {
                    req = req.header("Mcp-Session-Id", sid.as_str());
                }
                if let Some(id) = &last_event_id {
                    req = req.header("Last-Event-ID", id.as_str());
                }
                let Ok(mut resp) = req.call() else { return };
                if resp.status().as_u16() != 200 {
                    return; // no stream offered (405 typical)
                }
                let reader = resp.body_mut().as_reader();
                for event in SseParser::new(reader) {
                    let Ok(event) = event else { break };
                    if let Some(id) = &event.id {
                        last_event_id = Some(id.clone());
                    }
                    if !event.data.is_empty() {
                        write_frame(&event.data);
                    }
                }
                if shutdown.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        });
    }

    /// Best-effort session termination (spec: HTTP DELETE).
    pub fn shutdown(&self) {
        let Some(sid) = &self.session_id else { return };
        let mut req = self
            .post_agent
            .delete(&self.url)
            .header("Mcp-Session-Id", sid.as_str());
        for (name, value) in &self.headers {
            req = req.header(name.as_str(), value.as_str());
        }
        let _ = req.call();
    }
}

pub fn run_with(
    mut session: Session,
    cfg: &BridgeConfig,
    lines: impl Iterator<Item = std::io::Result<String>>,
) -> Result<i32> {
    let shutdown = Arc::new(AtomicBool::new(false));
    session.spawn_server_stream(cfg, shutdown.clone());
    for line in lines {
        let frame = line?;
        if frame.trim().is_empty() {
            continue;
        }
        session.handle_frame(&frame);
    }
    shutdown.store(true, Ordering::Relaxed);
    session.shutdown();
    Ok(0)
}
