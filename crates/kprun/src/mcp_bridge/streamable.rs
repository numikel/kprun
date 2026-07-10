//! Streamable HTTP transport (MCP 2025-03-26+): one POST per client message;
//! each response is plain JSON or a per-response SSE stream.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
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

/// Attach the headers common to every request the bridge issues: the
/// custom (vault-substituted) headers, `Mcp-Session-Id`, and
/// `MCP-Protocol-Version`. Generic over the ureq body typestate so POST
/// (`WithBody`) and GET/DELETE (`WithoutBody`) share it; verb-specific
/// headers (`Accept`, `Content-Type`, `Last-Event-ID`) stay at call sites.
fn apply_common_headers<B>(
    mut req: ureq::RequestBuilder<B>,
    headers: &[(String, String)],
    session_id: &Option<String>,
    protocol_version: &Option<String>,
) -> ureq::RequestBuilder<B> {
    for (name, value) in headers {
        req = req.header(name.as_str(), value.as_str());
    }
    if let Some(sid) = session_id {
        req = req.header("Mcp-Session-Id", sid.as_str());
    }
    if let Some(version) = protocol_version {
        req = req.header("MCP-Protocol-Version", version.as_str());
    }
    req
}

/// Sends `frame` and waits for the response status + headers, bounded by
/// `timeout`. `req`'s agent carries no response/global ureq timeout — this
/// function is the *only* place `--timeout` is enforced for a POST.
///
/// ureq 3.x has no config knob that bounds "receive headers" without the
/// same deadline leaking into the body: its per-phase timeouts (`Timeouts`
/// in `ureq::config`) are checked via each phase's *immediate predecessor*
/// too, so a configured `timeout_recv_response` continues to serve as an
/// absolute deadline (recorded-header-time + its own duration) during the
/// following `RecvBody` phase, however large `timeout_recv_body` is set —
/// `min_by` always picks the earliest candidate. Confirmed by tracing
/// `ureq::timings::CallTimings::next_timeout` and reproducing with the
/// `post_sse_response_outlives_request_timeout` test (it stayed RED after
/// swapping `timeout_global` for `timeout_recv_response` alone). Running
/// `send` on a helper thread and bounding the wait with a channel is the
/// only way to keep the two truly independent: once the response comes
/// back here, the caller reads its body on this (unbounded) thread using
/// an agent that was never configured with any response-phase deadline.
///
/// If the timeout fires, the helper thread is abandoned — it may still
/// complete or fail on its own against an unresponsive server. Because the
/// response body must stay unbounded, no response-phase deadline can be
/// placed on that call's agent: any such deadline re-anchors at header
/// time (see the phase-timeout note above) and would re-bound the body,
/// defeating the whole point of this function. So the leaked thread can
/// only be reclaimed at process exit. `kprun mcp` is a long-lived stdio
/// bridge — one `send_bounded` call per client JSON-RPC frame over the
/// entire editor/client session — so repeated `--timeout` firings
/// accumulate leaked threads for the remainder of the process's life.
/// This is an accepted trade-off of the thread-bounding approach given
/// ureq's per-call timeout model, not a short-lived-process non-issue.
fn send_bounded(
    req: ureq::RequestBuilder<ureq::typestate::WithBody>,
    frame: String,
    timeout: Duration,
) -> Result<ureq::http::Response<ureq::Body>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(req.send(frame).map_err(http_err));
    });
    rx.recv_timeout(timeout).unwrap_or_else(|_| {
        Err(KprunError::Other(format!(
            "no response headers within {timeout:?}"
        )))
    })
}

pub struct Session {
    post_agent: ureq::Agent,
    /// Bounds connect + response headers only (enforced in `post_raw` via
    /// `send_bounded`); response bodies, including SSE streams from a
    /// long-running tool call, are unbounded.
    header_timeout: Duration,
    url: String,
    headers: Vec<(String, String)>,
    /// Shared with the background GET-stream thread so it always sees the
    /// current session id, including after a transparent re-init replaces
    /// it mid-flight.
    session_id: Arc<Mutex<Option<String>>>,
    /// Shared with the background GET-stream thread — like `session_id` —
    /// so the stream always sends the current negotiated version,
    /// including after a transparent re-init re-negotiates it.
    protocol_version: Arc<Mutex<Option<String>>>,
    /// Raw initialize frame, kept byte-for-byte for transparent re-init.
    init_frame: String,
    /// Raw notifications/initialized frame, kept byte-for-byte so a
    /// transparent re-init can replay the complete lifecycle. Deliberately
    /// never synthesized: a client that skipped it gets the same
    /// (incomplete) session shape it built for itself the first time.
    initialized_frame: Option<String>,
}

impl Session {
    pub fn new(cfg: &BridgeConfig, init_frame: String) -> Self {
        // No response/global timeout here on purpose: `send_bounded` (used
        // by `post_raw`) enforces `cfg.timeout` for connect + response
        // headers itself, on a helper thread. Once headers are back, body
        // reads on this agent — plain JSON or a per-request SSE stream from
        // a long-running tool call — are unbounded, as the CLI help
        // promises. Accepted trade-off: a stalled plain-JSON body also
        // blocks unbounded — the response type is unknowable before the
        // headers arrive.
        let post_agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_connect(Some(Duration::from_secs(10)))
            .build()
            .into();
        Session {
            post_agent,
            header_timeout: cfg.timeout,
            url: cfg.url.clone(),
            headers: cfg.headers.clone(),
            session_id: Arc::new(Mutex::new(None)),
            protocol_version: Arc::new(Mutex::new(None)),
            init_frame,
            initialized_frame: None,
        }
    }

    fn session_id(&self) -> Option<String> {
        self.session_id.lock().unwrap().clone()
    }

    fn protocol_version(&self) -> Option<String> {
        self.protocol_version.lock().unwrap().clone()
    }

    fn post_raw(&self, frame: &str) -> Result<ureq::http::Response<ureq::Body>> {
        let req = self
            .post_agent
            .post(&self.url)
            .header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json");
        let req = apply_common_headers(
            req,
            &self.headers,
            &self.session_id(),
            &self.protocol_version(),
        );
        send_bounded(req, frame.to_string(), self.header_timeout)
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
            *self.session_id.lock().unwrap() = Some(sid.to_string());
        }
    }

    /// Transport metadata only: the negotiated version feeds the
    /// MCP-Protocol-Version request header. The frame itself is forwarded
    /// verbatim regardless. First capture wins; `reinitialize` clears the
    /// slot before re-capturing.
    fn capture_protocol_version(&self, frame: &str) {
        let mut slot = self.protocol_version.lock().unwrap();
        if slot.is_some() {
            return;
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(frame) {
            if let Some(version) = value
                .pointer("/result/protocolVersion")
                .and_then(|v| v.as_str())
            {
                *slot = Some(version.to_string());
            }
        }
    }

    /// Record the client's `notifications/initialized` frame the first
    /// time it passes through (it is still forwarded normally). Parsing
    /// stops once captured.
    fn capture_initialized(&mut self, frame: &str) {
        if self.initialized_frame.is_some() {
            return;
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(frame) {
            if value.get("method").and_then(|m| m.as_str()) == Some("notifications/initialized") {
                self.initialized_frame = Some(frame.to_string());
            }
        }
    }

    /// POST one client frame and forward whatever comes back. Survives
    /// individual request failures (JSON-RPC -32603 + stderr detail).
    pub fn handle_frame(&mut self, frame: &str) {
        self.capture_initialized(frame);
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
        if status == 404 && self.session_id().is_some() {
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
            // Track whether anything was already forwarded: if the stream
            // breaks (e.g. mid-response error) after a result already
            // reached the client, the caller must not also emit a
            // JSON-RPC error for the same request id.
            let mut forwarded_any = false;
            for event in SseParser::new(reader) {
                match event {
                    Ok(event) => {
                        if !event.data.is_empty() {
                            write_frame(&event.data);
                            forwarded_any = true;
                        }
                    }
                    Err(e) => {
                        if forwarded_any {
                            eprintln!("kprun mcp: SSE stream error after partial response: {e}");
                            return Ok(PostOutcome::Done);
                        }
                        return Err(e.into());
                    }
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
        *self.session_id.lock().unwrap() = None;
        // The new session may negotiate a different protocol version;
        // reset the slot so capture_protocol_version re-captures below.
        *self.protocol_version.lock().unwrap() = None;
        let frame = self.init_frame.clone();
        let mut resp = self.post_raw(&frame)?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(KprunError::Other(format!(
                "re-initialize failed: HTTP {status}"
            )));
        }
        self.capture_session(&resp);
        // Drain without forwarding (the client never re-sent initialize),
        // but parse the drained bytes to re-capture the negotiated
        // version. The response may be plain JSON or a short SSE stream.
        let mime = resp.body().mime_type().unwrap_or("").to_string();
        if let Ok(bytes) = resp.body_mut().read_to_vec() {
            if mime.starts_with("text/event-stream") {
                for event in SseParser::new(bytes.as_slice()).flatten() {
                    if !event.data.is_empty() {
                        self.capture_protocol_version(&event.data);
                    }
                }
            } else if let Ok(text) = std::str::from_utf8(&bytes) {
                self.capture_protocol_version(text.trim_end());
            }
        }
        // MCP lifecycle: the server expects notifications/initialized
        // before normal requests on the fresh session. Best effort — a
        // failure surfaces on the retried request itself.
        if let Some(frame) = self.initialized_frame.clone() {
            match self.post_raw(&frame) {
                Ok(resp) if (200..300).contains(&resp.status().as_u16()) => {}
                Ok(resp) => eprintln!(
                    "kprun mcp: replaying notifications/initialized failed: HTTP {}",
                    resp.status().as_u16()
                ),
                Err(e) => {
                    eprintln!("kprun mcp: replaying notifications/initialized failed: {e}")
                }
            }
        }
        Ok(())
    }

    /// Optional server→client stream: GET the endpoint as text/event-stream.
    /// Servers that offer no stream answer 405 before any stream has ever
    /// been established — the thread ends quietly rather than polling an
    /// endpoint that will never support it. A 404 (unknown/stale session,
    /// e.g. a race with `reinitialize`) or any failure once a stream has
    /// already been established is instead treated as transient: the loop
    /// re-reads the *current* session id (shared with `reinitialize` via
    /// `session_id`) and retries, so the stream comes back once re-init
    /// completes. A dropped stream reconnects with Last-Event-ID until
    /// shutdown.
    pub fn spawn_server_stream(
        &self,
        cfg: &BridgeConfig,
        shutdown: Arc<AtomicBool>,
        done_tx: mpsc::Sender<()>,
    ) {
        // Long-lived stream: connect timeout only, no global timeout.
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_connect(Some(Duration::from_secs(10)))
            .build()
            .into();
        let url = cfg.url.clone();
        let headers = self.headers.clone();
        let session_id = self.session_id.clone();
        let protocol_version = self.protocol_version.clone();
        std::thread::spawn(move || {
            // Dropped on every exit path, which disconnects the channel
            // and unblocks run_with's bounded shutdown wait.
            let _done_tx = done_tx;
            let mut last_event_id: Option<String> = None;
            let mut ever_streamed = false;
            loop {
                if shutdown.load(Ordering::Relaxed) {
                    return;
                }
                let current_sid = session_id.lock().unwrap().clone();
                let current_version = protocol_version.lock().unwrap().clone();
                let mut req = agent.get(&url).header("Accept", "text/event-stream");
                req = apply_common_headers(req, &headers, &current_sid, &current_version);
                if let Some(id) = &last_event_id {
                    req = req.header("Last-Event-ID", id.as_str());
                }
                let mut resp = match req.call() {
                    Ok(resp) => resp,
                    Err(e) => {
                        eprintln!("kprun mcp: server stream connection failed: {e}");
                        if !ever_streamed {
                            return;
                        }
                        std::thread::sleep(Duration::from_secs(1));
                        continue;
                    }
                };
                let status = resp.status().as_u16();
                if status != 200 {
                    // 404 signals an unknown/stale session (spec semantics
                    // shared with the POST path) and is always worth a
                    // retry with a fresh session id. Any other non-200
                    // status is only retryable once a stream has already
                    // succeeded once; before that, it means the server
                    // simply offers no GET stream (405 typical).
                    if status != 404 && !ever_streamed {
                        return;
                    }
                    eprintln!("kprun mcp: server stream request rejected: HTTP {status}");
                    // A 404 is likely a short-lived race with an in-flight
                    // `reinitialize` on the POST path; retry quickly rather
                    // than waiting out the full idle-reconnect backoff.
                    let backoff = if status == 404 {
                        Duration::from_millis(100)
                    } else {
                        Duration::from_secs(1)
                    };
                    std::thread::sleep(backoff);
                    continue;
                }
                ever_streamed = true;
                let reader = resp.body_mut().as_reader();
                for event in SseParser::new(reader) {
                    let event = match event {
                        Ok(event) => event,
                        Err(e) => {
                            eprintln!("kprun mcp: server stream read error: {e}");
                            break;
                        }
                    };
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

    /// Best-effort session termination (spec: HTTP DELETE). The DELETE
    /// response body is never read, so unlike the POST path there is no
    /// body-cutting hazard in bounding the whole call: it gets its own
    /// agent with `timeout_global` set to `header_timeout`, rather than
    /// reusing `post_agent` (which deliberately carries no response/global
    /// timeout so POST bodies stay unbounded). Without this, a server that
    /// accepts the TCP connection but never answers the DELETE would hang
    /// `req.call()` forever, blocking process exit indefinitely.
    pub fn shutdown(&self) {
        let sid = self.session_id();
        if sid.is_none() {
            return;
        }
        let delete_agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_connect(Some(Duration::from_secs(10)))
            .timeout_global(Some(self.header_timeout))
            .build()
            .into();
        let req = delete_agent.delete(&self.url);
        let req = apply_common_headers(req, &self.headers, &sid, &self.protocol_version());
        let _ = req.call();
    }
}

pub fn run_with(
    mut session: Session,
    cfg: &BridgeConfig,
    lines: impl Iterator<Item = std::io::Result<String>>,
) -> Result<i32> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let (done_tx, done_rx) = mpsc::channel::<()>();
    session.spawn_server_stream(cfg, shutdown.clone(), done_tx);
    for line in lines {
        let frame = line?;
        if frame.trim().is_empty() {
            continue;
        }
        session.handle_frame(&frame);
    }
    shutdown.store(true, Ordering::Relaxed);
    // The DELETE typically makes the server close the GET stream,
    // unblocking the thread's read; then wait (bounded — std has no
    // join-with-timeout) so a frame mid-write to stdout is never
    // truncated by process exit.
    session.shutdown();
    let _ = done_rx.recv_timeout(Duration::from_secs(1));
    Ok(0)
}
