//! Deprecated HTTP+SSE transport (MCP 2024-11-05): one long-lived GET
//! stream delivers all server→client messages (including responses); the
//! first `endpoint` event names the POST URL for client→server messages.

use std::sync::mpsc;
use std::time::Duration;

use kprun_core::{KprunError, Result};

use super::sse::SseParser;
use super::{emit_rpc_error, http_err, write_frame, BridgeConfig};

pub fn run(
    cfg: &BridgeConfig,
    first: String,
    lines: impl Iterator<Item = std::io::Result<String>>,
) -> Result<i32> {
    let post_agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_connect(Some(Duration::from_secs(10)))
        .timeout_global(Some(cfg.timeout))
        .build()
        .into();
    let stream_agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_connect(Some(Duration::from_secs(10)))
        .build()
        .into();

    // 1. Open the SSE stream.
    let mut req = stream_agent
        .get(&cfg.url)
        .header("Accept", "text/event-stream");
    for (name, value) in &cfg.headers {
        req = req.header(name.as_str(), value.as_str());
    }
    let resp = req.call().map_err(http_err)?;
    let status = resp.status().as_u16();
    if status != 200 {
        return Err(KprunError::Other(format!(
            "legacy SSE stream rejected: HTTP {status}"
        )));
    }
    let (_, body) = resp.into_parts();
    let mut parser = SseParser::new(body.into_reader());

    // 2. First event must be `endpoint` with the POST URL.
    let endpoint = loop {
        let event = parser
            .next()
            .ok_or_else(|| KprunError::Other("SSE stream closed before endpoint event".into()))??;
        match event.event.as_str() {
            "endpoint" => break resolve_endpoint(&cfg.url, event.data.trim())?,
            _ => continue, // keepalives before endpoint are tolerated
        }
    };

    // 3. Reader thread: every subsequent message event goes to stdout.
    let (done_tx, done_rx) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        for event in parser {
            let event = match event {
                Ok(event) => event,
                Err(e) => {
                    eprintln!("kprun mcp: legacy SSE stream read error: {e}");
                    break;
                }
            };
            if !event.data.is_empty() {
                write_frame(&event.data);
            }
        }
        let _ = done_tx.send(());
    });

    // 4. POST client frames to the endpoint.
    //
    // Deliberate leniency: a compliant 2024-11-05 server answers every
    // POST with 202 and an empty body — all responses arrive on the GET
    // stream — which makes the body forward below a no-op. Some
    // pre-standard servers instead answer on the POST itself, so a
    // non-empty body is forwarded. Known, accepted risk: a pathological
    // server that BOTH answers the POST and echoes the same response on
    // the stream would emit a duplicate JSON-RPC id on stdout. No dedup
    // is attempted — this transport is deprecated, and penalizing the
    // compliant majority for a server class never observed in practice
    // is not worth it.
    let post = |frame: &str| -> Result<()> {
        let mut req = post_agent
            .post(&endpoint)
            .header("Content-Type", "application/json");
        for (name, value) in &cfg.headers {
            req = req.header(name.as_str(), value.as_str());
        }
        let mut resp = req.send(frame).map_err(http_err)?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(KprunError::Other(format!("upstream HTTP {status}")));
        }
        // Pre-standard leniency: forward a non-empty POST body (see the
        // comment above the closure).
        let text = resp.body_mut().read_to_string().map_err(http_err)?;
        let text = text.trim_end();
        if !text.is_empty() {
            write_frame(text);
        }
        Ok(())
    };

    if let Err(e) = post(&first) {
        eprintln!("kprun mcp: request failed: {e}");
        emit_rpc_error(&first, "kprun mcp: upstream request failed");
    }
    for line in lines {
        let frame = line?;
        if frame.trim().is_empty() {
            continue;
        }
        if let Err(e) = post(&frame) {
            eprintln!("kprun mcp: request failed: {e}");
            emit_rpc_error(&frame, "kprun mcp: upstream request failed");
        }
    }

    // 5. stdin EOF: give in-flight responses on the stream a moment to land.
    let _ = done_rx.recv_timeout(Duration::from_secs(1));
    Ok(0)
}

/// Resolve the `endpoint` event data against the base URL: absolute URLs
/// pass through, `/rooted` paths keep scheme+authority, bare relatives
/// replace the base's last path segment.
pub fn resolve_endpoint(base: &str, endpoint: &str) -> Result<String> {
    if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        return Ok(endpoint.to_string());
    }
    let scheme_end = base.find("://").ok_or_else(|| {
        KprunError::Other(format!("invalid base URL '{}'", super::redact_url(base)))
    })? + 3;
    let authority_end = base[scheme_end..]
        .find('/')
        .map(|i| scheme_end + i)
        .unwrap_or(base.len());
    if let Some(rooted) = endpoint.strip_prefix('/') {
        return Ok(format!("{}/{rooted}", &base[..authority_end]));
    }
    let path_end = base.rfind('/').filter(|&i| i >= authority_end);
    let prefix = match path_end {
        Some(i) => &base[..i],
        None => &base[..authority_end],
    };
    Ok(format!("{prefix}/{endpoint}"))
}

#[cfg(test)]
mod tests {
    use super::resolve_endpoint;

    #[test]
    fn absolute_endpoint_passes_through() {
        assert_eq!(
            resolve_endpoint("https://a.test/sse", "https://b.test/msg").unwrap(),
            "https://b.test/msg"
        );
    }

    #[test]
    fn rooted_endpoint_keeps_authority() {
        assert_eq!(
            resolve_endpoint("https://a.test:8443/deep/sse", "/messages?sid=1").unwrap(),
            "https://a.test:8443/messages?sid=1"
        );
    }

    #[test]
    fn bare_relative_replaces_last_segment() {
        assert_eq!(
            resolve_endpoint("https://a.test/deep/sse", "messages").unwrap(),
            "https://a.test/deep/messages"
        );
    }

    #[test]
    fn base_without_path_gets_slash() {
        assert_eq!(
            resolve_endpoint("https://a.test", "/messages").unwrap(),
            "https://a.test/messages"
        );
    }
}
