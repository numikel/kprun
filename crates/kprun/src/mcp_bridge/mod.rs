//! stdio↔HTTP bridge for hosted MCP servers (`kprun mcp`).
//!
//! Invariants: stdout carries exclusively JSON-RPC frames; message bodies
//! pass through byte-for-byte; secrets never leave process memory.

pub mod legacy_sse;
pub mod sse;
pub mod streamable;

use std::io::{BufRead, Write};
use std::time::Duration;

use kprun_core::{KprunError, Result};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Auto,
    Streamable,
    LegacySse,
}

pub struct BridgeConfig {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub transport: Transport,
    pub timeout: Duration,
}

pub fn run_bridge(cfg: BridgeConfig) -> Result<i32> {
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    // `initialize` is always the first client message; EOF before it means
    // the client gave up — exit cleanly.
    let Some(first) = lines.next() else {
        return Ok(0);
    };
    let first = first?;
    match cfg.transport {
        Transport::Streamable | Transport::Auto => {
            let mut session = streamable::Session::new(&cfg, first.clone());
            match session.initialize()? {
                streamable::InitOutcome::Ready(resp) => {
                    session.finish_initialize(resp)?;
                    streamable::run_with(session, &cfg, lines)
                }
                streamable::InitOutcome::Unauthorized(status) => Err(KprunError::Other(format!(
                    "server returned HTTP {status}: authentication failed — check the token in your vault entry"
                ))),
                streamable::InitOutcome::FallbackToLegacy(status) => {
                    if cfg.transport == Transport::Auto {
                        // MCP backwards compatibility: non-auth 4xx on the
                        // initialize POST → deprecated HTTP+SSE transport.
                        eprintln!(
                            "kprun mcp: streamable HTTP rejected (HTTP {status}); falling back to HTTP+SSE"
                        );
                        legacy_sse::run(&cfg, first, lines)
                    } else {
                        Err(KprunError::Other(format!(
                            "server rejected streamable HTTP (status {status}); try --transport auto"
                        )))
                    }
                }
            }
        }
        Transport::LegacySse => legacy_sse::run(&cfg, first, lines),
    }
}

/// Write one JSON-RPC frame to stdout, line-atomically (two threads may
/// write concurrently once the server→client GET stream exists).
pub(crate) fn write_frame(frame: &str) {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = writeln!(lock, "{frame}");
    let _ = lock.flush();
}

/// Emit a JSON-RPC -32603 error for a failed request. The frame copy is
/// parsed only to recover `id`; notifications (no id) get no response.
pub(crate) fn emit_rpc_error(frame: &str, message: &str) {
    let id = serde_json::from_str::<serde_json::Value>(frame)
        .ok()
        .and_then(|v| v.get("id").cloned());
    let Some(id) = id else { return };
    if id.is_null() {
        return;
    }
    let error = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": -32603, "message": message }
    });
    write_frame(&error.to_string());
}

/// Redact a URL down to scheme + host: the resolved query string may carry
/// substituted vault secrets, so no error path may embed the full URL.
pub(crate) fn redact_url(url: &str) -> String {
    match url.find("://") {
        Some(i) => {
            let scheme = &url[..i];
            let rest = &url[i + 3..];
            let host = rest.split(['/', '?', '#']).next().unwrap_or("");
            format!("{scheme}://{host}/…")
        }
        None => "<invalid-url>".to_string(),
    }
}

pub(crate) fn http_err(e: ureq::Error) -> KprunError {
    match e {
        // BadUri's Display embeds the full URI, which may contain
        // substituted secrets in the query string — never echo it.
        ureq::Error::BadUri(_) => {
            KprunError::Other("invalid request URI (redacted; check the URL template)".into())
        }
        other => KprunError::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::redact_url;

    #[test]
    fn redact_url_keeps_scheme_and_host_only() {
        assert_eq!(
            redact_url("https://api.example.com/mcp/?key=SECRET_VALUE"),
            "https://api.example.com/…"
        );
        assert_eq!(
            redact_url("http://127.0.0.1:8080/x?token=SECRET"),
            "http://127.0.0.1:8080/…"
        );
    }

    #[test]
    fn redact_url_handles_missing_scheme() {
        assert_eq!(redact_url("no-scheme/path?x=SECRET"), "<invalid-url>");
    }
}
