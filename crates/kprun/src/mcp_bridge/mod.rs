//! stdio↔HTTP bridge for hosted MCP servers (`kprun mcp`).
//!
//! Invariants: stdout carries exclusively JSON-RPC frames; message bodies
//! pass through byte-for-byte; secrets never leave process memory.

pub mod legacy_sse;
pub mod sse;
pub mod streamable;

use std::io::{BufRead, Write};
use std::time::Duration;

use clap::ValueEnum;
use kprun_core::{KprunError, Result};

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Transport {
    /// Detect per MCP spec: try Streamable HTTP, fall back to HTTP+SSE
    #[value(name = "auto")]
    Auto,
    /// Streamable HTTP (2025-03-26+) only
    #[value(name = "streamable-http")]
    Streamable,
    /// Deprecated HTTP+SSE (2024-11-05) only
    #[value(name = "sse")]
    LegacySse,
}

pub struct BridgeConfig {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub transport: Transport,
    pub timeout: Duration,
}

/// One MCP remote transport: drives the whole bridge lifetime given the
/// first stdin frame (always `initialize`) and the remaining stdin lines.
pub trait McpTransportImpl {
    fn run(
        &self,
        cfg: &BridgeConfig,
        first: String,
        lines: &mut dyn Iterator<Item = std::io::Result<String>>,
    ) -> Result<i32>;
}

/// Streamable HTTP only: 404/405 on initialize is a hard error (no fallback).
struct StreamableHttp;

/// Deprecated HTTP+SSE only.
struct LegacySse;

/// Spec-mandated detection: probe Streamable HTTP, fall back to HTTP+SSE
/// on 404/405 — a decorator around the streamable probe.
struct Auto;

impl McpTransportImpl for StreamableHttp {
    fn run(
        &self,
        cfg: &BridgeConfig,
        first: String,
        lines: &mut dyn Iterator<Item = std::io::Result<String>>,
    ) -> Result<i32> {
        match streamable::probe_and_run(cfg, first, lines)? {
            streamable::ProbeOutcome::Ran(code) => Ok(code),
            streamable::ProbeOutcome::FallbackToLegacy(status) => Err(KprunError::Other(format!(
                "server rejected streamable HTTP (status {status}); try --transport auto"
            ))),
        }
    }
}

impl McpTransportImpl for LegacySse {
    fn run(
        &self,
        cfg: &BridgeConfig,
        first: String,
        lines: &mut dyn Iterator<Item = std::io::Result<String>>,
    ) -> Result<i32> {
        eprintln!(
            "kprun mcp: HTTP+SSE transport is deprecated (MCP 2024-11-05) \
             and validated against mock servers only"
        );
        legacy_sse::run(cfg, first, lines)
    }
}

impl McpTransportImpl for Auto {
    fn run(
        &self,
        cfg: &BridgeConfig,
        first: String,
        lines: &mut dyn Iterator<Item = std::io::Result<String>>,
    ) -> Result<i32> {
        match streamable::probe_and_run(cfg, first.clone(), lines)? {
            streamable::ProbeOutcome::Ran(code) => Ok(code),
            streamable::ProbeOutcome::FallbackToLegacy(status) => {
                // MCP backwards compatibility: 404/405 on the
                // initialize POST → deprecated HTTP+SSE transport.
                eprintln!(
                    "kprun mcp: streamable HTTP rejected (HTTP {status}); \
                     falling back to deprecated HTTP+SSE (validated against mock servers only)"
                );
                legacy_sse::run(cfg, first, lines)
            }
        }
    }
}

/// The single registration point: a new transport adds one enum variant
/// above (with its CLI name) and one arm here.
fn select_transport(transport: Transport) -> &'static dyn McpTransportImpl {
    match transport {
        Transport::Auto => &Auto,
        Transport::Streamable => &StreamableHttp,
        Transport::LegacySse => &LegacySse,
    }
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
    select_transport(cfg.transport).run(&cfg, first, &mut lines)
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
