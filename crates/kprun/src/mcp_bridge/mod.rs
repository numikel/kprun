//! stdio↔HTTP bridge for hosted MCP servers (`kprun mcp`).
//!
//! Invariants: stdout carries exclusively JSON-RPC frames; message bodies
//! pass through byte-for-byte; secrets never leave process memory.

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
            let mut session = streamable::Session::new(&cfg, first);
            match session.initialize()? {
                streamable::InitOutcome::Ready(resp) => {
                    session.finish_initialize(resp)?;
                    streamable::run_with(session, lines)
                }
                streamable::InitOutcome::Unauthorized(status) => Err(KprunError::Other(format!(
                    "server returned HTTP {status}: authentication failed — check the token in your vault entry"
                ))),
                // Legacy fallback lands in a follow-up task.
                streamable::InitOutcome::FallbackToLegacy(status) => Err(KprunError::Other(
                    format!("server rejected streamable HTTP (status {status})"),
                )),
            }
        }
        Transport::LegacySse => Err(KprunError::Other(
            "--transport sse is not implemented yet".to_string(),
        )),
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

pub(crate) fn http_err(e: ureq::Error) -> KprunError {
    KprunError::Other(e.to_string())
}
