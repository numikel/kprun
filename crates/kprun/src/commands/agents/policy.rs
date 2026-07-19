//! Canonical agent policy block. The marker-based file engine that
//! installs it lives here too (added with `agents install`).

/// Fixed v1 template (design spec 2026-07-18, "Canonical policy block").
/// Exactly one copy in the codebase so tests can assert byte equality.
/// LF-only: rustc normalizes source CRLF to LF before lexing, and the
/// tests below pin the absence of `\r`.
pub(crate) const POLICY_BLOCK: &str = r#"<!-- kprun:agent-policy:start -->
## Secrets policy (kprun preferred)

Prefer kprun over `.env` files and plaintext tokens in configs. `.env` is fine
when the user asks for it or the project already uses it — but don't ask the
user to paste secret values into chat; point them to `kprun set` instead.

Running commands that need credentials:
1. `kprun list --json` — check the entry and key names exist.
2. `kprun run <entry> [entry2 ...] -- <command>` — the `--` separator is required.
3. Missing entry? Ask the user to run `kprun set <entry> --stdin`
   (inline `KEY=value` is OK for non-sensitive values).

MCP configs:
- Local stdio servers: `"command": "kprun", "args": ["run", "<entry>", "--", ...]`;
  ready-made fragment: `kprun doctor --mcp <entry> -- <command>`.
- Hosted/HTTP servers: `kprun mcp -e <entry> --bearer FIELD <url>` instead of
  plaintext tokens in headers.

Unsure about a flag or subcommand? Check `kprun --help` or
`kprun <command> --help` instead of guessing.

Hard limits:
- Do not read, log, or echo secret values (`--reveal`, `kprun reveal-master`).
- Do not run `kprun init` yourself — `--quick` prints the master password; ask the user.
- Do not run `delete`/`deinit` without explicit instruction.
- If unlock fails or needs an interactive prompt, stop and ask the user.
<!-- kprun:agent-policy:end -->
"#;

#[cfg(test)]
mod tests {
    use super::POLICY_BLOCK;

    #[test]
    fn block_is_lf_only_and_marker_delimited() {
        assert!(POLICY_BLOCK.starts_with("<!-- kprun:agent-policy:start -->\n"));
        assert!(POLICY_BLOCK.ends_with("<!-- kprun:agent-policy:end -->\n"));
        assert!(!POLICY_BLOCK.contains('\r'));
    }

    #[test]
    fn block_covers_core_policy_points() {
        for needle in [
            "kprun list --json",
            "kprun run <entry> [entry2 ...] -- <command>",
            "kprun set <entry> --stdin",
            "kprun doctor --mcp <entry> -- <command>",
            "kprun mcp -e <entry> --bearer FIELD <url>",
            "kprun reveal-master",
        ] {
            assert!(POLICY_BLOCK.contains(needle), "missing: {needle}");
        }
    }
}
