//! Canonical agent policy block. The marker-based file engine that
//! installs it lives here too (added with `agents install`).

use std::path::Path;

use kprun_core::{KprunError, Result};

pub(crate) const MARKER_START: &str = "<!-- kprun:agent-policy:start -->";
pub(crate) const MARKER_END: &str = "<!-- kprun:agent-policy:end -->";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteOutcome {
    Created,
    Updated,
    Unchanged,
}

/// Create the file with the block, replace an existing marker-delimited
/// block, or append the block after a blank line — everything outside the
/// markers stays byte-for-byte untouched. Missing parent directories are
/// created. Writes keep default permissions (these files must be
/// committable, not 0600) but go through a temp sibling + rename so a
/// mid-write crash can never truncate a hand-authored file.
pub(crate) fn install_block(path: &Path) -> Result<WriteOutcome> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).map_err(|e| io_err(path, &e))?;
                }
            }
            write_atomic(path, POLICY_BLOCK).map_err(|e| io_err(path, &e))?;
            return Ok(WriteOutcome::Created);
        }
        Err(e) => return Err(io_err(path, &e)),
    };
    match updated_content(path, &content)? {
        None => Ok(WriteOutcome::Unchanged),
        Some(new) => {
            write_atomic(path, &new).map_err(|e| io_err(path, &e))?;
            Ok(WriteOutcome::Updated)
        }
    }
}

/// Write `contents` to `path` via a temp sibling + `rename`, so the target
/// only ever holds the old or the new full content — `fs::rename` replaces
/// existing files atomically on Unix and Windows alike. The temp file is
/// removed on failure; pid suffix keeps concurrent installs from colliding.
fn write_atomic(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".kprun-tmp-{}", std::process::id()));
    let tmp = std::path::PathBuf::from(tmp);
    let result = (|| {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Whether `path` contains a well-formed policy block (start marker with a
/// matching end marker below it). Read-only — `kprun doctor` uses it for
/// its `agents:` status line.
pub(crate) fn has_policy_block(path: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    match marker_line_range(&content, MARKER_START, 0) {
        Some((_, start_end)) => marker_line_range(&content, MARKER_END, start_end).is_some(),
        None => false,
    }
}

/// `Some(new_content)` when the file needs rewriting, `None` when it is
/// already up to date. Errors on corrupted markers — never guess the
/// replacement range.
fn updated_content(path: &Path, content: &str) -> Result<Option<String>> {
    match marker_line_range(content, MARKER_START, 0) {
        Some((start_begin, start_end)) => {
            let (_, end_end) =
                marker_line_range(content, MARKER_END, start_end).ok_or_else(|| corrupted(path))?;
            let new = format!(
                "{}{POLICY_BLOCK}{}",
                &content[..start_begin],
                &content[end_end..]
            );
            Ok((new != content).then_some(new))
        }
        None => {
            if marker_line_range(content, MARKER_END, 0).is_some() {
                return Err(corrupted(path));
            }
            let mut new = String::with_capacity(content.len() + POLICY_BLOCK.len() + 2);
            new.push_str(content);
            if !new.is_empty() {
                if !new.ends_with('\n') {
                    new.push('\n');
                }
                new.push('\n');
            }
            new.push_str(POLICY_BLOCK);
            Ok(Some(new))
        }
    }
}

/// Byte range `(start, end)` of the first line at or after `from` whose
/// content equals `marker` after `trim_end` (tolerates CRLF and trailing
/// spaces). `end` includes the line's newline when present.
fn marker_line_range(content: &str, marker: &str, from: usize) -> Option<(usize, usize)> {
    let mut offset = from;
    for line in content[from..].split_inclusive('\n') {
        if line.trim_end() == marker {
            return Some((offset, offset + line.len()));
        }
        offset += line.len();
    }
    None
}

fn io_err(path: &Path, e: &std::io::Error) -> KprunError {
    KprunError::Other(format!("{}: {e}", path.display()))
}

fn corrupted(path: &Path) -> KprunError {
    KprunError::Other(format!(
        "{}: corrupted kprun policy markers (start without a matching end below it, \
         or end without start); restore the missing marker line or delete the block, \
         then re-run",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn creates_missing_file_with_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("deep").join("AGENTS.md");
        assert_eq!(install_block(&path).unwrap(), WriteOutcome::Created);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), POLICY_BLOCK);
    }

    #[test]
    fn second_install_is_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("AGENTS.md");
        install_block(&path).unwrap();
        assert_eq!(install_block(&path).unwrap(), WriteOutcome::Unchanged);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), POLICY_BLOCK);
    }

    #[test]
    fn leaves_no_temp_siblings_after_create_and_update() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("AGENTS.md");
        assert_eq!(install_block(&path).unwrap(), WriteOutcome::Created);
        std::fs::write(&path, "# Notes\n").unwrap();
        assert_eq!(install_block(&path).unwrap(), WriteOutcome::Updated);
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, ["AGENTS.md"], "temp sibling must not survive");
    }

    #[test]
    fn appends_after_blank_line_when_no_markers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("CLAUDE.md");
        std::fs::write(&path, "# Notes\n").unwrap();
        assert_eq!(install_block(&path).unwrap(), WriteOutcome::Updated);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("# Notes\n\n{POLICY_BLOCK}")
        );
    }

    #[test]
    fn append_adds_missing_trailing_newline_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("CLAUDE.md");
        std::fs::write(&path, "# Notes").unwrap();
        install_block(&path).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("# Notes\n\n{POLICY_BLOCK}")
        );
    }

    #[test]
    fn empty_existing_file_receives_block_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("AGENTS.md");
        std::fs::write(&path, "").unwrap();
        assert_eq!(install_block(&path).unwrap(), WriteOutcome::Updated);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), POLICY_BLOCK);
    }

    #[test]
    fn replaces_between_markers_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("AGENTS.md");
        let before = format!("intro\n{MARKER_START}\nstale line\n{MARKER_END}\noutro\n");
        std::fs::write(&path, &before).unwrap();
        assert_eq!(install_block(&path).unwrap(), WriteOutcome::Updated);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("intro\n{POLICY_BLOCK}outro\n")
        );
    }

    #[test]
    fn tolerates_crlf_marker_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("AGENTS.md");
        let before = format!("intro\r\n{MARKER_START}\r\nstale\r\n{MARKER_END}\r\n");
        std::fs::write(&path, &before).unwrap();
        assert_eq!(install_block(&path).unwrap(), WriteOutcome::Updated);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("intro\r\n{POLICY_BLOCK}")
        );
    }

    #[test]
    fn start_without_end_errors_and_leaves_file_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("AGENTS.md");
        let before = format!("{MARKER_START}\nrest of file\n");
        std::fs::write(&path, &before).unwrap();
        let err = install_block(&path).unwrap_err().to_string();
        assert!(err.contains("marker"), "err was: {err}");
        assert!(err.contains("AGENTS.md"), "err was: {err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    #[test]
    fn end_without_start_errors_and_leaves_file_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("AGENTS.md");
        let before = format!("intro\n{MARKER_END}\n");
        std::fs::write(&path, &before).unwrap();
        assert!(install_block(&path).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    #[test]
    fn end_before_start_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("AGENTS.md");
        std::fs::write(&path, format!("{MARKER_END}\n{MARKER_START}\n")).unwrap();
        assert!(install_block(&path).is_err());
    }

    #[test]
    fn io_error_mentions_full_path() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, "a file, not a directory\n").unwrap();
        let target = blocker.join("AGENTS.md");
        let err = install_block(&target).unwrap_err().to_string();
        assert!(err.contains("AGENTS.md"), "err was: {err}");
    }

    #[test]
    fn has_policy_block_reports_presence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("AGENTS.md");
        assert!(!has_policy_block(&path), "missing file");
        std::fs::write(&path, "no markers here\n").unwrap();
        assert!(!has_policy_block(&path), "no markers");
        std::fs::write(&path, format!("{MARKER_START}\norphan start\n")).unwrap();
        assert!(
            !has_policy_block(&path),
            "corrupted markers are not installed"
        );
        std::fs::write(&path, "").unwrap();
        install_block(&path).unwrap();
        assert!(has_policy_block(&path));
    }
}
