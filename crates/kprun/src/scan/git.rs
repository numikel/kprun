//! Thin `git` process runner for the scanner. This is deliberately the only
//! `Command::new("git")` call site in non-test code.

use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};

use super::ScanError;

/// Run `git -C <path> <args>`. Ok(stdout bytes) on success; Err carries
/// git's own stderr (trimmed) so the user sees the real cause.
fn run_git(path: &str, args: &[&str]) -> Result<Vec<u8>, ScanError> {
    let out = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run git: {e}"))?;
    if out.status.success() {
        return Ok(out.stdout);
    }
    let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if msg.is_empty() {
        Err(format!(
            "git {} failed",
            args.first().copied().unwrap_or("git")
        ))
    } else {
        Err(msg)
    }
}

/// Toplevel directory of the repository containing `path`. Failure means
/// `path` is not inside a git repository (execution error, exit 2).
pub fn rev_parse_toplevel(path: &str) -> Result<String, ScanError> {
    let out = run_git(path, &["rev-parse", "--show-toplevel"])?;
    Ok(String::from_utf8_lossy(&out).trim().to_string())
}

/// Tracked files as toplevel-relative forward-slash paths.
/// `-z` (NUL separation) keeps unusual filenames intact; `--full-name`
/// keeps paths toplevel-relative even when `path` is a subdirectory.
pub fn ls_files(path: &str) -> Result<Vec<String>, ScanError> {
    let out = run_git(path, &["ls-files", "-z", "--full-name"])?;
    Ok(String::from_utf8_lossy(&out)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect())
}

/// Whether the repository has any commit (HEAD resolves). A repo without
/// commits makes `--history` a warn-and-skip, not an error.
pub fn head_exists(path: &str) -> bool {
    run_git(path, &["rev-parse", "--verify", "HEAD"]).is_ok()
}

/// Stream `git log -p` output into `sink`, one line at a time. `limit` caps
/// the number of commits from HEAD; `None` scans the reachable history
/// (`--full-history`). The patch is never buffered whole, so memory stays
/// bounded regardless of history size.
///
/// Scoped with the `-- .` pathspec under `git -C <path>`, so history honors
/// `--path` exactly like the working-tree scan (both run relative to
/// `<path>`). History still only covers commits reachable from `HEAD`.
pub fn stream_log_patch(
    path: &str,
    limit: Option<usize>,
    mut sink: impl FnMut(&str),
) -> Result<(), ScanError> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(path)
        .args(["log", "-p", "--no-color", "--format=%H"]);
    if let Some(n) = limit {
        cmd.arg("-n").arg(n.to_string());
    }
    // Scope to the same subtree the working-tree scan covers.
    cmd.arg("--").arg(".");
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| format!("failed to run git: {e}"))?;

    // Drain stdout to EOF first; git finishes writing before we touch its
    // (small) stderr, so the unread stderr pipe cannot fill and deadlock.
    let stdout = child.stdout.take().expect("stdout is piped");
    for line in BufReader::new(stdout).lines() {
        let line = line.map_err(|e| format!("reading git output: {e}"))?;
        sink(&line);
    }

    let status = child.wait().map_err(|e| format!("waiting on git: {e}"))?;
    if status.success() {
        return Ok(());
    }
    let mut stderr = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut stderr);
    }
    let msg = stderr.trim();
    if msg.is_empty() {
        Err("git log failed".to_string())
    } else {
        Err(msg.to_string())
    }
}
