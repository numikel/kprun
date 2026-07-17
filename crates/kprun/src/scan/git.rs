//! Thin `git` process runner for the scanner. This is deliberately the only
//! `Command::new("git")` call site in the codebase.

use std::process::Command;

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
        Err(format!("git {} failed", args[0]))
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

/// Full `git log -p` output. `limit` caps the number of commits from
/// HEAD; `None` scans the entire history (`--full-history`).
pub fn log_patch(path: &str, limit: Option<usize>) -> Result<String, ScanError> {
    let mut args = vec![
        "log".to_string(),
        "-p".to_string(),
        "--no-color".to_string(),
        "--format=%H".to_string(),
    ];
    if let Some(n) = limit {
        args.push("-n".to_string());
        args.push(n.to_string());
    }
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = run_git(path, &arg_refs)?;
    Ok(String::from_utf8_lossy(&out).into_owned())
}
