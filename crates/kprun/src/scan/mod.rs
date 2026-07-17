//! Heuristic committed-secrets scanner backing `kprun scan`.
//!
//! Narrow, high-confidence by design — not a substitute for dedicated
//! scanners (gitleaks, trufflehog). Never touches the vault.

pub mod git;

/// Fatal execution error (git missing, `--path` outside a repo) → exit 2.
pub type ScanError = String;

/// Phase 0: validate the environment — git on PATH, `path` inside a repo.
pub fn run_scan(path: &str) -> Result<(), ScanError> {
    if which::which("git").is_err() {
        return Err("git not found in PATH".to_string());
    }
    let _toplevel = git::rev_parse_toplevel(path)?;
    Ok(())
}
