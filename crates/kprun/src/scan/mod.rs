//! Heuristic committed-secrets scanner backing `kprun scan`.
//!
//! Narrow, high-confidence by design — not a substitute for dedicated
//! scanners (gitleaks, trufflehog). Never touches the vault.

pub mod git;

/// Fatal execution error (git missing, `--path` outside a repo) → exit 2.
pub type ScanError = String;

/// A single scan finding.
#[derive(Debug)]
pub enum Finding {
    /// A real (non-template) `.env` file tracked in git.
    TrackedEnvFile { path: String },
}

/// Result of a completed scan.
pub struct ScanOutcome {
    pub findings: Vec<Finding>,
}

/// Template basenames that are intentionally tracked; excluded from the
/// tracked-env-file rule. Their *content* is still pattern-scanned.
const ENV_TEMPLATES: [&str; 4] = [".env.example", ".env.sample", ".env.template", ".env.dist"];

/// Whether a `git ls-files` path (forward slashes) is a real tracked
/// `.env` file: basename `.env` or `.env.*`, excluding templates.
fn is_tracked_env_file(path: &str) -> bool {
    let basename = path.rsplit('/').next().unwrap_or(path);
    if ENV_TEMPLATES.contains(&basename) {
        return false;
    }
    basename == ".env" || basename.starts_with(".env.")
}

/// Phase 0 (environment validation) + phase 1a (tracked `.env` detection).
pub fn run_scan(path: &str) -> Result<ScanOutcome, ScanError> {
    if which::which("git").is_err() {
        return Err("git not found in PATH".to_string());
    }
    git::rev_parse_toplevel(path)?;
    let files = git::ls_files(path)?;

    let mut findings = Vec::new();
    for file in &files {
        if is_tracked_env_file(file) {
            findings.push(Finding::TrackedEnvFile { path: file.clone() });
        }
    }
    Ok(ScanOutcome { findings })
}

#[cfg(test)]
mod tests {
    use super::is_tracked_env_file;

    #[test]
    fn detects_env_and_env_dot_variants() {
        assert!(is_tracked_env_file(".env"));
        assert!(is_tracked_env_file("backend/.env"));
        assert!(is_tracked_env_file(".env.production"));
        assert!(is_tracked_env_file("a/b/.env.local"));
    }

    #[test]
    fn skips_templates_and_non_env_files() {
        assert!(!is_tracked_env_file(".env.example"));
        assert!(!is_tracked_env_file("api/.env.sample"));
        assert!(!is_tracked_env_file(".env.template"));
        assert!(!is_tracked_env_file(".env.dist"));
        assert!(!is_tracked_env_file(".environment"));
        assert!(!is_tracked_env_file("env"));
        assert!(!is_tracked_env_file("src/main.rs"));
    }
}
