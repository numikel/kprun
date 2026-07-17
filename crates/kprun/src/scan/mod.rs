//! Heuristic committed-secrets scanner backing `kprun scan`.
//!
//! Narrow, high-confidence by design — not a substitute for dedicated
//! scanners (gitleaks, trufflehog). Never touches the vault.

pub mod git;
pub mod patterns;
pub mod scanner;

/// Fatal execution error (git missing, `--path` outside a repo) → exit 2.
pub type ScanError = String;

/// A single scan finding. Secrets carry only the masked value.
#[derive(Debug)]
pub enum Finding {
    /// A real (non-template) `.env` file tracked in git.
    TrackedEnvFile { path: String },
    /// A pattern hit; `masked` never contains the full secret.
    Secret {
        pattern_id: &'static str,
        origin: Origin,
        masked: String,
    },
}

/// Where a secret was found.
#[derive(Debug)]
pub enum Origin {
    WorkingTree {
        path: String,
        line: usize,
    },
    /// Commit is the short 12-hex hash; no line number — a diff line
    /// number does not correspond to a file line. `git show` suffices.
    History {
        commit: String,
        path: String,
    },
}

/// Files larger than this are skipped with a stderr warning.
const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024;

/// Default commit cap for `--history`; `--full-history` removes it.
const HISTORY_COMMIT_LIMIT: usize = 500;

/// Counters surfaced in the JSON report.
/// `files_scanned` = tracked files whose content was pattern-scanned;
/// `files_skipped` = tracked files excluded for any reason (binary,
/// over 5 MiB, unreadable); `history_commits` = commits parsed in phase 2
/// (0 when `--history` was not passed).
#[derive(Default)]
pub struct ScanStats {
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub history_commits: usize,
}

/// Result of a completed scan.
pub struct ScanOutcome {
    pub findings: Vec<Finding>,
    pub stats: ScanStats,
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

/// Phase 0 (environment validation) + phase 1 (working tree: tracked
/// `.env` detection and pattern scanning of every tracked file).
pub fn run_scan(path: &str, history: bool, full_history: bool) -> Result<ScanOutcome, ScanError> {
    if which::which("git").is_err() {
        return Err("git not found in PATH".to_string());
    }
    let toplevel = git::rev_parse_toplevel(path)?;
    let files = git::ls_files(path)?;

    let mut findings = Vec::new();
    let mut stats = ScanStats::default();
    for file in &files {
        if is_tracked_env_file(file) {
            findings.push(Finding::TrackedEnvFile { path: file.clone() });
        }
        // Templates skipped above still get their content scanned — a real
        // key pasted into `.env.example` must be caught here.
        let abs = std::path::Path::new(&toplevel).join(file);
        match std::fs::metadata(&abs) {
            Ok(meta) if meta.len() > MAX_FILE_SIZE => {
                eprintln!("warning: skipping {file}: larger than 5 MiB");
                stats.files_skipped += 1;
                continue;
            }
            Err(e) => {
                eprintln!("warning: skipping {file}: {e}");
                stats.files_skipped += 1;
                continue;
            }
            Ok(_) => {}
        }
        let bytes = match std::fs::read(&abs) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("warning: skipping {file}: {e}");
                stats.files_skipped += 1;
                continue;
            }
        };
        if scanner::is_binary(&bytes) {
            stats.files_skipped += 1;
            continue; // binaries are expected in repos; skip silently
        }
        // Patterns are pure ASCII, so lossy conversion cannot corrupt a match.
        let text = String::from_utf8_lossy(&bytes);
        findings.extend(scanner::scan_file_text(file, &text));
        stats.files_scanned += 1;
    }

    if history {
        if git::head_exists(path) {
            let limit = if full_history {
                None
            } else {
                Some(HISTORY_COMMIT_LIMIT)
            };
            let patch = git::log_patch(path, limit)?;
            let (history_findings, commits) = scanner::scan_log_patch(&patch);
            findings.extend(history_findings);
            stats.history_commits = commits;
        } else {
            eprintln!("warning: repository has no commits; skipping history scan");
        }
    }

    Ok(ScanOutcome { findings, stats })
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
