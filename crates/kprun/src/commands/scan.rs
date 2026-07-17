use crate::scan::{self, Finding, Origin, ScanOutcome};
use crate::ui;

/// Own exit-code match instead of `run_command`: scan follows the
/// grep/gitleaks-style contract 0 = clean, 1 = findings, 2 = execution
/// error — a documented departure from the repo's binary 0/1 convention.
pub fn execute(path: Option<String>, history: bool, full_history: bool, json: bool) -> i32 {
    if !json {
        ui::maybe_banner();
    }
    let dir = path.unwrap_or_else(|| ".".to_string());
    match scan::run_scan(&dir, history, full_history) {
        Ok(outcome) => {
            render_text(&outcome);
            if outcome.findings.is_empty() {
                0
            } else {
                1
            }
        }
        Err(msg) => {
            eprintln!("error: {msg}");
            2
        }
    }
}

/// Finding lines on stdout (manual columns, `list.rs` pattern); summary
/// and the heuristic disclaimer on stderr.
fn render_text(outcome: &ScanOutcome) {
    for finding in &outcome.findings {
        match finding {
            Finding::TrackedEnvFile { path } => {
                println!("{:<20} {path}  (tracked in git)", "[env-file]");
            }
            Finding::Secret {
                pattern_id,
                origin,
                masked,
            } => match origin {
                Origin::WorkingTree { path, line } => {
                    println!("{:<20} {path}:{line}  {masked}", format!("[{pattern_id}]"));
                }
                Origin::History { commit, path } => {
                    println!(
                        "{:<20} commit {commit}  {path}  {masked}",
                        format!("[{pattern_id}]")
                    );
                }
            },
        }
    }
    if outcome.findings.is_empty() {
        ui::success(&format!(
            "no secrets found ({} files scanned)",
            outcome.files_scanned
        ));
    } else {
        eprintln!(
            "{} finding(s) — heuristic scan, run a dedicated scanner (gitleaks, trufflehog) for a full audit",
            outcome.findings.len()
        );
    }
}
