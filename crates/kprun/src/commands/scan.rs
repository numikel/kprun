use serde::Serialize;

use crate::scan::{self, Finding, Origin, ScanOutcome};
use crate::ui;

#[derive(Serialize)]
struct JsonReport<'a> {
    version: u32,
    findings: Vec<JsonFinding<'a>>,
    stats: JsonStats,
}

#[derive(Serialize)]
struct JsonStats {
    files_scanned: usize,
    files_skipped: usize,
    history_commits: usize,
}

/// One flat finding object; absent fields are omitted, matching the
/// spec's schema exactly (`kind` discriminates, `origin` refines).
#[derive(Serialize)]
struct JsonFinding<'a> {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pattern: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    commit: Option<&'a str>,
    path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    masked: Option<&'a str>,
}

fn json_finding(f: &Finding) -> JsonFinding<'_> {
    match f {
        Finding::TrackedEnvFile { path } => JsonFinding {
            kind: "tracked_env_file",
            pattern: None,
            origin: None,
            commit: None,
            path,
            line: None,
            masked: None,
        },
        Finding::Secret {
            pattern_id,
            origin,
            masked,
        } => match origin {
            Origin::WorkingTree { path, line } => JsonFinding {
                kind: "secret",
                pattern: Some(pattern_id),
                origin: Some("working_tree"),
                commit: None,
                path,
                line: Some(*line),
                masked: Some(masked),
            },
            Origin::History { commit, path } => JsonFinding {
                kind: "secret",
                pattern: Some(pattern_id),
                origin: Some("history"),
                commit: Some(commit),
                path,
                line: None,
                masked: Some(masked),
            },
        },
    }
}

/// Exactly one compact JSON document on stdout; no summary, no banner —
/// warnings on stderr never corrupt stdout parsing.
fn render_json(outcome: &ScanOutcome) {
    let report = JsonReport {
        version: 1,
        findings: outcome.findings.iter().map(json_finding).collect(),
        stats: JsonStats {
            files_scanned: outcome.stats.files_scanned,
            files_skipped: outcome.stats.files_skipped,
            history_commits: outcome.stats.history_commits,
        },
    };
    // Plain structs of strings and integers cannot fail to serialize.
    println!(
        "{}",
        serde_json::to_string(&report).expect("report serializes")
    );
}

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
            if json {
                render_json(&outcome);
            } else {
                render_text(&outcome);
            }
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
            outcome.stats.files_scanned
        ));
    } else {
        eprintln!(
            "{} finding(s) — heuristic scan, run a dedicated scanner (gitleaks, trufflehog) for a full audit",
            outcome.findings.len()
        );
    }
}
