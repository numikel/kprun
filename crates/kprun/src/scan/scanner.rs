//! Text scanning over file content and diff patches.

use super::patterns;
use super::{Finding, Origin};

/// NUL byte in the first 8 KiB marks the content as binary.
pub fn is_binary(bytes: &[u8]) -> bool {
    bytes[..bytes.len().min(8192)].contains(&0)
}

/// Scan text file content line by line; `path` is the toplevel-relative
/// path used in reported origins. Line numbers are 1-based.
pub fn scan_file_text(path: &str, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        for hit in patterns::find_in_line(line) {
            findings.push(Finding::Secret {
                pattern_id: hit.pattern_id,
                origin: Origin::WorkingTree {
                    path: path.to_string(),
                    line: idx + 1,
                },
                masked: hit.masked,
            });
        }
    }
    findings
}

/// Scan `git log -p --no-color --format=%H` output. Only added lines
/// (`+` but not `+++`) are scanned — a secret counts in the commit that
/// introduced it; removals are skipped because the introducing commit
/// already reports it. Returns findings and the number of commits seen.
///
/// Heuristic parser: a bare 40-hex line is a commit boundary (`--format=%H`),
/// `+++ b/<path>` selects the current file. Content lines always carry a
/// diff prefix char, so they cannot be mistaken for either marker.
pub fn scan_log_patch(patch: &str) -> (Vec<Finding>, usize) {
    let mut findings = Vec::new();
    let mut commits = 0;
    let mut commit: Option<String> = None; // short 12-hex
    let mut file: Option<String> = None;
    for line in patch.lines() {
        if is_commit_hash(line) {
            commits += 1;
            commit = Some(line[..12].to_string());
            file = None;
        } else if let Some(rest) = line.strip_prefix("+++ ") {
            // `+++ /dev/null` (deletion) yields None and drops later hits.
            file = rest.strip_prefix("b/").map(str::to_string);
        } else if let Some(added) = line.strip_prefix('+') {
            if let (Some(commit), Some(path)) = (&commit, &file) {
                for hit in patterns::find_in_line(added) {
                    findings.push(Finding::Secret {
                        pattern_id: hit.pattern_id,
                        origin: Origin::History {
                            commit: commit.clone(),
                            path: path.clone(),
                        },
                        masked: hit.masked,
                    });
                }
            }
        }
    }
    (findings, commits)
}

fn is_commit_hash(line: &str) -> bool {
    line.len() == 40 && line.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aws(fill: char) -> String {
        "AKIA".to_string() + &fill.to_string().repeat(16)
    }

    #[test]
    fn nul_in_first_8_kib_marks_binary() {
        assert!(is_binary(b"\x00binary"));
        assert!(is_binary(&[b'a', 0, b'b']));
        assert!(!is_binary(b"plain text"));
        assert!(!is_binary(b""));
    }

    #[test]
    fn nul_after_first_8_kib_is_still_text() {
        let mut bytes = vec![b'a'; 8192];
        bytes.push(0);
        assert!(!is_binary(&bytes));
    }

    #[test]
    fn line_numbers_are_one_based() {
        let text = format!("first\nsecond\nkey = {}\n", aws('D'));
        let findings = scan_file_text("src/config.rs", &text);
        assert_eq!(findings.len(), 1);
        match &findings[0] {
            Finding::Secret {
                origin: Origin::WorkingTree { path, line },
                ..
            } => {
                assert_eq!(path, "src/config.rs");
                assert_eq!(*line, 3);
            }
            other => panic!("unexpected finding: {other:?}"),
        }
    }

    #[test]
    fn multiple_hits_in_one_file_are_all_reported() {
        let anthropic = "sk-ant-".to_string() + &"e".repeat(24);
        let text = format!("a={}\nplain\nb={anthropic}\n", aws('E'));
        let findings = scan_file_text("f.txt", &text);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn log_parser_attributes_commit_and_file_and_skips_non_added_lines() {
        let secret = aws('F');
        let hash = "3fa8c21d90ab".to_string() + &"0".repeat(28);
        let patch = format!(
            "{hash}\n\
             diff --git a/scripts/deploy.sh b/scripts/deploy.sh\n\
             index 0000000..1111111 100644\n\
             --- a/scripts/deploy.sh\n\
             +++ b/scripts/deploy.sh\n\
             @@ -0,0 +1,2 @@\n\
             +export KEY={secret}\n\
             +echo done\n\
             -removed={secret}\n"
        );
        let (findings, commits) = scan_log_patch(&patch);
        assert_eq!(commits, 1);
        assert_eq!(findings.len(), 1, "removed line must not be scanned");
        match &findings[0] {
            Finding::Secret {
                pattern_id,
                origin: Origin::History { commit, path },
                masked,
            } => {
                assert_eq!(*pattern_id, "aws-access-key-id");
                assert_eq!(commit, "3fa8c21d90ab");
                assert_eq!(path, "scripts/deploy.sh");
                assert!(!masked.contains(&secret));
            }
            other => panic!("unexpected finding: {other:?}"),
        }
    }

    #[test]
    fn log_parser_tracks_multiple_commits_and_ignores_dev_null() {
        let secret_a = aws('G');
        let secret_b = "glpat-".to_string() + &"h".repeat(20);
        let hash_a = "aaaaaaaaaaaa".to_string() + &"0".repeat(28);
        let hash_b = "bbbbbbbbbbbb".to_string() + &"0".repeat(28);
        let patch = format!(
            "{hash_a}\n\
             diff --git a/a.txt b/a.txt\n\
             +++ b/a.txt\n\
             +k={secret_a}\n\
             {hash_b}\n\
             diff --git a/gone.txt b/gone.txt\n\
             +++ /dev/null\n\
             +orphan={secret_a}\n\
             diff --git a/b.txt b/b.txt\n\
             +++ b/b.txt\n\
             +k={secret_b}\n"
        );
        let (findings, commits) = scan_log_patch(&patch);
        assert_eq!(commits, 2);
        assert_eq!(
            findings.len(),
            2,
            "hit after '+++ /dev/null' must be dropped"
        );
        match (&findings[0], &findings[1]) {
            (
                Finding::Secret {
                    origin:
                        Origin::History {
                            commit: c0,
                            path: p0,
                        },
                    ..
                },
                Finding::Secret {
                    origin:
                        Origin::History {
                            commit: c1,
                            path: p1,
                        },
                    ..
                },
            ) => {
                assert_eq!((c0.as_str(), p0.as_str()), ("aaaaaaaaaaaa", "a.txt"));
                assert_eq!((c1.as_str(), p1.as_str()), ("bbbbbbbbbbbb", "b.txt"));
            }
            other => panic!("unexpected findings: {other:?}"),
        }
    }
}
