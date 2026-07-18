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

/// Incremental parser for `git log -p --no-color --format=%H` output, fed
/// one line at a time. Only added lines (`+` but not `+++`) are scanned — a
/// secret counts in the commit that introduced it; removals are skipped
/// because the introducing commit already reports it.
///
/// Heuristic parser: a bare 40- or 64-hex line (SHA-1 or SHA-256) is a commit
/// boundary (`--format=%H`), `+++ b/<path>` selects the current file.
/// Content lines always carry a diff prefix char, so they cannot be mistaken
/// for either marker.
///
/// State is held across `push_line` calls so history can be streamed
/// without buffering the entire `git log` in memory.
pub struct LogPatchScanner {
    findings: Vec<Finding>,
    commits: usize,
    commit: Option<String>, // short 12-hex
    file: Option<String>,
}

impl LogPatchScanner {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            commits: 0,
            commit: None,
            file: None,
        }
    }

    /// Feed one output line (trailing newline already stripped).
    pub fn push_line(&mut self, line: &str) {
        if is_commit_hash(line) {
            self.commits += 1;
            self.commit = Some(line[..12].to_string());
            self.file = None;
        } else if let Some(rest) = line.strip_prefix("+++ ") {
            // `+++ /dev/null` (deletion) yields None and drops later hits.
            self.file = parse_diff_target(rest);
        } else if let Some(added) = line.strip_prefix('+') {
            if let (Some(commit), Some(path)) = (&self.commit, &self.file) {
                for hit in patterns::find_in_line(added) {
                    self.findings.push(Finding::Secret {
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

    /// Consume the parser, returning findings and the commit count.
    pub fn finish(self) -> (Vec<Finding>, usize) {
        (self.findings, self.commits)
    }
}

impl Default for LogPatchScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Scan a fully-buffered `git log -p` patch. Thin wrapper over
/// `LogPatchScanner` for the unit tests, which hold the whole string in
/// memory; production streams via `LogPatchScanner` directly.
#[cfg(test)]
fn scan_log_patch(patch: &str) -> (Vec<Finding>, usize) {
    let mut scanner = LogPatchScanner::new();
    for line in patch.lines() {
        scanner.push_line(line);
    }
    scanner.finish()
}

fn is_commit_hash(line: &str) -> bool {
    (line.len() == 40 || line.len() == 64) && line.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Decode a git diff-header target: `b/<path>`, `/dev/null`, or a C-quoted
/// `"b/<escaped>"` (core.quotePath). Returns the toplevel-relative path, or
/// None for /dev/null (deletion).
fn parse_diff_target(rest: &str) -> Option<String> {
    let target = if rest.len() >= 2 && rest.starts_with('"') && rest.ends_with('"') {
        unquote_git_path(&rest[1..rest.len() - 1])
    } else {
        rest.to_string()
    };
    if target == "/dev/null" {
        return None;
    }
    target.strip_prefix("b/").map(str::to_string)
}

/// Decode git's C-style path quoting: `\\ \" \t \n \r` and `\NNN` octal byte
/// escapes (accumulated as bytes, then lossy-UTF-8). Unknown escapes pass
/// through literally.
fn unquote_git_path(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'\\' => {
                    out.push(b'\\');
                    i += 2;
                }
                b'"' => {
                    out.push(b'"');
                    i += 2;
                }
                b't' => {
                    out.push(b'\t');
                    i += 2;
                }
                b'n' => {
                    out.push(b'\n');
                    i += 2;
                }
                b'r' => {
                    out.push(b'\r');
                    i += 2;
                }
                b'0'..=b'7' => {
                    match s
                        .get(i + 1..i + 4)
                        .and_then(|oct| u8::from_str_radix(oct, 8).ok())
                    {
                        Some(v) => {
                            out.push(v);
                            i += 4;
                        }
                        None => {
                            out.push(bytes[i]);
                            i += 1;
                        }
                    }
                }
                _ => {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
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

    #[test]
    fn log_parser_accepts_sha256_commit_hash() {
        let secret = aws('X');
        let hash = "abcdef012345".to_string() + &"0".repeat(52);
        assert_eq!(hash.len(), 64);
        let patch = format!(
            "{hash}\n\
             diff --git a/f.txt b/f.txt\n\
             +++ b/f.txt\n\
             +key={secret}\n"
        );
        let (findings, commits) = scan_log_patch(&patch);
        assert_eq!(commits, 1);
        assert_eq!(findings.len(), 1);
        match &findings[0] {
            Finding::Secret {
                origin: Origin::History { commit, path },
                ..
            } => {
                assert_eq!(commit, "abcdef012345");
                assert_eq!(path, "f.txt");
            }
            other => panic!("unexpected finding: {other:?}"),
        }
    }

    #[test]
    fn log_parser_survives_octal_escape_before_multibyte_char() {
        let secret = aws('R');
        let hash = "dddddddddddd".to_string() + &"0".repeat(28);
        // `\3€` — an octal-digit escape start immediately followed by a 3-byte char.
        // The end index of the would-be `\NNN` slice lands mid-character; the parser
        // must not panic, and must still attribute the secret on the next added line.
        let patch = format!("{hash}\n+++ \"b/\\3€.txt\"\n+k={secret}\n");
        let (findings, commits) = scan_log_patch(&patch);
        assert_eq!(commits, 1);
        assert_eq!(
            findings.len(),
            1,
            "secret on the added line must still be found"
        );
        // Masking still absolute: the raw secret must not appear in the reported path/mask.
        if let Finding::Secret {
            masked,
            origin: Origin::History { path, .. },
            ..
        } = &findings[0]
        {
            assert!(!masked.contains(&secret));
            assert!(!path.contains(&secret));
        } else {
            panic!("expected a history Secret finding");
        }
    }

    #[test]
    fn log_parser_decodes_c_quoted_path_with_tab() {
        let secret = aws('Y');
        let hash = "1234567890ab".to_string() + &"0".repeat(28);
        let patch = format!(
            "{hash}\n\
             diff --git a/na.txt b/na.txt\n\
             +++ \"b/na\\tme.txt\"\n\
             +key={secret}\n"
        );
        let (findings, _commits) = scan_log_patch(&patch);
        assert_eq!(findings.len(), 1);
        match &findings[0] {
            Finding::Secret {
                origin: Origin::History { path, .. },
                ..
            } => {
                assert_eq!(path, "na\tme.txt");
            }
            other => panic!("unexpected finding: {other:?}"),
        }
    }
}
