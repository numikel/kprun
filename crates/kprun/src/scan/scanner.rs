//! Text scanning over file content.

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
}
