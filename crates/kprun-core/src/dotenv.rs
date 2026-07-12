//! Standard `.env` file parsing (`kprun migrate`) and the shared dotenv
//! value unquoting used by both `migrate` and `import`.
//!
//! Intentionally distinct from the CLI's import format, where `#` marks an
//! entry title: here `#` lines are plain comments.

use crate::{KprunError, Result};

/// Parse a dotenv value, unquoting and unescaping when wrapped in double quotes.
pub fn parse_dotenv_value(raw: &str) -> String {
    let bytes = raw.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
        unescape_dotenv_value(&raw[1..raw.len() - 1])
    } else {
        raw.to_string()
    }
}

/// Resolve `\n`, `\r`, and `\\` escapes; unknown escapes are kept literally.
pub fn unescape_dotenv_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A parsed standard `.env` file.
#[derive(Debug)]
pub struct ParsedDotenv {
    /// Deduplicated pairs in file order (last occurrence of a key wins).
    pub pairs: Vec<(String, String)>,
    /// Keys that appeared more than once (for a CLI warning).
    pub duplicate_keys: Vec<String>,
}

/// Parse standard `.env` content: blank lines and full-line `#` comments are
/// skipped, a leading `export ` prefix is stripped, lines split on the first
/// `=`. No inline comments, no interpolation, no single-quote handling.
pub fn parse_dotenv(input: &str) -> Result<ParsedDotenv> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut duplicate_keys: Vec<String> = Vec::new();
    for (idx, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line
            .strip_prefix("export ")
            .map(str::trim_start)
            .unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            // Never echo the line: it may contain a secret.
            return Err(KprunError::Other(format!(
                "dotenv line {}: expected KEY=value (missing '=')",
                idx + 1
            )));
        };
        let key = key.trim();
        if key.is_empty() {
            return Err(KprunError::EmptyKey);
        }
        let value = parse_dotenv_value(value.trim());
        match pairs.iter_mut().find(|(k, _)| k.as_str() == key) {
            Some(existing) => {
                existing.1 = value;
                if !duplicate_keys.iter().any(|k| k.as_str() == key) {
                    duplicate_keys.push(key.to_string());
                }
            }
            None => pairs.push((key.to_string(), value)),
        }
    }
    Ok(ParsedDotenv {
        pairs,
        duplicate_keys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_pairs_in_file_order() {
        let p = parse_dotenv("A=1\nB=2\n").unwrap();
        assert_eq!(
            p.pairs,
            vec![("A".into(), "1".into()), ("B".into(), "2".into())]
        );
        assert!(p.duplicate_keys.is_empty());
    }

    #[test]
    fn skips_blank_lines_and_comments() {
        let p = parse_dotenv("# header\n\nA=1\n   # indented comment\n\nB=2\n").unwrap();
        assert_eq!(p.pairs.len(), 2);
    }

    #[test]
    fn strips_export_prefix() {
        let p = parse_dotenv("export A=1\nexport   B=2\n").unwrap();
        assert_eq!(
            p.pairs,
            vec![("A".into(), "1".into()), ("B".into(), "2".into())]
        );
    }

    #[test]
    fn unquotes_double_quoted_values_with_escapes() {
        let p = parse_dotenv("A=\"line1\\nline2\"\nB=\"back\\\\slash\"\nC=\"keep\\qunknown\"\n")
            .unwrap();
        assert_eq!(p.pairs[0].1, "line1\nline2");
        assert_eq!(p.pairs[1].1, "back\\slash");
        assert_eq!(p.pairs[2].1, "keep\\qunknown");
    }

    #[test]
    fn empty_value_is_allowed() {
        let p = parse_dotenv("A=\n").unwrap();
        assert_eq!(p.pairs, vec![("A".into(), String::new())]);
    }

    #[test]
    fn missing_equals_reports_line_number_without_content() {
        let err = parse_dotenv("A=1\nSECRETWORD\n").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("line 2"), "got: {msg}");
        assert!(!msg.contains("SECRETWORD"), "got: {msg}");
    }

    #[test]
    fn empty_key_errors() {
        let err = parse_dotenv("=value\n").unwrap_err();
        assert!(matches!(err, KprunError::EmptyKey));
    }

    #[test]
    fn duplicate_key_last_value_wins_and_is_reported() {
        let p = parse_dotenv("A=1\nB=2\nA=3\nA=4\n").unwrap();
        assert_eq!(
            p.pairs,
            vec![("A".into(), "4".into()), ("B".into(), "2".into())]
        );
        assert_eq!(p.duplicate_keys, vec!["A".to_string()]);
    }

    #[test]
    fn handles_crlf_input() {
        let p = parse_dotenv("A=1\r\nB=\"x\"\r\n").unwrap();
        assert_eq!(
            p.pairs,
            vec![("A".into(), "1".into()), ("B".into(), "x".into())]
        );
    }

    #[test]
    fn trims_key_and_unquoted_value_whitespace() {
        let p = parse_dotenv(" A = 1 \n").unwrap();
        assert_eq!(p.pairs, vec![("A".into(), "1".into())]);
    }

    #[test]
    fn hash_inside_value_is_kept_verbatim() {
        // Passwords frequently contain '#': no inline-comment stripping.
        let p = parse_dotenv("PASS=abc#def\n").unwrap();
        assert_eq!(p.pairs[0].1, "abc#def");
    }

    #[test]
    fn single_quotes_are_literal_text() {
        let p = parse_dotenv("A='x'\n").unwrap();
        assert_eq!(p.pairs[0].1, "'x'");
    }
}
