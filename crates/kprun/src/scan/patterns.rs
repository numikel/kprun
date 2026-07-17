//! Declarative secret-pattern table. Pure string matching; returns ONLY
//! masked values — the full secret value never leaves `find_in_line`.

/// One prefix-anchored detection rule. Provider prefix variants
/// (`ghp_`/`gho_`/…) are separate rows sharing an `id` — the struct stays
/// flat, no list fields.
struct SecretPattern {
    id: &'static str,
    prefix: &'static str,
    /// Allowed bytes after the prefix.
    charset: fn(u8) -> bool,
    /// Minimum matched bytes after the prefix.
    min_len: usize,
    /// Maximum matched bytes after the prefix; `None` = greedy until the
    /// charset ends.
    max_len: Option<usize>,
}

/// A match with the secret already masked. The full value is dropped here.
pub struct PatternMatch {
    pub pattern_id: &'static str,
    pub masked: String,
}

fn upper_digit(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit()
}
fn alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}
fn alnum_underscore(b: u8) -> bool {
    alnum(b) || b == b'_'
}
fn alnum_dash(b: u8) -> bool {
    alnum(b) || b == b'-'
}
fn alnum_dash_underscore(b: u8) -> bool {
    alnum(b) || b == b'-' || b == b'_'
}
fn nothing(_b: u8) -> bool {
    false
}

/// Curated, compile-time rule table (deliberately not a config file: keeps
/// the tool zero-dep, CI-deterministic, and tamper-evident). Bare `sk-` is
/// knowingly excluded — too ambiguous (legacy OpenAI keys stay undetected).
/// Private-key headers are literal rows: empty charset, length 0; the
/// header itself is the mask.
const PATTERNS: &[SecretPattern] = &[
    SecretPattern {
        id: "aws-access-key-id",
        prefix: "AKIA",
        charset: upper_digit,
        min_len: 16,
        max_len: Some(16),
    },
    SecretPattern {
        id: "github-token",
        prefix: "ghp_",
        charset: alnum,
        min_len: 36,
        max_len: Some(36),
    },
    SecretPattern {
        id: "github-token",
        prefix: "gho_",
        charset: alnum,
        min_len: 36,
        max_len: Some(36),
    },
    SecretPattern {
        id: "github-token",
        prefix: "ghu_",
        charset: alnum,
        min_len: 36,
        max_len: Some(36),
    },
    SecretPattern {
        id: "github-token",
        prefix: "ghs_",
        charset: alnum,
        min_len: 36,
        max_len: Some(36),
    },
    SecretPattern {
        id: "github-token",
        prefix: "ghr_",
        charset: alnum,
        min_len: 36,
        max_len: Some(36),
    },
    SecretPattern {
        id: "github-fine-grained-pat",
        prefix: "github_pat_",
        charset: alnum_underscore,
        min_len: 82,
        max_len: Some(82),
    },
    SecretPattern {
        id: "openai-project-key",
        prefix: "sk-proj-",
        charset: alnum_dash_underscore,
        min_len: 20,
        max_len: None,
    },
    SecretPattern {
        id: "anthropic-key",
        prefix: "sk-ant-",
        charset: alnum_dash_underscore,
        min_len: 20,
        max_len: None,
    },
    SecretPattern {
        id: "stripe-secret-key",
        prefix: "sk_live_",
        charset: alnum,
        min_len: 24,
        max_len: None,
    },
    SecretPattern {
        id: "stripe-secret-key",
        prefix: "sk_test_",
        charset: alnum,
        min_len: 24,
        max_len: None,
    },
    SecretPattern {
        id: "google-api-key",
        prefix: "AIza",
        charset: alnum_dash_underscore,
        min_len: 35,
        max_len: Some(35),
    },
    SecretPattern {
        id: "slack-token",
        prefix: "xoxb-",
        charset: alnum_dash,
        min_len: 10,
        max_len: None,
    },
    SecretPattern {
        id: "slack-token",
        prefix: "xoxp-",
        charset: alnum_dash,
        min_len: 10,
        max_len: None,
    },
    SecretPattern {
        id: "slack-token",
        prefix: "xoxa-",
        charset: alnum_dash,
        min_len: 10,
        max_len: None,
    },
    SecretPattern {
        id: "slack-token",
        prefix: "xoxr-",
        charset: alnum_dash,
        min_len: 10,
        max_len: None,
    },
    SecretPattern {
        id: "slack-token",
        prefix: "xoxs-",
        charset: alnum_dash,
        min_len: 10,
        max_len: None,
    },
    SecretPattern {
        id: "gitlab-pat",
        prefix: "glpat-",
        charset: alnum_dash_underscore,
        min_len: 20,
        max_len: Some(20),
    },
    SecretPattern {
        id: "private-key-block",
        prefix: "-----BEGIN PRIVATE KEY-----",
        charset: nothing,
        min_len: 0,
        max_len: Some(0),
    },
    SecretPattern {
        id: "private-key-block",
        prefix: "-----BEGIN RSA PRIVATE KEY-----",
        charset: nothing,
        min_len: 0,
        max_len: Some(0),
    },
    SecretPattern {
        id: "private-key-block",
        prefix: "-----BEGIN EC PRIVATE KEY-----",
        charset: nothing,
        min_len: 0,
        max_len: Some(0),
    },
    SecretPattern {
        id: "private-key-block",
        prefix: "-----BEGIN DSA PRIVATE KEY-----",
        charset: nothing,
        min_len: 0,
        max_len: Some(0),
    },
    SecretPattern {
        id: "private-key-block",
        prefix: "-----BEGIN OPENSSH PRIVATE KEY-----",
        charset: nothing,
        min_len: 0,
        max_len: Some(0),
    },
    SecretPattern {
        id: "private-key-block",
        prefix: "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        charset: nothing,
        min_len: 0,
        max_len: Some(0),
    },
    SecretPattern {
        id: "private-key-block",
        prefix: "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        charset: nothing,
        min_len: 0,
        max_len: Some(0),
    },
];

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// All pattern matches in `line`. At each byte offset the first matching
/// table row wins and scanning resumes after that match.
pub fn find_in_line(line: &str) -> Vec<PatternMatch> {
    let bytes = line.as_bytes();
    let mut matches = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let mut advanced = false;
        for pat in PATTERNS {
            if let Some(len) = match_at(pat, bytes, i) {
                matches.push(PatternMatch {
                    pattern_id: pat.id,
                    masked: mask(pat, bytes, i, len),
                });
                i += pat.prefix.len() + len;
                advanced = true;
                break;
            }
        }
        if !advanced {
            i += 1;
        }
    }
    matches
}

/// Try `pat` at byte offset `i`. Returns the number of matched bytes after
/// the prefix, or None. Boundary rules: the byte before the prefix must not
/// be an identifier byte; charset consumption is greedy, so a fixed-length
/// row fails when extra charset bytes follow (`n > max_len`).
fn match_at(pat: &SecretPattern, bytes: &[u8], i: usize) -> Option<usize> {
    if !bytes[i..].starts_with(pat.prefix.as_bytes()) {
        return None;
    }
    if i > 0 && is_ident(bytes[i - 1]) {
        return None;
    }
    let after = &bytes[i + pat.prefix.len()..];
    let mut n = 0;
    while n < after.len() && (pat.charset)(after[n]) {
        n += 1;
    }
    if n < pat.min_len {
        return None;
    }
    if pat.max_len.is_some_and(|max| n > max) {
        return None;
    }
    Some(n)
}

/// `<prefix><first 4 chars>…(<total length> chars)`. For literal rows
/// (matched length 0) the prefix itself is the mask — a private-key
/// header is not a secret.
fn mask(pat: &SecretPattern, bytes: &[u8], i: usize, len: usize) -> String {
    if len == 0 {
        return pat.prefix.to_string();
    }
    let start = i + pat.prefix.len();
    let head = String::from_utf8_lossy(&bytes[start..start + len.min(4)]);
    format!("{}{}…({} chars)", pat.prefix, head, pat.prefix.len() + len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pattern_row_matches_a_synthetic_example() {
        // (value, expected id) — one entry per table row. Values are built
        // by concatenation so this file never trips a secret scanner.
        let examples: Vec<(String, &str)> = vec![
            ("AKIA".to_string() + &"A".repeat(16), "aws-access-key-id"),
            ("ghp_".to_string() + &"a".repeat(36), "github-token"),
            ("gho_".to_string() + &"a".repeat(36), "github-token"),
            ("ghu_".to_string() + &"a".repeat(36), "github-token"),
            ("ghs_".to_string() + &"a".repeat(36), "github-token"),
            ("ghr_".to_string() + &"a".repeat(36), "github-token"),
            (
                "github_pat_".to_string() + &"a".repeat(82),
                "github-fine-grained-pat",
            ),
            (
                "sk-proj-".to_string() + &"a".repeat(20),
                "openai-project-key",
            ),
            ("sk-ant-".to_string() + &"a".repeat(24), "anthropic-key"),
            (
                "sk_live_".to_string() + &"a".repeat(24),
                "stripe-secret-key",
            ),
            (
                "sk_test_".to_string() + &"a".repeat(24),
                "stripe-secret-key",
            ),
            ("AIza".to_string() + &"a".repeat(35), "google-api-key"),
            ("xoxb-".to_string() + &"1".repeat(12), "slack-token"),
            ("xoxp-".to_string() + &"1".repeat(12), "slack-token"),
            ("xoxa-".to_string() + &"1".repeat(12), "slack-token"),
            ("xoxr-".to_string() + &"1".repeat(12), "slack-token"),
            ("xoxs-".to_string() + &"1".repeat(12), "slack-token"),
            ("glpat-".to_string() + &"a".repeat(20), "gitlab-pat"),
            (
                "-----BEGIN ".to_string() + "PRIVATE KEY-----",
                "private-key-block",
            ),
            (
                "-----BEGIN ".to_string() + "RSA PRIVATE KEY-----",
                "private-key-block",
            ),
            (
                "-----BEGIN ".to_string() + "EC PRIVATE KEY-----",
                "private-key-block",
            ),
            (
                "-----BEGIN ".to_string() + "DSA PRIVATE KEY-----",
                "private-key-block",
            ),
            (
                "-----BEGIN ".to_string() + "OPENSSH PRIVATE KEY-----",
                "private-key-block",
            ),
            (
                "-----BEGIN ".to_string() + "ENCRYPTED PRIVATE KEY-----",
                "private-key-block",
            ),
            (
                "-----BEGIN ".to_string() + "PGP PRIVATE KEY BLOCK-----",
                "private-key-block",
            ),
        ];
        for (value, id) in examples {
            let line = format!("token = \"{value}\"");
            let hits = find_in_line(&line);
            assert_eq!(
                hits.len(),
                1,
                "expected exactly one hit for {id} in {line:?}"
            );
            assert_eq!(hits[0].pattern_id, id, "wrong id for {line:?}");
        }
    }

    #[test]
    fn prefix_preceded_by_identifier_char_does_not_match() {
        let value = "AKIA".to_string() + &"A".repeat(16);
        assert!(find_in_line(&format!("ID{value}")).is_empty());
        assert!(find_in_line(&format!("_{value}")).is_empty());
        assert!(find_in_line(&format!("9{value}")).is_empty());
        // Non-identifier boundary chars still match.
        assert_eq!(find_in_line(&format!("({value})")).len(), 1);
    }

    #[test]
    fn fixed_length_followed_by_extra_charset_char_does_not_match() {
        // One charset char too many after a fixed-length pattern.
        let value = "AKIA".to_string() + &"A".repeat(17);
        assert!(find_in_line(&value).is_empty());
    }

    #[test]
    fn value_shorter_than_min_len_does_not_match() {
        let value = "sk-ant-".to_string() + &"a".repeat(19);
        assert!(find_in_line(&value).is_empty());
    }

    #[test]
    fn masked_output_contains_prefix_head_and_length_but_never_the_value() {
        let value = "ghp_".to_string() + "x7Kq" + &"a".repeat(32);
        let hits = find_in_line(&format!("token={value}"));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].masked, "ghp_x7Kq…(40 chars)");
        assert!(!hits[0].masked.contains(&value));
    }

    #[test]
    fn private_key_mask_is_the_header_itself() {
        let header = "-----BEGIN ".to_string() + "RSA PRIVATE KEY-----";
        let hits = find_in_line(&header);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].masked, header);
    }

    #[test]
    fn two_secrets_on_one_line_are_both_found() {
        let a = "AKIA".to_string() + &"B".repeat(16);
        let b = "glpat-".to_string() + &"b".repeat(20);
        let hits = find_in_line(&format!("{a} {b}"));
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].pattern_id, "aws-access-key-id");
        assert_eq!(hits[1].pattern_id, "gitlab-pat");
    }
}
