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
