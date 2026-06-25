use std::collections::HashSet;
use std::fs;
use std::path::Path;

use kprun_core::{KprunError, Result};
use serde::Deserialize;

use super::{mutate_vault, run_command};
use crate::ui;

pub fn execute(file: String, merge: bool) -> i32 {
    run_command(|| run(&file, merge))
}

#[derive(Debug, Deserialize)]
struct ImportFile {
    entries: Vec<ImportEntry>,
}

#[derive(Debug, Deserialize)]
struct ImportEntry {
    title: String,
    keys: serde_json::Value,
}

fn run(file: &str, merge: bool) -> Result<()> {
    ui::maybe_banner();
    let path = Path::new(file);
    let content = fs::read_to_string(path)?;
    let entries = if path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("json"))
    {
        parse_json_import(&content)?
    } else {
        parse_dotenv_import(&content)?
    };

    if !merge && entries.is_empty() {
        return Err(KprunError::Other(
            "import file contains no entries; refusing to replace vault".into(),
        ));
    }

    mutate_vault(|vault| {
        if !merge {
            let imported_titles: HashSet<String> =
                entries.iter().map(|e| e.title.clone()).collect();
            for summary in vault.list_entries() {
                if !imported_titles.contains(&summary.title) {
                    vault.delete_entry(&summary.title)?;
                }
            }
        }

        for entry in &entries {
            if !merge {
                if let Ok(id) = vault.find_entry_by_title(&entry.title) {
                    let existing = vault.entry_custom_keys(id);
                    let imported_keys: HashSet<&str> =
                        entry.pairs.iter().map(|(k, _)| k.as_str()).collect();
                    let to_remove: Vec<String> = existing
                        .into_iter()
                        .filter(|k| !imported_keys.contains(k.as_str()))
                        .collect();
                    if !to_remove.is_empty() {
                        vault.unset_attributes(&entry.title, &to_remove)?;
                    }
                }
            }
            vault.set_attributes(&entry.title, &entry.pairs)?;
        }
        Ok(())
    })?;
    let count = entries.len();
    let noun = if count == 1 { "entry" } else { "entries" };
    let mode = if merge {
        "merged into"
    } else {
        "imported into"
    };
    ui::success(&format!("{count} {noun} {mode} vault"));
    Ok(())
}

struct ParsedEntry {
    title: String,
    pairs: Vec<(String, String)>,
}

fn parse_json_import(content: &str) -> Result<Vec<ParsedEntry>> {
    let file: ImportFile = serde_json::from_str(content)?;
    file.entries
        .into_iter()
        .map(|entry| {
            let pairs = match entry.keys {
                serde_json::Value::Object(map) => map
                    .into_iter()
                    .map(|(k, v)| {
                        let value = v.as_str().ok_or_else(|| {
                            KprunError::Other(format!(
                                "import entry '{}' key '{}' must be a string value",
                                entry.title, k
                            ))
                        })?;
                        Ok((k, value.to_string()))
                    })
                    .collect::<Result<Vec<_>>>()?,
                other => {
                    return Err(KprunError::Other(format!(
                        "import entry '{}' keys must be an object, got {}",
                        entry.title, other
                    )));
                }
            };
            Ok(ParsedEntry {
                title: entry.title,
                pairs,
            })
        })
        .collect()
}

fn parse_dotenv_import(content: &str) -> Result<Vec<ParsedEntry>> {
    let mut entries = Vec::new();
    let mut current_title: Option<String> = None;
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut saw_structure = false;
    let mut saw_key_value = false;

    let flush = |title: &mut Option<String>,
                 pairs: &mut Vec<(String, String)>,
                 entries: &mut Vec<ParsedEntry>| {
        if let Some(t) = title.take() {
            if !pairs.is_empty() {
                entries.push(ParsedEntry {
                    title: t,
                    pairs: std::mem::take(pairs),
                });
            }
        }
    };

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            flush(&mut current_title, &mut pairs, &mut entries);
            continue;
        }

        if let Some(rest) = line.strip_prefix('#') {
            let label = rest.trim();
            if label.is_empty() {
                continue;
            }
            if current_title.is_none() {
                saw_structure = true;
                current_title = Some(label.to_string());
            } else if pairs.is_empty() && !label.contains('=') {
                // Commented key placeholder from non-reveal export — skip.
                saw_structure = true;
                continue;
            } else {
                flush(&mut current_title, &mut pairs, &mut entries);
                current_title = Some(label.to_string());
            }
            continue;
        }

        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            if key.is_empty() {
                return Err(KprunError::EmptyKey);
            }
            if current_title.is_none() {
                return Err(KprunError::Other(
                    "dotenv import line before entry title comment".into(),
                ));
            }
            saw_key_value = true;
            pairs.push((key.to_string(), parse_dotenv_value(value.trim())));
        } else {
            return Err(KprunError::Other(format!(
                "invalid dotenv import line: {line}"
            )));
        }
    }

    flush(&mut current_title, &mut pairs, &mut entries);

    if entries.is_empty() && saw_structure && !saw_key_value {
        return Err(KprunError::Other(
            "structure-only dotenv export cannot be imported; re-export with --reveal or use --merge carefully".into(),
        ));
    }

    Ok(entries)
}

/// Parse a dotenv value, unquoting and unescaping when wrapped in double quotes.
fn parse_dotenv_value(raw: &str) -> String {
    let bytes = raw.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
        unescape_dotenv_value(&raw[1..raw.len() - 1])
    } else {
        raw.to_string()
    }
}

fn unescape_dotenv_value(s: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::parse_dotenv_import;

    #[test]
    fn imports_quoted_value_with_escaped_newline() {
        let content = "# svc\nMULTI=\"line1\\nline2\"\n";
        let entries = parse_dotenv_import(content).unwrap();
        assert_eq!(entries[0].pairs[0].0, "MULTI");
        assert_eq!(entries[0].pairs[0].1, "line1\nline2");
    }
}
