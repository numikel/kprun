use std::fs;
use std::path::Path;

use kprun_core::dotenv::parse_dotenv_value;
use kprun_core::import::{apply_import, ImportEntry, ImportMode};
use kprun_core::{KprunError, Result};
use serde::Deserialize;

use kprun_core::audit::AuditRecord;

use super::{audit_access, mutate_vault, run_command};
use crate::ui;

pub fn execute(file: String, merge: bool) -> i32 {
    run_command(|| run(&file, merge))
}

#[derive(Debug, Deserialize)]
struct ImportFile {
    entries: Vec<JsonImportEntry>,
}

#[derive(Debug, Deserialize)]
struct JsonImportEntry {
    title: String,
    keys: serde_json::Value,
}

fn run(file: &str, merge: bool) -> Result<()> {
    ui::maybe_banner();
    let path = Path::new(file);
    let content = fs::read_to_string(path)?;
    let parsed = if path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("json"))
    {
        parse_json_import(&content)?
    } else {
        parse_dotenv_import(&content)?
    };

    let entries: Vec<ImportEntry> = parsed
        .into_iter()
        .map(|e| ImportEntry {
            title: e.title,
            pairs: e.pairs,
        })
        .collect();

    let mode = if merge {
        ImportMode::Merge
    } else {
        ImportMode::Replace
    };

    let cfg = mutate_vault(|vault| {
        apply_import(vault, &entries, mode)?;
        Ok(())
    })?;

    // Audit: all imported entry titles and key names, never values.
    // A failed audit write warns and does not abort — the import already
    // happened.
    let titles: Vec<String> = entries.iter().map(|e| e.title.clone()).collect();
    let keys: Vec<String> = entries
        .iter()
        .flat_map(|e| e.pairs.iter().map(|(k, _)| k.clone()))
        .collect();
    let record = AuditRecord::new(&cfg.db_path, titles, keys, Some("import".to_string()));
    if let Err(e) = audit_access(&cfg, record) {
        eprintln!("WARNING: failed to write audit log: {e}");
    }

    let count = entries.len();
    let noun = if count == 1 { "entry" } else { "entries" };
    let mode_label = if merge {
        "merged into"
    } else {
        "imported into"
    };
    ui::success(&format!("{count} {noun} {mode_label} vault"));
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

enum DotenvParserState {
    Idle,
    InEntry {
        title: String,
        pairs: Vec<(String, String)>,
    },
}

struct DotenvParser {
    state: DotenvParserState,
    entries: Vec<ParsedEntry>,
    saw_structure: bool,
    saw_key_value: bool,
}

impl DotenvParser {
    fn new() -> Self {
        Self {
            state: DotenvParserState::Idle,
            entries: Vec::new(),
            saw_structure: false,
            saw_key_value: false,
        }
    }

    fn flush_entry(&mut self) {
        if let DotenvParserState::InEntry { title, pairs } =
            std::mem::replace(&mut self.state, DotenvParserState::Idle)
        {
            if !pairs.is_empty() {
                self.entries.push(ParsedEntry { title, pairs });
            }
        }
    }

    fn feed(&mut self, line: &str) -> Result<()> {
        let line = line.trim();
        if line.is_empty() {
            self.flush_entry();
            return Ok(());
        }

        if let Some(rest) = line.strip_prefix('#') {
            let label = rest.trim();
            if label.is_empty() {
                return Ok(());
            }
            match &self.state {
                DotenvParserState::Idle => {
                    self.saw_structure = true;
                    self.state = DotenvParserState::InEntry {
                        title: label.to_string(),
                        pairs: Vec::new(),
                    };
                }
                DotenvParserState::InEntry { pairs, .. }
                    if pairs.is_empty() && !label.contains('=') =>
                {
                    self.saw_structure = true;
                }
                DotenvParserState::InEntry { .. } => {
                    self.flush_entry();
                    self.state = DotenvParserState::InEntry {
                        title: label.to_string(),
                        pairs: Vec::new(),
                    };
                }
            }
            return Ok(());
        }

        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            if key.is_empty() {
                return Err(KprunError::EmptyKey);
            }
            match &mut self.state {
                DotenvParserState::Idle => {
                    return Err(KprunError::Other(
                        "dotenv import line before entry title comment".into(),
                    ));
                }
                DotenvParserState::InEntry { pairs, .. } => {
                    self.saw_key_value = true;
                    pairs.push((key.to_string(), parse_dotenv_value(value.trim())));
                }
            }
            return Ok(());
        }

        Err(KprunError::Other(format!(
            "invalid dotenv import line: {line}"
        )))
    }

    fn finish(mut self) -> Result<Vec<ParsedEntry>> {
        self.flush_entry();
        if self.entries.is_empty() && self.saw_structure && !self.saw_key_value {
            return Err(KprunError::Other(
                "structure-only dotenv export cannot be imported; re-export with --reveal or use --merge carefully".into(),
            ));
        }
        Ok(self.entries)
    }
}

fn parse_dotenv_import(content: &str) -> Result<Vec<ParsedEntry>> {
    let mut parser = DotenvParser::new();
    for line in content.lines() {
        parser.feed(line)?;
    }
    parser.finish()
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
