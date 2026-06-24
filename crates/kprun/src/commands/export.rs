use std::io::{self, Write};

use kprun_core::audit::{log_access, AuditRecord};
use kprun_core::vault::OpenMode;
use kprun_core::Result;
use serde_json::{json, Value};

use crate::cli::ExportFormat;

use super::unlock_vault;

pub fn execute(format: ExportFormat, stdout: bool, reveal: bool, output: Option<String>) -> i32 {
    match run(format, stdout, reveal, output) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn run(format: ExportFormat, stdout: bool, reveal: bool, output: Option<String>) -> Result<()> {
    let (cfg, _ctx, vault, _db_key) = unlock_vault(OpenMode::ReadOnly)?;
    let summaries = vault.list_entries();

    if reveal {
        eprintln!("WARNING: secret values are displayed in the terminal");
    }

    let output_str = match format {
        ExportFormat::Json => export_json(&vault, &summaries, reveal)?,
        ExportFormat::Dotenv => export_dotenv(&vault, &summaries, reveal)?,
    };

    if reveal {
        let titles: Vec<String> = summaries.iter().map(|e| e.title.clone()).collect();
        let keys: Vec<String> = summaries.iter().flat_map(|e| e.keys.clone()).collect();
        log_access(
            &cfg,
            &AuditRecord::new(cfg.db_path.clone(), titles, keys, None),
        )?;
    }

    if stdout {
        let mut out = io::stdout().lock();
        out.write_all(output_str.as_bytes())?;
        if !output_str.ends_with('\n') {
            out.write_all(b"\n")?;
        }
    } else {
        let path = output
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| default_export_path(format));
        if reveal {
            eprintln!(
                "WARNING: writing plaintext secrets to {} (permissions restricted to owner)",
                path.display()
            );
        }
        kprun_core::secure_fs::write_restricted(&path, output_str.as_bytes())?;
        eprintln!("wrote export to {}", path.display());
    }

    Ok(())
}

fn default_export_path(format: ExportFormat) -> std::path::PathBuf {
    match format {
        ExportFormat::Json => std::path::PathBuf::from("kprun-export.json"),
        ExportFormat::Dotenv => std::path::PathBuf::from("kprun-export.env"),
    }
}

fn export_json(
    vault: &kprun_core::vault::Vault,
    summaries: &[kprun_core::vault::EntrySummary],
    reveal: bool,
) -> Result<String> {
    let entries: Vec<Value> = summaries
        .iter()
        .map(|summary| {
            let keys_value = if reveal {
                let id = vault.find_entry_by_title(&summary.title)?;
                let values = vault.entry_custom_values(id);
                json!(values)
            } else {
                json!(summary.keys)
            };
            Ok(json!({
                "title": summary.title,
                "keys": keys_value,
            }))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(serde_json::to_string_pretty(
        &json!({ "entries": entries }),
    )?)
}

fn export_dotenv(
    vault: &kprun_core::vault::Vault,
    summaries: &[kprun_core::vault::EntrySummary],
    reveal: bool,
) -> Result<String> {
    let mut blocks = Vec::new();

    for summary in summaries {
        let mut lines = vec![format!("# {}", summary.title)];
        if reveal {
            let id = vault.find_entry_by_title(&summary.title)?;
            let values = vault.entry_custom_values(id);
            for key in &summary.keys {
                if let Some(value) = values.get(key) {
                    let escaped = value
                        .replace('\\', "\\\\")
                        .replace('\n', "\\n")
                        .replace('\r', "\\r");
                    lines.push(format!("{key}=\"{escaped}\""));
                }
            }
        } else {
            for key in &summary.keys {
                lines.push(format!("# {key}"));
            }
        }
        blocks.push(lines.join("\n"));
    }

    Ok(blocks.join("\n\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kprun_core::unlock::{build_database_key, UnlockContext};
    use kprun_core::vault::{create_vault, open_vault, OpenMode};
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn dotenv_export_escapes_newlines() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("e.kdbx");
        let ctx = UnlockContext {
            keyfile: None,
            db_path: PathBuf::from("test.kdbx"),
        };
        let key = build_database_key(&ctx, "pass").unwrap();
        create_vault(&path, key.clone(), "kprun").unwrap();
        let mut v = open_vault(&path, key.clone(), OpenMode::ReadWrite).unwrap();
        v.set_attributes("svc", &[("MULTI".into(), "line1\nline2".into())])
            .unwrap();
        v.save(key.clone()).unwrap();

        let v2 = open_vault(&path, key, OpenMode::ReadOnly).unwrap();
        let summaries = v2.list_entries();
        let out = export_dotenv(&v2, &summaries, true).unwrap();
        assert!(out.contains("MULTI=\"line1\\nline2\""));
    }
}
