use std::io::{self, Write};

use kprun_core::audit::{log_access, AuditRecord};
use kprun_core::vault::OpenMode;
use kprun_core::Result;
use serde_json::{json, Value};

use crate::cli::ExportFormat;

use super::unlock_vault;

pub fn execute(format: ExportFormat, stdout: bool, reveal: bool) -> i32 {
    match run(format, stdout, reveal) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn run(format: ExportFormat, stdout: bool, reveal: bool) -> Result<()> {
    let (cfg, _ctx, vault, _db_key) = unlock_vault(OpenMode::ReadOnly)?;
    let summaries = vault.list_entries();

    if reveal {
        eprintln!("WARNING: secret values are displayed in the terminal");
    }

    let output = match format {
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
        out.write_all(output.as_bytes())?;
        if !output.ends_with('\n') {
            out.write_all(b"\n")?;
        }
    } else {
        let path = default_export_path(format);
        kprun_core::secure_fs::write_restricted(&path, output.as_bytes())?;
        eprintln!("wrote export to {} (permissions restricted to owner)", path.display());
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
                    lines.push(format!("{key}={value}"));
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
