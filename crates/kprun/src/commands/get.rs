use kprun_core::audit::{log_access, AuditRecord};
use kprun_core::vault::OpenMode;
use kprun_core::Result;

use super::unlock_vault;

pub fn execute(entry: String, keys_only: bool, reveal: bool) -> i32 {
    match run(&entry, keys_only, reveal) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn run(entry: &str, keys_only: bool, reveal: bool) -> Result<()> {
    let (cfg, _ctx, vault) = unlock_vault(OpenMode::ReadOnly)?;
    let id = vault.find_entry_by_title(entry)?;
    let keys = vault.entry_custom_keys(id);

    if keys_only {
        for k in &keys {
            println!("{k}");
        }
        return Ok(());
    }

    if reveal {
        eprintln!("WARNING: secret values are displayed in the terminal");
        let values = vault.entry_custom_values(id);
        for k in &keys {
            if let Some(v) = values.get(k) {
                println!("{k}={v}");
            }
        }
        log_access(
            &cfg,
            &AuditRecord::new(
                cfg.db_path.clone(),
                vec![entry.to_string()],
                keys,
                None,
            ),
        )?;
        return Ok(());
    }

    println!("title: {entry}");
    println!("keys: {}", keys.join(", "));
    Ok(())
}
