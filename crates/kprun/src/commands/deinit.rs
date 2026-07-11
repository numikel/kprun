use std::io::ErrorKind;

use kprun_core::config::Config;
use kprun_core::unlock::delete_master_from_keystore;
use kprun_core::{KprunError, Result};

use crate::ui;

use super::{confirm_on_tty, run_command};

pub fn execute(delete_vault: bool, yes: bool) -> i32 {
    run_command(|| run(delete_vault, yes))
}

fn run(delete_vault: bool, yes: bool) -> Result<()> {
    ui::maybe_banner();
    let cfg = Config::from_env();

    if !delete_vault {
        delete_master_from_keystore(&cfg.db_path)?;
        ui::success(&format!(
            "Removed stored master password for {} from keychain",
            cfg.db_path.display()
        ));
        return Ok(());
    }

    ui::info(&format!("Vault: {}", cfg.db_path.display()));
    if !yes {
        let confirmed = confirm_on_tty(
            &format!(
                "Delete vault file {} and its keychain entry? [y/N]",
                cfg.db_path.display()
            ),
            "refusing to delete without confirmation; pass --yes or run from an interactive terminal",
        )?;
        if !confirmed {
            return Err(KprunError::Other("aborted; nothing deleted".into()));
        }
    }

    // The keyfile and access.log are never touched.
    //
    // Order matters: delete the keychain entry BEFORE removing the file. The
    // per-vault account name is a SHA-256 of the *canonicalized* db path, and
    // canonicalization only resolves while the file still exists. Removing the
    // file first would make the account hash fall back to the raw path, so the
    // delete would target a different account and silently orphan the real
    // entry. Do not reorder these two operations.
    delete_master_from_keystore(&cfg.db_path)?;
    match std::fs::remove_file(&cfg.db_path) {
        Ok(()) => ui::success(&format!("Deleted vault file {}", cfg.db_path.display())),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            ui::info(&format!(
                "vault file {} not found (nothing to delete)",
                cfg.db_path.display()
            ));
        }
        Err(e) => return Err(e.into()),
    }
    ui::success("Removed stored master password from keychain");
    Ok(())
}
