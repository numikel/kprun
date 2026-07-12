use std::io::ErrorKind;
use std::path::PathBuf;

use kprun_core::config::Config;
use kprun_core::unlock::delete_master_from_keystore;
use kprun_core::{KprunError, Result};

use crate::ui;

use super::{confirm_on_tty, run_command};

pub fn execute(db: Option<String>, delete_vault: bool, yes: bool) -> i32 {
    run_command(|| run(db, delete_vault, yes))
}

fn run(db: Option<String>, delete_vault: bool, yes: bool) -> Result<()> {
    ui::maybe_banner();
    let cfg = Config::from_env();
    // `--db` overrides KPRUN_DB / the default so deinit targets the same vault
    // (and keychain account) that `init --quick --db <path>` created.
    let db_path = db.map(PathBuf::from).unwrap_or_else(|| cfg.db_path.clone());

    if !delete_vault {
        delete_master_from_keystore(&db_path)?;
        ui::success(&format!(
            "Removed stored master password for {} from keychain (if present)",
            db_path.display()
        ));
        return Ok(());
    }

    ui::info(&format!("Vault: {}", db_path.display()));
    if !yes {
        let confirmed = confirm_on_tty(
            &format!(
                "Delete vault file {} and its keychain entry? [y/N]",
                db_path.display()
            ),
            "refusing to delete without confirmation; pass --yes or run from an interactive terminal",
        )?;
        if !confirmed {
            return Err(KprunError::Other("aborted; nothing deleted".into()));
        }
    }

    // The keyfile and access.log are never touched.
    //
    // Order matters for lockout safety: remove the vault FILE first, then the
    // keychain entry. `remove_file` is the failure-prone step (e.g. the .kdbx
    // is open in KeePassXC on Windows → AccessDenied). If we deleted the
    // keychain entry first and the file removal then failed, a password-only
    // vault would be left with no way to unlock it — permanent lockout. The
    // account name is a *lexical* digest of the path, stable whether or not the
    // file exists, so deleting the keychain entry after the file is gone still
    // targets the correct account.
    match std::fs::remove_file(&db_path) {
        Ok(()) => ui::success(&format!("Deleted vault file {}", db_path.display())),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            ui::info(&format!(
                "vault file {} not found (nothing to delete)",
                db_path.display()
            ));
        }
        Err(e) => return Err(e.into()),
    }
    delete_master_from_keystore(&db_path)?;
    ui::success("Removed stored master password from keychain (if present)");
    Ok(())
}
