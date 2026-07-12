use std::path::PathBuf;

use kprun_core::audit::AuditRecord;
use kprun_core::config::Config;
use kprun_core::unlock::read_master_from_keystore;
use kprun_core::{KprunError, Result};

use crate::ui;

use super::{audit_access, run_command, warn_secret_display};

pub fn execute(db: Option<String>) -> i32 {
    run_command(|| run(db))
}

fn run(db: Option<String>) -> Result<()> {
    ui::maybe_banner();
    let cfg = Config::from_env();
    // `--db` overrides KPRUN_DB / the default so the keychain account matches
    // the vault that `init --quick --db <path>` stored under.
    let db_path = db.map(PathBuf::from).unwrap_or_else(|| cfg.db_path.clone());

    // The keychain is the source of truth: the vault file does not need to
    // exist or be unlockable for the stored password to be retrievable.
    let master = read_master_from_keystore(&db_path).map_err(|e| match e {
        KprunError::UnlockFailed => KprunError::Other(format!(
            "No master password stored in the OS keychain for this vault (did you init with --no-store?). Vault: {}",
            db_path.display()
        )),
        KprunError::Keyring(inner) => KprunError::Other(format!(
            "OS keychain unavailable while reading the stored master password ({inner}). On headless Linux start/unlock a secret-service store; on macOS approve the keychain access prompt. Vault: {}",
            db_path.display()
        )),
        other => other,
    })?;

    // Warn and audit before printing (unlike `get --reveal`, which audits
    // after printing): an audit-write failure here blocks the password from
    // ever reaching stdout, since there is no vault entry list to print first.
    warn_secret_display();
    audit_access(
        &cfg,
        AuditRecord::new(&db_path, vec![], vec![], Some("reveal-master".to_string())),
    )?;
    println!("{}", master.as_str());
    Ok(())
}
