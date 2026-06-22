use kprun_core::audit::{log_access, AuditRecord};
use kprun_core::config::Config;
use kprun_core::inject::resolve_injection;
use kprun_core::unlock::{build_database_key, unlock_with_fallback, UnlockContext};
use kprun_core::vault::{open_vault, OpenMode};
use kprun_core::Result;

use crate::spawn::run_child;

pub fn execute(entries: Vec<String>, command: Vec<String>) -> i32 {
    match run_inner(entries, command) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn run_inner(entries: Vec<String>, command: Vec<String>) -> Result<i32> {
    let cfg = Config::from_env();
    let ctx = UnlockContext {
        keyfile: cfg.keyfile.clone(),
    };

    let master = unlock_with_fallback(&ctx)?;
    let db_key = build_database_key(&ctx, &master)?;
    let vault = open_vault(&cfg.db_path, db_key, OpenMode::ReadOnly)?;

    let injection = resolve_injection(&vault, &entries)?;

    if injection.injected_keys.is_empty() {
        eprintln!("WARNING: no keys injected from vault entries");
    }

    let child_cmd = command.first().cloned();
    log_access(
        &cfg,
        &AuditRecord::new(
            cfg.db_path.clone(),
            injection.entries.clone(),
            injection.injected_keys.clone(),
            child_cmd,
        ),
    )?;

    let code = run_child(&command, &injection.env)?;
    Ok(code)
}
