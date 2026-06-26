use kprun_core::audit::{log_access, AuditRecord};
use kprun_core::inject::resolve_injection;
use kprun_core::Result;

use crate::spawn::run_child;

use super::unlock_vault_readonly;

pub fn execute(entries: Vec<String>, command: Vec<String>, clean_env: bool) -> i32 {
    match run_inner(entries, command, clean_env) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn run_inner(entries: Vec<String>, command: Vec<String>, clean_env: bool) -> Result<i32> {
    let (cfg, vault) = unlock_vault_readonly()?;
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

    let code = run_child(&command, &injection.env, clean_env)?;
    Ok(code)
}
