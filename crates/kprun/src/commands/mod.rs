use kprun_core::audit::{log_access, AuditRecord};
use kprun_core::config::Config;
use kprun_core::unlock::{build_database_key, unlock_with_fallback, UnlockContext};
use kprun_core::vault::{open_vault, OpenMode, Vault, VaultKey};
use kprun_core::Result;

use crate::cli::Commands;

mod deinit;
mod delete;
mod doctor;
mod export;
mod get;
mod import;
mod init;
mod list;
mod mcp;
mod migrate;
mod reveal_master;
mod run;
mod scan;
mod set;
mod unset;

pub fn dispatch(command: Commands) {
    match command {
        Commands::Init {
            db,
            no_store,
            keyfile,
            quick,
            force,
        } => std::process::exit(init::execute(db, no_store, keyfile, quick, force)),
        Commands::Run {
            entries,
            command,
            clean_env,
        } => std::process::exit(run::execute(entries, command, clean_env)),
        Commands::List { json } => std::process::exit(list::execute(json)),
        Commands::Get {
            entry,
            keys,
            reveal,
        } => std::process::exit(get::execute(entry, keys, reveal)),
        Commands::Set {
            entry,
            pairs,
            stdin,
        } => std::process::exit(set::execute(entry, pairs, stdin)),
        Commands::Unset { entry, keys } => std::process::exit(unset::execute(entry, keys)),
        Commands::Delete { entry } => std::process::exit(delete::execute(entry)),
        Commands::Export {
            format,
            stdout,
            reveal,
            output,
        } => std::process::exit(export::execute(format, stdout, reveal, output)),
        Commands::Import { file, merge } => std::process::exit(import::execute(file, merge)),
        Commands::Migrate {
            file,
            entry,
            merge,
            gitignore,
            delete,
        } => std::process::exit(migrate::execute(file, entry, merge, gitignore, delete)),
        Commands::Doctor { mcp, command } => std::process::exit(doctor::execute(mcp, command)),
        Commands::Mcp {
            entry,
            headers,
            bearer,
            transport,
            timeout,
            allow_insecure_http,
            url,
        } => std::process::exit(mcp::execute(
            entry,
            headers,
            bearer,
            transport,
            timeout,
            allow_insecure_http,
            url,
        )),
        Commands::RevealMaster { db } => std::process::exit(reveal_master::execute(db)),
        Commands::Deinit {
            db,
            delete_vault,
            yes,
        } => std::process::exit(deinit::execute(db, delete_vault, yes)),
        Commands::Scan {
            path,
            history,
            full_history,
            json,
        } => std::process::exit(scan::execute(path, history, full_history, json)),
    }
}

fn unlock_vault(mode: OpenMode) -> Result<(Config, Vault, VaultKey)> {
    let cfg = Config::from_env();
    let ctx = UnlockContext {
        keyfile: cfg.keyfile.clone(),
        db_path: cfg.db_path.clone(),
    };
    let master = unlock_with_fallback(&ctx)?;
    let db_key = build_database_key(&ctx, &master)?;
    let vault = open_vault(&cfg.db_path, db_key.clone(), mode)?;
    Ok((cfg, vault, db_key))
}

fn unlock_vault_readonly() -> Result<(Config, Vault)> {
    let (cfg, vault, _key) = unlock_vault(OpenMode::ReadOnly)?;
    Ok((cfg, vault))
}

pub(crate) fn run_command<F>(f: F) -> i32
where
    F: FnOnce() -> Result<()>,
{
    match f() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

/// Unlock read-write, apply `f`, save atomically. Returns the `Config` so
/// callers can write audit records against the same vault/log paths.
fn mutate_vault<F>(f: F) -> Result<Config>
where
    F: FnOnce(&mut Vault) -> Result<()>,
{
    let (cfg, mut vault, db_key) = unlock_vault(OpenMode::ReadWrite)?;
    f(&mut vault)?;
    vault.save(db_key)?;
    Ok(cfg)
}

fn warn_secret_display() {
    eprintln!("WARNING: secret values are displayed in the terminal");
}

/// Ask `prompt` on stderr and read a y/N answer. Errors with `no_tty_error`
/// when stdin is not a terminal — destructive actions are never confirmed
/// implicitly by piped input.
fn confirm_on_tty(prompt: &str, no_tty_error: &str) -> Result<bool> {
    use std::io::{BufRead, IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return Err(kprun_core::KprunError::Other(no_tty_error.to_string()));
    }
    eprint!("{prompt} ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(kprun_core::KprunError::Io)?;
    Ok(is_yes(&line))
}

/// Only a literal trimmed `y` confirms — the [y/N] default is No.
fn is_yes(line: &str) -> bool {
    line.trim() == "y"
}

fn audit_access(cfg: &Config, record: AuditRecord) -> Result<()> {
    log_access(cfg, &record)
}

#[cfg(test)]
mod tests {
    use super::is_yes;

    #[test]
    fn only_bare_y_confirms() {
        assert!(is_yes("y\n"));
        assert!(is_yes(" y \r\n"));
        assert!(!is_yes("Y\n"));
        assert!(!is_yes("yes\n"));
        assert!(!is_yes("\n"));
        assert!(!is_yes("n\n"));
    }
}
