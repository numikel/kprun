use std::io::{self, BufRead, IsTerminal};
use std::path::{Path, PathBuf};

use kprun_core::config::Config;
use kprun_core::unlock::{
    build_database_key, generate_keyfile, generate_master_password, probe_keystore,
    store_master_in_keystore, unlock_with_fallback, UnlockContext,
};
use kprun_core::vault::{create_vault, open_vault, OpenMode};
use kprun_core::{KprunError, Result};
use zeroize::Zeroizing;

use crate::ui;

const MIN_MASTER_LEN: usize = 12;

use super::run_command;

pub fn execute(
    db: Option<String>,
    no_store: bool,
    keyfile: Option<String>,
    quick: bool,
    force: bool,
) -> i32 {
    if quick {
        run_command(|| run_quick(db, force))
    } else {
        run_command(|| run(db, no_store, keyfile))
    }
}

fn run(db: Option<String>, no_store: bool, keyfile: Option<String>) -> Result<()> {
    ui::maybe_banner();

    let cfg = Config::from_env();
    let db_path = db.map(PathBuf::from).unwrap_or_else(|| cfg.db_path.clone());
    let keyfile_path = keyfile.map(PathBuf::from).or_else(|| cfg.keyfile.clone());

    if let Some(ref kf) = keyfile_path {
        if !kf.exists() {
            ui::info(&format!("Generating keyfile at {}", kf.display()));
            generate_keyfile(kf)?;
        }
    }

    let ctx = UnlockContext {
        keyfile: keyfile_path,
        db_path: db_path.clone(),
    };

    if db_path.exists() {
        verify_existing(&ctx, &db_path, no_store)
    } else {
        create_new(&cfg, &db_path, &ctx, no_store)
    }
}

fn run_quick(db: Option<String>, force: bool) -> Result<()> {
    ui::maybe_banner();

    let cfg = Config::from_env();
    let db_path = db.map(PathBuf::from).unwrap_or_else(|| cfg.db_path.clone());

    // A quick vault is always password-only, so the revealed password alone
    // opens it in KeePassXC.
    if cfg.keyfile.is_some() {
        ui::info("ignoring KPRUN_KEYFILE (--quick creates a password-only vault)");
    }

    if db_path.exists() {
        if !force {
            return Err(KprunError::Other(format!(
                "Vault already exists at {p}. Run 'kprun init' to attach it, 'kprun init --quick --force' to overwrite, or 'kprun deinit --delete-vault' to remove it.",
                p = db_path.display()
            )));
        }
        ui::info(&format!(
            "Consider a backup first: cp {p} {p}.bak",
            p = db_path.display()
        ));
        let confirmed = super::confirm_on_tty(
            &format!("Overwrite existing vault at {}? [y/N]", db_path.display()),
            "overwrite requires interactive confirmation (no terminal detected)",
        )?;
        if !confirmed {
            return Err(KprunError::Other(
                "aborted; existing vault left untouched".into(),
            ));
        }
    }

    ui::step(1, 3, "Checking OS keychain availability");
    probe_keystore().map_err(keychain_unavailable)?;

    ui::step(
        2,
        3,
        &format!("Creating KeePass database at {}", db_path.display()),
    );
    cfg.ensure_parent_dirs(&db_path)?;
    if force && db_path.exists() {
        // create_vault refuses to overwrite; the user confirmed above and
        // the keychain probe already succeeded.
        std::fs::remove_file(&db_path)?;
    }
    let master = generate_master_password();
    let ctx = UnlockContext {
        keyfile: None,
        db_path: db_path.clone(),
    };
    let db_key = build_database_key(&ctx, &master)?;
    create_vault(&db_path, db_key, "kprun")?;

    ui::step(3, 3, "Storing master password in OS keychain");
    if let Err(e) = store_master_in_keystore(&db_path, &master) {
        let _ = std::fs::remove_file(&db_path);
        return Err(e);
    }

    ui::success(&format!("Vault ready at {}", db_path.display()));
    ui::info("(shown once — save it for KeePassXC; retrieve later with 'kprun reveal-master')");
    println!("{}", master.as_str());
    ui::next_steps(&[
        "kprun set github GITHUB_TOKEN=ghp_xxx",
        "kprun run github -- npx @modelcontextprotocol/server-github",
        "kprun doctor --mcp github",
    ]);
    Ok(())
}

/// Classify a keychain-probe failure into the user-facing abort message —
/// no vault is created when the keychain cannot round-trip a credential.
fn keychain_unavailable(e: KprunError) -> KprunError {
    KprunError::Other(format!(
        "OS keychain unavailable ({e}). Run 'kprun init' to choose a password interactively."
    ))
}

fn verify_existing(ctx: &UnlockContext, db_path: &Path, no_store: bool) -> Result<()> {
    let total = if no_store { 1 } else { 2 };
    ui::step(
        1,
        total,
        &format!("Verifying database at {}", db_path.display()),
    );
    let master = unlock_with_fallback(ctx)?;
    let db_key = build_database_key(ctx, &master)?;
    let _vault = open_vault(db_path, db_key, OpenMode::ReadOnly)?;

    if !no_store {
        ui::step(2, total, "Storing master password in OS keychain");
        store_master_in_keystore(db_path, &master)?;
    }

    ui::success("Database verified");
    ui::next_steps(&[
        "kprun list",
        "kprun set <entry> KEY=val ...",
        "kprun doctor",
    ]);
    Ok(())
}

fn create_new(cfg: &Config, db_path: &Path, ctx: &UnlockContext, no_store: bool) -> Result<()> {
    cfg.ensure_parent_dirs(db_path)?;
    let total = if no_store { 2 } else { 3 };

    ui::step(1, total, "Choose a master password (min 12 characters)");
    let master = prompt_new_master()?;

    ui::step(
        2,
        total,
        &format!("Creating KeePass database at {}", db_path.display()),
    );
    let db_key = build_database_key(ctx, &master)?;
    create_vault(db_path, db_key, "kprun")?;

    if !no_store {
        ui::step(3, total, "Storing master password in OS keychain");
        store_master_in_keystore(db_path, &master)?;
    }

    ui::success(&format!("Vault ready at {}", db_path.display()));
    ui::next_steps(&[
        "kprun set github GITHUB_TOKEN=ghp_xxx",
        "kprun run github -- npx @modelcontextprotocol/server-github",
        "kprun doctor --mcp github",
    ]);
    Ok(())
}

fn validate_new_master(pw1: &str, pw2: &str) -> Result<()> {
    if pw1 != pw2 {
        return Err(KprunError::Other("passwords do not match".into()));
    }
    if pw1.chars().count() < MIN_MASTER_LEN {
        return Err(KprunError::WeakPassword(MIN_MASTER_LEN));
    }
    Ok(())
}

fn prompt_new_master() -> Result<Zeroizing<String>> {
    #[cfg(feature = "test-hooks")]
    if let Ok(pw) = std::env::var("KPRUN_TEST_MASTER") {
        return Ok(Zeroizing::new(pw));
    }

    let pw1 = read_password_prompt("Choose KeePass master password: ")?;
    let pw2 = read_password_prompt("Confirm master password: ")?;
    validate_new_master(&pw1, &pw2)?;
    Ok(pw1)
}

fn read_password_prompt(prompt: &str) -> Result<Zeroizing<String>> {
    #[cfg(feature = "test-hooks")]
    if let Ok(pw) = std::env::var("KPRUN_TEST_MASTER") {
        return Ok(Zeroizing::new(pw));
    }

    if io::stdin().is_terminal() {
        let pw =
            rpassword::prompt_password(prompt).map_err(|e| KprunError::Other(e.to_string()))?;
        return Ok(Zeroizing::new(pw));
    }

    eprint!("{prompt}");
    eprintln!(
        "\nWARNING: reading password from a non-terminal (pipe); the value may be visible in shell history or process listings"
    );
    let mut line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(KprunError::Io)?;
    Ok(Zeroizing::new(
        line.trim_end_matches(['\r', '\n']).to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_password() {
        assert!(matches!(
            validate_new_master("short", "short"),
            Err(KprunError::WeakPassword(12))
        ));
    }

    #[test]
    fn accepts_long_matching_password() {
        assert!(validate_new_master("a-strong-passphrase", "a-strong-passphrase").is_ok());
    }

    #[test]
    fn rejects_mismatch() {
        assert!(validate_new_master("a-strong-passphrase", "different-passphrase").is_err());
    }

    #[test]
    fn keychain_unavailable_wraps_probe_error() {
        let msg = keychain_unavailable(KprunError::Other("no secret service".into())).to_string();
        assert!(msg.contains("OS keychain unavailable (no secret service)"));
        assert!(msg.contains("kprun init"));
    }
}
