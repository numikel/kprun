use std::io::{self, BufRead, IsTerminal};
use std::path::{Path, PathBuf};

use kprun_core::config::Config;
use kprun_core::unlock::{
    build_database_key, generate_keyfile, store_master_in_keystore, unlock_with_fallback,
    UnlockContext,
};
use kprun_core::vault::{create_vault, open_vault, OpenMode};
use kprun_core::{KprunError, Result};
use zeroize::Zeroizing;

const MIN_MASTER_LEN: usize = 12;

pub fn execute(db: Option<String>, no_store: bool, keyfile: Option<String>) -> i32 {
    match run(db, no_store, keyfile) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn run(db: Option<String>, no_store: bool, keyfile: Option<String>) -> Result<()> {
    let cfg = Config::from_env();
    let db_path = db.map(PathBuf::from).unwrap_or_else(|| cfg.db_path.clone());
    let keyfile_path = keyfile.map(PathBuf::from).or_else(|| cfg.keyfile.clone());

    if let Some(ref kf) = keyfile_path {
        if !kf.exists() {
            eprintln!("Generating keyfile at {}", kf.display());
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

fn verify_existing(ctx: &UnlockContext, db_path: &Path, no_store: bool) -> Result<()> {
    eprintln!("Verifying database at {}", db_path.display());
    let master = unlock_with_fallback(ctx)?;
    let db_key = build_database_key(ctx, &master)?;
    let _vault = open_vault(db_path, db_key, OpenMode::ReadOnly)?;

    if !no_store {
        store_master_in_keystore(db_path, &master)?;
        eprintln!("Master password stored in OS keychain.");
    }

    eprintln!("Database verified successfully.");
    eprintln!("Hint: use `kprun set <entry> KEY=val ...` to add secrets.");
    Ok(())
}

fn create_new(cfg: &Config, db_path: &Path, ctx: &UnlockContext, no_store: bool) -> Result<()> {
    cfg.ensure_parent_dirs(db_path)?;
    let master = prompt_new_master()?;
    let db_key = build_database_key(ctx, &master)?;
    create_vault(db_path, db_key, "kprun")?;
    eprintln!("Created KeePass database at {}", db_path.display());

    if !no_store {
        store_master_in_keystore(db_path, &master)?;
        eprintln!("Master password stored in OS keychain.");
    }

    eprintln!("Hint: use `kprun set <entry> KEY=val ...` to add secrets.");
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
}
