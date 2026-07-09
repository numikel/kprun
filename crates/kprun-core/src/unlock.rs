use std::fs::File;
use std::path::{Path, PathBuf};

use keepass::DatabaseKey;
use keyring::v1::Entry;
use zeroize::Zeroizing;

use crate::vault::VaultKey;
use crate::{KprunError, Result};

const SERVICE: &str = "kprun";

pub struct UnlockContext {
    pub keyfile: Option<PathBuf>,
    pub db_path: PathBuf,
}

pub trait MasterPasswordSource {
    fn get_master(&self) -> Result<Zeroizing<String>>;
}

pub struct SystemUnlock<'a> {
    pub db_path: &'a Path,
}

impl MasterPasswordSource for SystemUnlock<'_> {
    fn get_master(&self) -> Result<Zeroizing<String>> {
        let entry = Entry::new(SERVICE, &keychain_account(self.db_path))?;
        match entry.get_password() {
            Ok(pw) => Ok(Zeroizing::new(pw)),
            Err(keyring::v1::Error::NoEntry) => Err(KprunError::UnlockFailed),
            Err(e) => Err(KprunError::Keyring(e)),
        }
    }
}

pub struct PromptUnlock;

impl MasterPasswordSource for PromptUnlock {
    fn get_master(&self) -> Result<Zeroizing<String>> {
        #[cfg(feature = "test-hooks")]
        if let Ok(pw) = std::env::var("KPRUN_TEST_MASTER") {
            return Ok(Zeroizing::new(pw));
        }
        let pw = rpassword::prompt_password("KeePass master password: ")
            .map_err(|e| KprunError::Other(e.to_string()))?;
        if pw.is_empty() {
            return Err(KprunError::UnlockFailed);
        }
        Ok(Zeroizing::new(pw))
    }
}

/// Test helper — production code uses SystemUnlock then PromptUnlock fallback.
#[cfg(feature = "test-hooks")]
pub struct FixedUnlock(pub String);

#[cfg(feature = "test-hooks")]
impl MasterPasswordSource for FixedUnlock {
    fn get_master(&self) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(self.0.clone()))
    }
}

/// Derive a stable, per-vault keychain account name from the database path,
/// so different vaults never overwrite each other's stored master password.
fn keychain_account(db_path: &Path) -> String {
    format!("master:{}", path_digest_hex(db_path))
}

/// Full lowercase-hex SHA-256 of the canonicalized db path (raw path on
/// canonicalize failure). Shared by the keyring account name and `vault_id`.
fn path_digest_hex(db_path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let canonical = std::fs::canonicalize(db_path).unwrap_or_else(|_| db_path.to_path_buf());
    let digest = Sha256::digest(canonical.to_string_lossy().as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Stable, non-identifying vault identifier for the audit log: the first 16
/// hex chars of the same digest the OS keyring account name uses.
pub fn vault_id(db_path: &Path) -> String {
    path_digest_hex(db_path)[..16].to_string()
}

pub fn unlock_master(
    _ctx: &UnlockContext,
    source: &dyn MasterPasswordSource,
) -> Result<Zeroizing<String>> {
    source.get_master()
}

/// Outcome of attempting the OS keyring as a master-password source, shared
/// by `unlock_with_fallback` and `unlock_noninteractive` so both classify
/// keyring errors identically before diverging on their own fallback policy.
enum KeyringOutcome {
    Found(Zeroizing<String>),
    /// No stored entry, or a keyring backend error (e.g. headless Linux CI
    /// with no secret-service store) — caller should try its fallback.
    Recoverable,
    Fatal(KprunError),
}

fn try_keyring(ctx: &UnlockContext) -> KeyringOutcome {
    match unlock_master(
        ctx,
        &SystemUnlock {
            db_path: &ctx.db_path,
        },
    ) {
        Ok(pw) => KeyringOutcome::Found(pw),
        Err(KprunError::UnlockFailed) | Err(KprunError::Keyring(_)) => KeyringOutcome::Recoverable,
        Err(e) => KeyringOutcome::Fatal(e),
    }
}

pub fn unlock_with_fallback(ctx: &UnlockContext) -> Result<Zeroizing<String>> {
    // Test hook must override keyring so integration tests stay deterministic locally.
    #[cfg(feature = "test-hooks")]
    if std::env::var("KPRUN_TEST_MASTER").is_ok() {
        return unlock_master(ctx, &PromptUnlock);
    }
    match try_keyring(ctx) {
        KeyringOutcome::Found(pw) => Ok(pw),
        KeyringOutcome::Recoverable => unlock_master(ctx, &PromptUnlock),
        KeyringOutcome::Fatal(e) => Err(e),
    }
}

/// Unlock without any TTY interaction (for `kprun mcp`, where stdin carries
/// JSON-RPC frames and no terminal is attached). Order: test hook (feature
/// gated) → OS keyring → keyfile-only key. Never prompts.
pub fn unlock_noninteractive(ctx: &UnlockContext) -> Result<VaultKey> {
    #[cfg(feature = "test-hooks")]
    if let Ok(pw) = std::env::var("KPRUN_TEST_MASTER") {
        return build_database_key(ctx, &pw);
    }
    match try_keyring(ctx) {
        KeyringOutcome::Found(pw) => build_database_key(ctx, &pw),
        KeyringOutcome::Recoverable => match &ctx.keyfile {
            Some(path) => {
                let mut file = File::open(path)?;
                DatabaseKey::new()
                    .with_keyfile(&mut file)
                    .map(VaultKey::new)
                    .map_err(|e| KprunError::Other(e.to_string()))
            }
            None => Err(KprunError::NonInteractiveUnlock),
        },
        KeyringOutcome::Fatal(e) => Err(e),
    }
}

pub fn build_database_key(ctx: &UnlockContext, master: &str) -> Result<VaultKey> {
    let mut key = DatabaseKey::new().with_password(master);
    if let Some(path) = &ctx.keyfile {
        let mut file = File::open(path)?;
        key = key
            .with_keyfile(&mut file)
            .map_err(|e| KprunError::Other(e.to_string()))?;
    }
    Ok(VaultKey::new(key))
}

pub fn store_master_in_keystore(db_path: &Path, master: &str) -> Result<()> {
    let entry = Entry::new(SERVICE, &keychain_account(db_path))?;
    entry.set_password(master)?;
    Ok(())
}

pub fn delete_master_from_keystore(db_path: &Path) -> Result<()> {
    let entry = Entry::new(SERVICE, &keychain_account(db_path))?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::v1::Error::NoEntry) => Ok(()),
        Err(e) => Err(KprunError::Keyring(e)),
    }
}

pub fn keystore_has_master(db_path: &Path) -> bool {
    Entry::new(SERVICE, &keychain_account(db_path))
        .and_then(|e| e.get_password())
        .is_ok()
}

pub fn generate_keyfile(path: &Path) -> Result<()> {
    use rand::Rng;
    let mut bytes = [0u8; 64];
    rand::rng().fill_bytes(&mut bytes);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    crate::secure_fs::write_restricted(path, &bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_database_key_with_password() {
        let ctx = UnlockContext {
            keyfile: None,
            db_path: PathBuf::from("test.kdbx"),
        };
        let _key = build_database_key(&ctx, "testpass").unwrap();
    }

    #[cfg(feature = "test-hooks")]
    #[test]
    fn fixed_unlock_returns_password() {
        let src = FixedUnlock("secret".into());
        let ctx = UnlockContext {
            keyfile: None,
            db_path: PathBuf::from("test.kdbx"),
        };
        let pw = unlock_master(&ctx, &src).unwrap();
        assert_eq!(&*pw, "secret");
    }

    #[test]
    fn keychain_account_is_per_vault() {
        let a = keychain_account(Path::new("a.kdbx"));
        let b = keychain_account(Path::new("b.kdbx"));
        assert_ne!(a, b);
        assert!(a.starts_with("master:"));
    }

    #[test]
    fn vault_id_is_16_lowercase_hex_and_stable() {
        let id1 = vault_id(Path::new("a.kdbx"));
        let id2 = vault_id(Path::new("a.kdbx"));
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 16);
        assert!(id1
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_ne!(id1, vault_id(Path::new("b.kdbx")));
    }

    #[test]
    fn vault_id_matches_keychain_account_digest() {
        // Same vault must present the same identity in keyring and audit log.
        let p = Path::new("a.kdbx");
        let account = keychain_account(p);
        assert!(account.starts_with("master:"));
        assert_eq!(account.len(), "master:".len() + 64);
        assert!(account["master:".len()..].starts_with(&vault_id(p)));
    }

    #[cfg(unix)]
    #[test]
    fn generate_keyfile_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("kprun.keyfile");
        generate_keyfile(&kf).unwrap();
        assert_eq!(std::fs::read(&kf).unwrap().len(), 64);
        let mode = std::fs::metadata(&kf).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn noninteractive_unlocks_keyfile_only_vault() {
        // No keyring entry exists for this fresh temp path, so the keyring
        // step fails and the keyfile-only fallback must kick in.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("secrets.kdbx");
        let kf = dir.path().join("kprun.keyfile");
        generate_keyfile(&kf).unwrap();

        let mut file = File::open(&kf).unwrap();
        let key = DatabaseKey::new().with_keyfile(&mut file).unwrap();
        crate::vault::create_vault(&db, VaultKey::new(key), "kprun").unwrap();

        let ctx = UnlockContext {
            keyfile: Some(kf),
            db_path: db.clone(),
        };
        let key = unlock_noninteractive(&ctx).unwrap();
        crate::vault::open_vault(&db, key, crate::vault::OpenMode::ReadOnly).unwrap();
    }

    #[test]
    fn noninteractive_without_keyring_or_keyfile_errors() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = UnlockContext {
            keyfile: None,
            db_path: dir.path().join("no-such.kdbx"),
        };
        let err = unlock_noninteractive(&ctx).unwrap_err();
        assert!(matches!(
            err,
            KprunError::NonInteractiveUnlock | KprunError::Keyring(_)
        ));
    }
}
