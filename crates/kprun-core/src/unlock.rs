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
        keystore_get(&keychain_account(self.db_path))
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

/// Full lowercase-hex SHA-256 of the *lexically* absolutized db path. Shared
/// by the keyring account name and `vault_id`.
///
/// `std::path::absolute` never touches the filesystem, so the digest is
/// identical whether or not the vault file currently exists. This is the whole
/// contract behind `reveal-master` and `deinit --delete-vault`: both must
/// resolve the same keychain account *after* the file is gone. An earlier
/// version hashed `fs::canonicalize`, which resolves symlinks and (on Windows)
/// prepends a `\\?\` verbatim prefix only while the file exists — so the
/// account name silently changed the moment the file was deleted or moved.
fn path_digest_hex(db_path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let absolute = std::path::absolute(db_path).unwrap_or_else(|_| db_path.to_path_buf());
    let digest = Sha256::digest(absolute.to_string_lossy().as_bytes());
    hex(&digest)
}

/// Lowercase-hex encode a byte slice. Single source of the encoding used for
/// the keychain account digest and the throwaway probe account name.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").expect("writing to a String cannot fail");
    }
    s
}

/// Stable, non-identifying vault identifier for the audit log: the first 16
/// hex chars of the same digest the OS keyring account name uses.
pub fn vault_id(db_path: &Path) -> String {
    path_digest_hex(db_path)[..16].to_string()
}

/// Open the configured keyfile, citing its path on failure — the bare io
/// error ("file not found") is useless when KPRUN_KEYFILE silently points
/// at the wrong location.
fn open_keyfile(path: &Path) -> Result<File> {
    File::open(path)
        .map_err(|e| KprunError::Other(format!("cannot read keyfile '{}': {e}", path.display())))
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
        // A missing entry or a keyring backend error both mean "fall through to
        // the next source". Under `test-hooks` the file-backed keystore seam
        // reports backend trouble as `Io` (a real keyring returns `Keyring(_)`);
        // treat it identically so the test seam and production agree on the
        // fallback path. In release builds `SystemUnlock` never yields `Io`
        // here, so the extra arm cannot change production behaviour.
        Err(KprunError::UnlockFailed) | Err(KprunError::Keyring(_)) => KeyringOutcome::Recoverable,
        #[cfg(feature = "test-hooks")]
        Err(KprunError::Io(_)) => KeyringOutcome::Recoverable,
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
                let mut file = open_keyfile(path)?;
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
        let mut file = open_keyfile(path)?;
        key = key
            .with_keyfile(&mut file)
            .map_err(|e| KprunError::Other(e.to_string()))?;
    }
    Ok(VaultKey::new(key))
}

/// All keychain access funnels through `keystore_set` / `keystore_get` /
/// `keystore_delete` so the test-hooks file-backed seam covers every caller
/// (store, read, delete, has, probe) in one place.
fn keystore_set(account: &str, value: &str) -> Result<()> {
    #[cfg(feature = "test-hooks")]
    if let Some(dir) = test_keystore::dir_from_env() {
        return test_keystore::set(&dir, account, value);
    }
    let entry = Entry::new(SERVICE, account)?;
    entry.set_password(value)?;
    Ok(())
}

fn keystore_get(account: &str) -> Result<Zeroizing<String>> {
    #[cfg(feature = "test-hooks")]
    if let Some(dir) = test_keystore::dir_from_env() {
        return test_keystore::get(&dir, account);
    }
    let entry = Entry::new(SERVICE, account)?;
    match entry.get_password() {
        Ok(pw) => Ok(Zeroizing::new(pw)),
        Err(keyring::v1::Error::NoEntry) => Err(KprunError::UnlockFailed),
        Err(e) => Err(KprunError::Keyring(e)),
    }
}

fn keystore_delete(account: &str) -> Result<()> {
    #[cfg(feature = "test-hooks")]
    if let Some(dir) = test_keystore::dir_from_env() {
        return test_keystore::delete(&dir, account);
    }
    let entry = Entry::new(SERVICE, account)?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::v1::Error::NoEntry) => Ok(()),
        Err(e) => Err(KprunError::Keyring(e)),
    }
}

pub fn store_master_in_keystore(db_path: &Path, master: &str) -> Result<()> {
    keystore_set(&keychain_account(db_path), master)
}

/// Read the stored master password for `db_path` from the OS keychain.
/// Returns `KprunError::UnlockFailed` when no entry is stored. Does not
/// require the vault file to exist — the keychain is the source of truth, and
/// `path_digest_hex` derives the account name lexically, so it is stable
/// whether or not the file is present.
pub fn read_master_from_keystore(db_path: &Path) -> Result<Zeroizing<String>> {
    SystemUnlock { db_path }.get_master()
}

pub fn delete_master_from_keystore(db_path: &Path) -> Result<()> {
    keystore_delete(&keychain_account(db_path))
}

pub fn keystore_has_master(db_path: &Path) -> bool {
    keystore_get(&keychain_account(db_path)).is_ok()
}

/// Round-trip set → get → delete on a throwaway `probe:<random>` account to
/// verify the OS keychain works before creating a vault whose password only
/// the keychain will know. The vault's own `master:<digest>` entry is never
/// touched, so a stale entry is never disturbed.
pub fn probe_keystore() -> Result<()> {
    use rand::Rng;
    let mut suffix = [0u8; 8];
    rand::rng().fill_bytes(&mut suffix);
    let account = format!("probe:{}", hex(&suffix));
    keystore_set(&account, "kprun-probe")?;
    // Best-effort cleanup regardless of how the read went: a failed get/delete
    // must not `?`-propagate before the entry is removed, or every failed probe
    // orphans a `probe:<hex>` entry in the real keychain. The value is
    // non-secret, but the litter is still avoidable.
    let read_back = keystore_get(&account);
    let _ = keystore_delete(&account);
    let read_back = read_back?;
    if read_back.as_str() != "kprun-probe" {
        return Err(KprunError::Other(
            "keychain probe read back a different value".into(),
        ));
    }
    Ok(())
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

/// 128-bit random master password for `init --quick`, formatted as 8
/// dash-separated groups of 4 lowercase hex chars (39 chars) — readable
/// enough to retype into KeePassXC.
pub fn generate_master_password() -> Zeroizing<String> {
    use std::fmt::Write;

    use rand::Rng;
    let mut bytes = Zeroizing::new([0u8; 16]);
    rand::rng().fill_bytes(&mut *bytes);
    let mut out = Zeroizing::new(String::with_capacity(39));
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && i % 2 == 0 {
            out.push('-');
        }
        write!(out, "{b:02x}").expect("writing to a String cannot fail");
    }
    out
}

/// File-backed keystore for integration tests: one file per keychain
/// account inside `KPRUN_TEST_KEYSTORE`. Compiled only with `test-hooks`,
/// so release binaries contain no trace of this path.
#[cfg(feature = "test-hooks")]
mod test_keystore {
    use std::path::{Path, PathBuf};

    use zeroize::Zeroizing;

    use crate::{KprunError, Result};

    pub fn dir_from_env() -> Option<PathBuf> {
        std::env::var_os("KPRUN_TEST_KEYSTORE").map(PathBuf::from)
    }

    /// ':' is reserved in Windows filenames; substitute it.
    fn file(dir: &Path, account: &str) -> PathBuf {
        dir.join(account.replace(':', "_"))
    }

    pub fn set(dir: &Path, account: &str, value: &str) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        crate::secure_fs::write_restricted(&file(dir, account), value.as_bytes())
    }

    pub fn get(dir: &Path, account: &str) -> Result<Zeroizing<String>> {
        match std::fs::read_to_string(file(dir, account)) {
            Ok(v) => Ok(Zeroizing::new(v)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(KprunError::UnlockFailed),
            Err(e) => Err(KprunError::Io(e)),
        }
    }

    pub fn delete(dir: &Path, account: &str) -> Result<()> {
        match std::fs::remove_file(file(dir, account)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(KprunError::Io(e)),
        }
    }
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

    #[test]
    fn keychain_account_is_stable_across_file_existence() {
        // The whole point of the lexical digest: `reveal-master` and `deinit`
        // must resolve the same account before the file is created, while it
        // exists, and after it is deleted. The old `fs::canonicalize` digest
        // changed the moment the file appeared/vanished (Windows \\?\, macOS
        // /tmp), silently orphaning the stored password.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("secrets.kdbx");

        let before = keychain_account(&p);
        std::fs::write(&p, b"x").unwrap();
        let while_exists = keychain_account(&p);
        std::fs::remove_file(&p).unwrap();
        let after = keychain_account(&p);

        assert_eq!(before, while_exists);
        assert_eq!(while_exists, after);
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

    #[cfg(feature = "test-hooks")]
    #[test]
    fn test_keystore_set_get_delete_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        assert!(matches!(
            test_keystore::get(d, "master:0123abcd"),
            Err(KprunError::UnlockFailed)
        ));
        test_keystore::set(d, "master:0123abcd", "s3cret").unwrap();
        assert_eq!(
            test_keystore::get(d, "master:0123abcd").unwrap().as_str(),
            "s3cret"
        );
        test_keystore::delete(d, "master:0123abcd").unwrap();
        // Deleting a missing entry is tolerated, mirroring keyring NoEntry.
        test_keystore::delete(d, "master:0123abcd").unwrap();
        assert!(test_keystore::get(d, "master:0123abcd").is_err());
    }

    #[test]
    fn read_master_from_keystore_missing_entry_errors() {
        // Fresh temp path has no keyring entry; headless CI may instead
        // report a backend error — both are acceptable failures.
        let dir = tempfile::tempdir().unwrap();
        let err = read_master_from_keystore(&dir.path().join("no-such.kdbx")).unwrap_err();
        assert!(matches!(
            err,
            KprunError::UnlockFailed | KprunError::Keyring(_)
        ));
    }

    #[test]
    fn generated_master_password_has_expected_format() {
        let pw = generate_master_password();
        assert_eq!(pw.len(), 39);
        let groups: Vec<&str> = pw.split('-').collect();
        assert_eq!(groups.len(), 8);
        for g in groups {
            assert_eq!(g.len(), 4);
            assert!(g
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }
    }

    #[test]
    fn generated_master_passwords_are_unique() {
        assert_ne!(*generate_master_password(), *generate_master_password());
    }
}
