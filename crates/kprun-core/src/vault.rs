use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};

use keepass::db::{fields, EntryId, EntryRef};
use keepass::{Database, DatabaseKey};

use crate::{KprunError, Result};

/// Owned wrapper around the third-party key material so `keepass::DatabaseKey`
/// never appears in `kprun-core`'s public API. Built via
/// `unlock::build_database_key` / `unlock::unlock_noninteractive`.
#[derive(Clone)]
pub struct VaultKey(DatabaseKey);

impl VaultKey {
    pub(crate) fn new(inner: DatabaseKey) -> Self {
        Self(inner)
    }

    pub(crate) fn into_inner(self) -> DatabaseKey {
        self.0
    }
}

// `keepass::DatabaseKey` derives `Debug` and prints its `password` field in
// plaintext, so a derived `Debug` here would defeat the point of wrapping it.
impl std::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("VaultKey").field(&"<redacted>").finish()
    }
}

/// Opaque handle to an entry inside a `Vault`. Cannot be constructed or
/// inspected from outside `kprun-core`; obtained only via
/// `Vault::find_entry_by_title` and fed back into `entry_custom_keys` /
/// `entry_custom_values`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryHandle(EntryId);

const STANDARD_FIELDS: &[&str] = &[
    "Title",
    "UserName",
    "Password",
    "URL",
    "Notes",
    "Expires",
    "Created",
    "LastAccess",
    "LastModification",
    "Tags",
];

// KDF for newly created vaults (KDBX4 stores these in the file header,
// so existing vaults keep their own parameters).
// Argon2id per RFC 9106; memory is in BYTES (the keepass-rs doc comment
// saying KiB is wrong — mem_cost = memory / 1024 internally).
const KDF_MEMORY_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB
const KDF_ITERATIONS: u64 = 3;
const KDF_PARALLELISM: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone)]
pub struct EntrySummary {
    pub title: String,
    pub keys: Vec<String>,
}

pub struct Vault {
    db: Database,
    path: PathBuf,
    mode: OpenMode,
}

impl Vault {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub fn open_vault(path: &Path, key: VaultKey, mode: OpenMode) -> Result<Vault> {
    if !path.exists() {
        return Err(KprunError::DatabaseNotFound(path.to_path_buf()));
    }
    let mut file = File::open(path)?;
    let db = Database::open(&mut file, key.into_inner())
        .map_err(|e| KprunError::VaultOpen(e.to_string()))?;
    Ok(Vault {
        db,
        path: path.to_path_buf(),
        mode,
    })
}

/// Build an empty KeePass database with kprun's KDF settings. Shared by
/// `create_vault` and `create_vault_atomic` so the two never drift.
fn new_database(db_name: &str) -> Database {
    let mut db = Database::new();
    db.config.kdf_config = keepass::config::KdfConfig::Argon2id {
        iterations: KDF_ITERATIONS,
        memory: KDF_MEMORY_BYTES,
        parallelism: KDF_PARALLELISM,
        version: argon2::Version::Version13,
    };
    db.meta.database_name = Some(db_name.to_string());
    db
}

pub fn create_vault(path: &Path, key: VaultKey, db_name: &str) -> Result<()> {
    if path.exists() {
        return Err(KprunError::Other(format!(
            "database already exists: {}",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let db = new_database(db_name);
    let mut file = crate::secure_fs::create_restricted(path)?;
    db.save(&mut file, key.into_inner()).map_err(map_save_error)
}

/// Create a fresh vault at `dst`, atomically replacing any existing file there.
///
/// The new database is written to a sibling temp file first; `before_commit`
/// then runs *while any pre-existing vault at `dst` is still intact*, and only
/// if it succeeds is the temp file atomically renamed over `dst`. This ordering
/// is what makes `init --quick --force` safe: the generated master password
/// lives only in memory and (once `before_commit` stores it) the OS keychain,
/// so committing the file before the keychain write succeeds could strand the
/// user with an unopenable vault and no old one to fall back to. Any failure —
/// writing the temp file, `before_commit`, or the rename — leaves the previous
/// vault file untouched, so the user is never left with no usable vault.
pub fn create_vault_atomic<F>(
    dst: &Path,
    key: VaultKey,
    db_name: &str,
    before_commit: F,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let dir = dst
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    let db = new_database(db_name);
    db.save(tmp.as_file_mut(), key.into_inner())
        .map_err(map_save_error)?;
    // Old vault still in place here; on error `tmp` is dropped and deleted.
    before_commit()?;
    crate::secure_fs::persist_restricted(tmp, dst)
}

impl Vault {
    fn require_rw(&self) -> Result<()> {
        if self.mode != OpenMode::ReadWrite {
            return Err(KprunError::Other("vault opened read-only".into()));
        }
        Ok(())
    }

    pub fn find_entry_by_title(&self, title: &str) -> Result<EntryHandle> {
        let title_lower = title.to_ascii_lowercase();
        let mut found: Option<EntryId> = None;
        for entry in self.db.iter_all_entries() {
            let matches = entry
                .get_title()
                .map(|t| t.to_ascii_lowercase() == title_lower)
                .unwrap_or(false);
            if matches {
                if found.is_some() {
                    return Err(KprunError::DuplicateEntry(title.to_string()));
                }
                found = Some(entry.id());
            }
        }
        found
            .map(EntryHandle)
            .ok_or_else(|| KprunError::EntryNotFound(title.to_string()))
    }

    pub fn list_entries(&self) -> Vec<EntrySummary> {
        self.db
            .iter_all_entries()
            .filter_map(|e| {
                let title = e.get_title()?.to_string();
                let keys = custom_field_names(&e);
                Some(EntrySummary { title, keys })
            })
            .collect()
    }

    pub fn entry_custom_keys(&self, id: EntryHandle) -> Vec<String> {
        self.db
            .entry(id.0)
            .map(|e| custom_field_names(&e))
            .unwrap_or_default()
    }

    pub fn entry_custom_values(&self, id: EntryHandle) -> HashMap<String, String> {
        self.db
            .entry(id.0)
            .map(|e| custom_fields(&e))
            .unwrap_or_default()
    }

    pub fn set_attributes(&mut self, title: &str, pairs: &[(String, String)]) -> Result<()> {
        self.require_rw()?;
        let title_owned = title.to_string();
        let result = self.find_entry_by_title(&title_owned);
        match result {
            Ok(id) => {
                if let Some(mut entry) = self.db.entry_mut(id.0) {
                    for (k, v) in pairs {
                        entry.set_protected(k.clone(), v.clone());
                    }
                }
                Ok(())
            }
            Err(KprunError::EntryNotFound(_)) => {
                self.db.root_mut().add_entry().edit(|e| {
                    e.set_unprotected(fields::TITLE, title_owned);
                    for (k, v) in pairs {
                        e.set_protected(k.clone(), v.clone());
                    }
                });
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn unset_attributes(&mut self, title: &str, keys: &[String]) -> Result<()> {
        self.require_rw()?;
        let id = self.find_entry_by_title(title)?;
        if let Some(mut entry) = self.db.entry_mut(id.0) {
            for k in keys {
                entry.fields.remove(k);
            }
        }
        Ok(())
    }

    pub fn delete_entry(&mut self, title: &str) -> Result<()> {
        self.require_rw()?;
        let id = self.find_entry_by_title(title)?;
        if let Some(entry) = self.db.entry_mut(id.0) {
            entry.remove();
            Ok(())
        } else {
            Err(KprunError::EntryNotFound(title.to_string()))
        }
    }

    pub fn save(&mut self, key: VaultKey) -> Result<()> {
        self.require_rw()?;
        prepare_for_save(&mut self.db);
        let mut tmp =
            tempfile::NamedTempFile::new_in(self.path.parent().unwrap_or_else(|| Path::new(".")))?;
        self.db
            .save(tmp.as_file_mut(), key.into_inner())
            .map_err(map_save_error)?;
        crate::secure_fs::persist_restricted(tmp, &self.path)?;
        Ok(())
    }

    #[cfg(test)]
    fn simulate_legacy_kdbx4_open(&mut self) {
        use keepass::config::DatabaseVersion;
        self.db.config.version = DatabaseVersion::KDB4(0);
    }
}

fn is_standard_field(name: &str) -> bool {
    STANDARD_FIELDS.iter().any(|f| f.eq_ignore_ascii_case(name))
}

fn custom_field_names(entry: &EntryRef<'_>) -> Vec<String> {
    let mut keys: Vec<String> = entry
        .fields
        .keys()
        .filter(|k| !is_standard_field(k))
        .cloned()
        .collect();
    keys.sort_unstable();
    keys
}

fn custom_fields(entry: &EntryRef<'_>) -> HashMap<String, String> {
    entry
        .fields
        .keys()
        .filter(|k| !is_standard_field(k))
        .filter_map(|k| entry.get(k).map(|val| (k.clone(), val.to_string())))
        .collect()
}

fn map_save_error(e: keepass::db::DatabaseSaveError) -> KprunError {
    use keepass::db::DatabaseSaveError;

    match e {
        DatabaseSaveError::UnsupportedVersion => KprunError::Other(
            "vault format is read-only (legacy KDBX3/KDBX4.0); upgrade with KeePassXC or re-init"
                .into(),
        ),
        DatabaseSaveError::Io(io_err) if io_err.to_string().to_lowercase().contains("lock") => {
            KprunError::DatabaseLocked
        }
        other => KprunError::Other(other.to_string()),
    }
}

/// KDBX minor version required by keepass-rs when saving (see keepass `dump_kdbx4`).
const KDBX4_SAVE_MINOR_VERSION: u16 = 1;

/// Normalize legacy vault headers so keepass-rs can persist changes (KDBX4.1 only).
fn prepare_for_save(db: &mut Database) {
    use keepass::config::{DatabaseConfig, DatabaseVersion};

    match db.config.version {
        DatabaseVersion::KDB4(KDBX4_SAVE_MINOR_VERSION) => {}
        DatabaseVersion::KDB4(_) => {
            db.config.version = DatabaseVersion::KDB4(KDBX4_SAVE_MINOR_VERSION);
        }
        DatabaseVersion::KDB3(_) => {
            db.config = DatabaseConfig::default();
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{create_test_vault, test_vault_password};
    use crate::unlock::{build_database_key, UnlockContext};
    use crate::KprunError;
    use keepass::db::fields;
    use tempfile::tempdir;

    #[test]
    fn find_entry_by_title_case_insensitive() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.kdbx");
        create_test_vault(&db_path, test_vault_password()).unwrap();
        let ctx = UnlockContext {
            keyfile: None,
            db_path: PathBuf::from("test.kdbx"),
        };
        let key = build_database_key(&ctx, test_vault_password()).unwrap();
        let vault = open_vault(&db_path, key, OpenMode::ReadOnly).unwrap();
        let id = vault.find_entry_by_title("GitHub").unwrap();
        let keys = vault.entry_custom_keys(id);
        assert_eq!(keys, vec!["GITHUB_TOKEN".to_string()]);
    }

    fn password_key(pw: &str) -> VaultKey {
        let ctx = UnlockContext {
            keyfile: None,
            db_path: PathBuf::from("unused.kdbx"),
        };
        build_database_key(&ctx, pw).unwrap()
    }

    #[test]
    fn create_vault_atomic_creates_when_absent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v.kdbx");
        let key = password_key("pw-new");

        create_vault_atomic(&path, key.clone(), "kprun", || Ok(())).unwrap();

        open_vault(&path, key, OpenMode::ReadOnly).unwrap();
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no temp file may leak"
        );
    }

    #[test]
    fn create_vault_atomic_overwrites_existing_vault() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v.kdbx");
        let old = password_key("pw-old");
        create_vault(&path, old.clone(), "kprun").unwrap();

        let new = password_key("pw-new");
        create_vault_atomic(&path, new.clone(), "kprun", || Ok(())).unwrap();

        open_vault(&path, new, OpenMode::ReadOnly).unwrap();
        assert!(
            open_vault(&path, old, OpenMode::ReadOnly).is_err(),
            "old key must no longer open the replaced vault"
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn create_vault_atomic_preserves_existing_vault_when_before_commit_fails() {
        // The finding-4 guarantee: if `before_commit` (e.g. the keychain store)
        // fails, the pre-existing vault must be left completely untouched — the
        // user is never stranded with no usable vault.
        let dir = tempdir().unwrap();
        let path = dir.path().join("v.kdbx");
        let old = password_key("pw-old");
        create_vault(&path, old.clone(), "kprun").unwrap();
        let before = std::fs::read(&path).unwrap();

        let new = password_key("pw-new");
        let err = create_vault_atomic(&path, new.clone(), "kprun", || {
            Err(KprunError::Other("keychain store failed".into()))
        })
        .unwrap_err();
        assert!(matches!(err, KprunError::Other(_)));

        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "existing vault must be byte-identical after a failed commit"
        );
        open_vault(&path, old, OpenMode::ReadOnly).unwrap();
        assert!(
            open_vault(&path, new, OpenMode::ReadOnly).is_err(),
            "the uncommitted replacement must not be openable"
        );
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "the temp file must be cleaned up on failure"
        );
    }

    #[test]
    fn set_attributes_persists_after_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("w.kdbx");
        let ctx = UnlockContext {
            keyfile: None,
            db_path: PathBuf::from("test.kdbx"),
        };
        let key = build_database_key(&ctx, test_vault_password()).unwrap();
        create_vault(&path, key.clone(), "kprun").unwrap();

        let mut vault = open_vault(&path, key.clone(), OpenMode::ReadWrite).unwrap();
        vault
            .set_attributes("openai", &[("OPENAI_API_KEY".into(), "sk-test".into())])
            .unwrap();
        vault.save(key.clone()).unwrap();

        let vault2 = open_vault(&path, key, OpenMode::ReadOnly).unwrap();
        let id = vault2.find_entry_by_title("openai").unwrap();
        let vals = vault2.entry_custom_values(id);
        assert_eq!(
            vals.get("OPENAI_API_KEY").map(String::as_str),
            Some("sk-test")
        );
    }

    #[test]
    fn set_attributes_stores_protected_values() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("prot.kdbx");
        let ctx = UnlockContext {
            keyfile: None,
            db_path: PathBuf::from("test.kdbx"),
        };
        let key = build_database_key(&ctx, test_vault_password()).unwrap();
        create_vault(&path, key.clone(), "kprun").unwrap();

        let mut vault = open_vault(&path, key.clone(), OpenMode::ReadWrite).unwrap();
        vault
            .set_attributes("svc", &[("SECRET".into(), "sk-protected".into())])
            .unwrap();
        vault.save(key.clone()).unwrap();

        // Reopen and confirm the value round-trips via the unprotecting getter.
        let vault2 = open_vault(&path, key, OpenMode::ReadOnly).unwrap();
        let id = vault2.find_entry_by_title("svc").unwrap();
        let vals = vault2.entry_custom_values(id);
        assert_eq!(vals.get("SECRET").map(String::as_str), Some("sk-protected"));
    }

    #[test]
    fn read_only_vault_rejects_write_operations() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ro.kdbx");
        let ctx = UnlockContext {
            keyfile: None,
            db_path: PathBuf::from("test.kdbx"),
        };
        let key = build_database_key(&ctx, test_vault_password()).unwrap();
        create_vault(&path, key.clone(), "kprun").unwrap();

        let mut vault = open_vault(&path, key.clone(), OpenMode::ReadOnly).unwrap();
        let err = vault
            .unset_attributes("missing", &["KEY".into()])
            .unwrap_err();
        assert!(matches!(err, KprunError::Other(msg) if msg == "vault opened read-only"));

        let err = vault.save(key).unwrap_err();
        assert!(matches!(err, KprunError::Other(msg) if msg == "vault opened read-only"));
    }

    #[test]
    fn custom_field_names_are_sorted_alphabetically() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sort.kdbx");
        let ctx = UnlockContext {
            keyfile: None,
            db_path: PathBuf::from("test.kdbx"),
        };
        let key = build_database_key(&ctx, test_vault_password()).unwrap();
        create_vault(&path, key.clone(), "kprun").unwrap();

        let mut vault = open_vault(&path, key.clone(), OpenMode::ReadWrite).unwrap();
        vault
            .set_attributes(
                "svc",
                &[
                    ("ZZZ".into(), "z".into()),
                    ("AAA".into(), "a".into()),
                    ("MMM".into(), "m".into()),
                ],
            )
            .unwrap();
        vault.save(key.clone()).unwrap();

        let vault2 = open_vault(&path, key, OpenMode::ReadOnly).unwrap();
        let id = vault2.find_entry_by_title("svc").unwrap();
        let keys = vault2.entry_custom_keys(id);
        assert_eq!(
            keys,
            vec!["AAA".to_string(), "MMM".to_string(), "ZZZ".to_string()]
        );
    }

    #[test]
    fn save_persists_without_second_unlock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.kdbx");
        let ctx = UnlockContext {
            keyfile: None,
            db_path: PathBuf::from("test.kdbx"),
        };
        let key = build_database_key(&ctx, test_vault_password()).unwrap();
        create_vault(&path, key.clone(), "kprun").unwrap();

        let mut vault = open_vault(&path, key.clone(), OpenMode::ReadWrite).unwrap();
        vault
            .set_attributes("svc", &[("TOKEN".into(), "t1".into())])
            .unwrap();
        vault.save(key.clone()).unwrap();

        let vault2 = open_vault(&path, key, OpenMode::ReadOnly).unwrap();
        let id = vault2.find_entry_by_title("svc").unwrap();
        let vals = vault2.entry_custom_values(id);
        assert_eq!(vals.get("TOKEN").map(String::as_str), Some("t1"));
    }

    #[test]
    fn legacy_kdbx4_minor_zero_persists_after_save() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("legacy.kdbx");
        let ctx = UnlockContext {
            keyfile: None,
            db_path: PathBuf::from("test.kdbx"),
        };
        let key = build_database_key(&ctx, test_vault_password()).unwrap();
        create_vault(&path, key.clone(), "kprun").unwrap();

        let mut vault = open_vault(&path, key.clone(), OpenMode::ReadWrite).unwrap();
        vault.simulate_legacy_kdbx4_open();

        vault
            .set_attributes("svc", &[("TOKEN".into(), "legacy".into())])
            .unwrap();
        vault.save(key.clone()).unwrap();

        let vault2 = open_vault(&path, key, OpenMode::ReadOnly).unwrap();
        let id = vault2.find_entry_by_title("svc").unwrap();
        let vals = vault2.entry_custom_values(id);
        assert_eq!(vals.get("TOKEN").map(String::as_str), Some("legacy"));
    }

    #[test]
    fn find_entry_by_title_rejects_duplicates() {
        use keepass::Database;
        let dir = tempdir().unwrap();
        let path = dir.path().join("dup.kdbx");
        let mut db = Database::new();
        db.root_mut().add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "dup");
        });
        db.root_mut().add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "DUP");
        });
        let ctx = UnlockContext {
            keyfile: None,
            db_path: PathBuf::from("test.kdbx"),
        };
        let key = build_database_key(&ctx, test_vault_password()).unwrap();
        let mut file = std::fs::File::create(&path).unwrap();
        db.save(&mut file, key.clone().into_inner()).unwrap();

        let vault = open_vault(&path, key, OpenMode::ReadOnly).unwrap();
        let err = vault.find_entry_by_title("dup").unwrap_err();
        assert!(matches!(err, KprunError::DuplicateEntry(_)));
    }

    #[cfg(unix)]
    #[test]
    fn create_vault_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("perm.kdbx");
        let ctx = UnlockContext {
            keyfile: None,
            db_path: PathBuf::from("test.kdbx"),
        };
        let key = build_database_key(&ctx, test_vault_password()).unwrap();
        create_vault(&path, key, "kprun").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn create_vault_uses_hardened_kdf() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("kdf.kdbx");
        let ctx = UnlockContext {
            keyfile: None,
            db_path: PathBuf::from("test.kdbx"),
        };
        let key = build_database_key(&ctx, test_vault_password()).unwrap();
        create_vault(&path, key.clone(), "kprun").unwrap();
        // Reopen from disk: proves the parameters landed in the KDBX4 file
        // header, not just the in-memory struct.
        let vault = open_vault(&path, key, OpenMode::ReadOnly).unwrap();
        assert_eq!(
            vault.db.config.kdf_config,
            keepass::config::KdfConfig::Argon2id {
                iterations: 3,
                memory: 64 * 1024 * 1024,
                parallelism: 4,
                version: argon2::Version::Version13,
            }
        );
    }

    #[test]
    fn map_save_error_unsupported_version_suggests_upgrade() {
        use keepass::db::DatabaseSaveError;

        let err = map_save_error(DatabaseSaveError::UnsupportedVersion);
        match err {
            KprunError::Other(msg) => {
                assert!(msg.contains("upgrade with KeePassXC or re-init"), "{msg}");
            }
            other => panic!("expected KprunError::Other, got {other:?}"),
        }
    }

    #[test]
    fn map_save_error_io_lock_message_maps_to_database_locked() {
        use keepass::db::DatabaseSaveError;

        // Pins the exact wording this heuristic depends on: if a future
        // std/keepass io-wrapping change stops producing "lock" in the
        // message, this test fails loudly instead of silently falling
        // through to `KprunError::Other`.
        let io_err = std::io::Error::other(
            "The process cannot access the file because it is locked by another process.",
        );
        let err = map_save_error(DatabaseSaveError::Io(io_err));
        assert!(matches!(err, KprunError::DatabaseLocked));
    }

    #[test]
    fn map_save_error_io_without_lock_wording_falls_through_to_other() {
        use keepass::db::DatabaseSaveError;

        let io_err = std::io::Error::other("disk full");
        let err = map_save_error(DatabaseSaveError::Io(io_err));
        assert!(matches!(err, KprunError::Other(_)));
    }
}
