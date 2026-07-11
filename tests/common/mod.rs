//! Shared helpers for kprun integration tests.
#![allow(dead_code)]

pub mod mcp_mock;

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use kprun_core::test_support;
use kprun_core::unlock::{build_database_key, UnlockContext};
use kprun_core::vault::{create_vault, open_vault, OpenMode};

/// Path to the optional KeePassXC-created fixture (`tests/fixtures/keepassxc.kdbx`).
pub fn keepassxc_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/keepassxc.kdbx")
}

/// Whether the KeePassXC compatibility test should run (`KPRUN_KEEPASSXC_FIXTURE` set).
pub fn keepassxc_fixture_enabled() -> bool {
    std::env::var_os("KPRUN_KEEPASSXC_FIXTURE").is_some()
}

/// Master password for the KeePassXC fixture (`KPRUN_TEST_MASTER` or `KPRUN_KEEPASSXC_PASSWORD`).
pub fn keepassxc_fixture_password() -> Option<String> {
    std::env::var("KPRUN_TEST_MASTER")
        .ok()
        .or_else(|| std::env::var("KPRUN_KEEPASSXC_PASSWORD").ok())
}

/// Returns a configured `kprun` binary for integration tests.
pub fn kprun_cmd() -> Command {
    Command::cargo_bin("kprun").unwrap()
}

/// Standard test env vars: vault path + master password hook.
pub fn test_env(db: &Path) -> [(&str, &str); 2] {
    [
        ("KPRUN_DB", db.to_str().unwrap()),
        ("KPRUN_TEST_MASTER", test_support::vault_password()),
    ]
}

/// Create a vault with one or more entries (title + custom field pairs).
pub fn create_vault_with_entries(db: &Path, entries: &[(&str, &[(&str, &str)])]) {
    create_vault_inner(db, None, entries);
}

/// Like `create_vault_with_entries`, but the vault key composes the master
/// password with a keyfile generated at `keyfile`.
pub fn create_vault_with_keyfile_entries(
    db: &Path,
    keyfile: &Path,
    entries: &[(&str, &[(&str, &str)])],
) {
    kprun_core::unlock::generate_keyfile(keyfile).unwrap();
    create_vault_inner(db, Some(keyfile), entries);
}

fn create_vault_inner(db: &Path, keyfile: Option<&Path>, entries: &[(&str, &[(&str, &str)])]) {
    let ctx = UnlockContext {
        keyfile: keyfile.map(Path::to_path_buf),
        db_path: db.to_path_buf(),
    };
    let key = build_database_key(&ctx, test_support::vault_password()).unwrap();
    create_vault(db, key.clone(), "kprun").unwrap();
    let mut vault = open_vault(db, key.clone(), OpenMode::ReadWrite).unwrap();
    for (title, pairs) in entries {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        vault.set_attributes(title, &owned).unwrap();
    }
    vault.save(key).unwrap();
}

/// Env for `--quick` / `reveal-master` tests: vault path + file-backed
/// keystore dir (`KPRUN_TEST_KEYSTORE` seam). Deliberately does NOT set
/// `KPRUN_TEST_MASTER`, which would bypass the keystore paths under test.
pub fn quick_env(db: &Path, keystore: &Path) -> [(&'static str, String); 2] {
    [
        ("KPRUN_DB", db.to_str().unwrap().to_string()),
        (
            "KPRUN_TEST_KEYSTORE",
            keystore.to_str().unwrap().to_string(),
        ),
    ]
}
