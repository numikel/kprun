use std::path::Path;

use assert_cmd::Command;
use kprun_core::unlock::{build_database_key, UnlockContext};
use kprun_core::vault::{create_vault, open_vault, OpenMode};
use predicates::prelude::PredicateBooleanExt;

fn setup_openai_vault(db: &Path) {
    let ctx = UnlockContext {
        keyfile: None,
        db_path: db.to_path_buf(),
    };
    let key = build_database_key(&ctx, "pass").unwrap();
    create_vault(db, key.clone(), "kprun").unwrap();
    let mut vault = open_vault(db, key.clone(), OpenMode::ReadWrite).unwrap();
    vault
        .set_attributes(
            "openai",
            &[("OPENAI_API_KEY".into(), "sk-secret-value".into())],
        )
        .unwrap();
    vault.save(key).unwrap();
}

fn kprun() -> Command {
    Command::cargo_bin("kprun").unwrap()
}

#[test]
fn list_shows_entry_keys_not_values() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_openai_vault(&db);

    let output = kprun()
        .env("KPRUN_DB", db.to_str().unwrap())
        .env("KPRUN_TEST_MASTER", "pass")
        .args(["list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8_lossy(&output);
    assert!(stdout.contains("openai"));
    assert!(stdout.contains("OPENAI_API_KEY"));
    assert!(!stdout.contains("sk-secret"));
    assert!(!stdout.contains("sk-"));
}

#[test]
fn get_reveal_audits_access() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let log = dir.path().join("access.log");
    setup_openai_vault(&db);

    kprun()
        .env("KPRUN_DB", db.to_str().unwrap())
        .env("KPRUN_LOG", log.to_str().unwrap())
        .env("KPRUN_TEST_MASTER", "pass")
        .args(["get", "openai", "--reveal"])
        .assert()
        .success()
        .stderr(predicates::str::contains(
            "WARNING: secret values are displayed in the terminal",
        ));

    let log_content = std::fs::read_to_string(&log).unwrap();
    assert!(log_content.contains("openai"));
    assert!(log_content.contains("OPENAI_API_KEY"));
    assert!(!log_content.contains("sk-secret"));
    assert!(!log_content.contains("sk-"));
}

#[test]
fn get_keys_audits_access() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let log = dir.path().join("access.log");
    setup_openai_vault(&db);

    kprun()
        .env("KPRUN_DB", db.to_str().unwrap())
        .env("KPRUN_LOG", log.to_str().unwrap())
        .env("KPRUN_TEST_MASTER", "pass")
        .args(["get", "openai", "--keys"])
        .assert()
        .success();

    let log_content = std::fs::read_to_string(&log).unwrap();
    assert!(log_content.contains("openai"));
    assert!(log_content.contains("OPENAI_API_KEY"));
}

#[test]
fn set_unset_delete_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let ctx = UnlockContext {
        keyfile: None,
        db_path: db.to_path_buf(),
    };
    let key = build_database_key(&ctx, "pass").unwrap();
    create_vault(&db, key, "kprun").unwrap();

    let env = [
        ("KPRUN_DB", db.to_str().unwrap()),
        ("KPRUN_TEST_MASTER", "pass"),
    ];

    kprun()
        .envs(env)
        .args(["set", "demo", "DEMO_KEY=demo-val", "OTHER=1"])
        .assert()
        .success();

    kprun()
        .envs(env)
        .args(["get", "demo", "--keys"])
        .assert()
        .success()
        .stdout(predicates::str::contains("DEMO_KEY"))
        .stdout(predicates::str::contains("OTHER"));

    kprun()
        .envs(env)
        .args(["unset", "demo", "OTHER"])
        .assert()
        .success();

    kprun()
        .envs(env)
        .args(["get", "demo", "--keys"])
        .assert()
        .success()
        .stdout(predicates::str::contains("DEMO_KEY"))
        .stdout(predicates::str::contains("OTHER").not());

    kprun()
        .envs(env)
        .args(["delete", "demo"])
        .assert()
        .success();

    kprun()
        .envs(env)
        .args(["list"])
        .assert()
        .success()
        .stdout(predicates::str::contains("demo").not());
}
