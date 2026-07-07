mod common;

use std::path::Path;

use kprun_core::test_support;
use kprun_core::unlock::{build_database_key, UnlockContext};
use kprun_core::vault::create_vault;
use predicates::prelude::PredicateBooleanExt;

use common::{create_vault_with_entries, kprun_cmd, test_env};

fn setup_openai_vault(db: &Path) {
    create_vault_with_entries(db, &[("openai", &[("OPENAI_API_KEY", "sk-secret-value")])]);
}

#[test]
fn list_shows_entry_keys_not_values() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_openai_vault(&db);

    let output = kprun_cmd()
        .envs(test_env(&db))
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

    kprun_cmd()
        .envs(test_env(&db))
        .env("KPRUN_LOG", log.to_str().unwrap())
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

    kprun_cmd()
        .envs(test_env(&db))
        .env("KPRUN_LOG", log.to_str().unwrap())
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
    let key = build_database_key(&ctx, test_support::vault_password()).unwrap();
    create_vault(&db, key, "kprun").unwrap();

    let env = test_env(&db);

    kprun_cmd()
        .envs(env)
        .args(["set", "demo", "DEMO_KEY=demo-val", "OTHER=1"])
        .assert()
        .success();

    kprun_cmd()
        .envs(env)
        .args(["get", "demo", "--keys"])
        .assert()
        .success()
        .stdout(predicates::str::contains("DEMO_KEY"))
        .stdout(predicates::str::contains("OTHER"));

    kprun_cmd()
        .envs(env)
        .args(["unset", "demo", "OTHER"])
        .assert()
        .success();

    kprun_cmd()
        .envs(env)
        .args(["get", "demo", "--keys"])
        .assert()
        .success()
        .stdout(predicates::str::contains("DEMO_KEY"))
        .stdout(predicates::str::contains("OTHER").not());

    kprun_cmd()
        .envs(env)
        .args(["delete", "demo"])
        .assert()
        .success();

    kprun_cmd()
        .envs(env)
        .args(["list"])
        .assert()
        .success()
        .stdout(predicates::str::contains("demo").not());
}
