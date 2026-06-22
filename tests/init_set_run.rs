use std::path::Path;

use assert_cmd::Command;
use kprun_core::unlock::{build_database_key, UnlockContext};
use kprun_core::vault::{create_vault, open_vault, OpenMode};

fn setup_demo_vault(db: &Path) {
    let ctx = UnlockContext { keyfile: None };
    let key = build_database_key(&ctx, "pass").unwrap();
    create_vault(db, key.clone(), "kprun").unwrap();
    let mut vault = open_vault(db, key.clone(), OpenMode::ReadWrite).unwrap();
    vault
        .set_attributes("demo", &[("DEMO_KEY".into(), "secret".into())])
        .unwrap();
    vault.save(key).unwrap();
}

#[test]
fn run_injects_env_var() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_demo_vault(&db);

    let child_args: Vec<&str> = if cfg!(windows) {
        vec!["cmd", "/C", "echo", "%DEMO_KEY%"]
    } else {
        vec!["sh", "-c", "echo $DEMO_KEY"]
    };

    let expected_stdout = if cfg!(windows) {
        "secret\r\n"
    } else {
        "secret\n"
    };

    Command::cargo_bin("kprun")
        .unwrap()
        .env("KPRUN_DB", db.to_str().unwrap())
        .env("KPRUN_TEST_MASTER", "pass")
        .args(["run", "demo", "--"])
        .args(child_args)
        .assert()
        .success()
        .stdout(expected_stdout);
}
