use std::path::Path;

use assert_cmd::Command;
use kprun_core::unlock::{build_database_key, UnlockContext};
use kprun_core::vault::{create_vault, open_vault, OpenMode};

fn setup_demo_vault(db: &Path) {
    let ctx = UnlockContext {
        keyfile: None,
        db_path: db.to_path_buf(),
    };
    let key = build_database_key(&ctx, "pass").unwrap();
    create_vault(db, key.clone(), "kprun").unwrap();
    let mut vault = open_vault(db, key.clone(), OpenMode::ReadWrite).unwrap();
    vault
        .set_attributes("demo", &[("DEMO_KEY".into(), "secret".into())])
        .unwrap();
    vault.save(key).unwrap();
}

#[test]
fn run_writes_nothing_to_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_demo_vault(&db);

    let expected_stdout = if cfg!(windows) {
        "child\r\n"
    } else {
        "child\n"
    };

    let mut cmd = Command::cargo_bin("kprun").unwrap();
    cmd.env("KPRUN_DB", db.to_str().unwrap())
        .env("KPRUN_TEST_MASTER", "pass")
        .args(["run", "demo", "--"]);

    if cfg!(windows) {
        cmd.args(["cmd", "/C", "echo", "child"]);
    } else {
        cmd.args(["echo", "child"]);
    }

    cmd.assert().success().stdout(expected_stdout);
}
