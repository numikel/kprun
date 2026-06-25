mod common;

use std::path::Path;

use common::{create_vault_with_entries, kprun_cmd, test_env};

fn setup_demo_vault(db: &Path) {
    create_vault_with_entries(db, &[("demo", &[("DEMO_KEY", "secret")])]);
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

    kprun_cmd()
        .envs(test_env(&db))
        .args(["run", "demo", "--"])
        .args(child_args)
        .assert()
        .success()
        .stdout(expected_stdout);
}
