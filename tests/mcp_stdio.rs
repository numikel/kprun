mod common;

use std::path::Path;

use common::{create_vault_with_entries, kprun_cmd, test_env};

fn setup_demo_vault(db: &Path) {
    create_vault_with_entries(db, &[("demo", &[("DEMO_KEY", "secret")])]);
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

    let mut cmd = kprun_cmd();
    cmd.envs(test_env(&db)).args(["run", "demo", "--"]);

    if cfg!(windows) {
        cmd.args(["cmd", "/C", "echo", "child"]);
    } else {
        cmd.args(["echo", "child"]);
    }

    cmd.assert().success().stdout(expected_stdout);
}
