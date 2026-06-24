use std::path::Path;

use assert_cmd::Command;
use kprun_core::unlock::{build_database_key, UnlockContext};
use kprun_core::vault::{create_vault, open_vault, OpenMode};
use serde_json::Value;

fn setup_vault(db: &Path) {
    let ctx = UnlockContext {
        keyfile: None,
        db_path: db.to_path_buf(),
    };
    let key = build_database_key(&ctx, "pass").unwrap();
    create_vault(db, key.clone(), "kprun").unwrap();
    let mut vault = open_vault(db, key.clone(), OpenMode::ReadWrite).unwrap();
    vault
        .set_attributes("github", &[("GITHUB_TOKEN".into(), "ghp_secret".into())])
        .unwrap();
    vault.save(key).unwrap();
}

fn kprun() -> Command {
    Command::cargo_bin("kprun").unwrap()
}

#[test]
fn doctor_reports_vault_unlock_and_binary() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_vault(&db);

    let output = kprun()
        .env("KPRUN_DB", db.to_str().unwrap())
        .env("KPRUN_TEST_MASTER", "pass")
        .args(["doctor"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8_lossy(&output);
    assert!(stdout.contains("vault:"));
    assert!(stdout.contains("ok"));
    assert!(stdout.contains(db.to_str().unwrap()));
    assert!(stdout.contains("unlock:"));
    assert!(stdout.contains("keystore:"));
    assert!(stdout.contains("keyfile:"));
    assert!(stdout.contains("binary:"));
}

#[test]
fn doctor_mcp_github_prints_json_fragment() {
    let output = kprun()
        .args(["doctor", "--mcp", "github"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output).expect("stdout must be valid JSON");
    let command = value
        .get("command")
        .and_then(Value::as_str)
        .expect("command field");
    let args = value
        .get("args")
        .and_then(Value::as_array)
        .expect("args field");

    if cfg!(unix) {
        assert!(command == "kprun" || command.ends_with("/kprun"));
    } else {
        assert!(command.ends_with("kprun.exe"));
    }

    let expected_args = [
        "run",
        "github",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-github@2025.4.8",
    ];
    assert_eq!(args.len(), expected_args.len());
    for (i, expected) in expected_args.iter().enumerate() {
        assert_eq!(args[i].as_str(), Some(*expected));
    }
}

#[test]
fn doctor_mcp_generic_entry_prints_placeholder_args() {
    let assert = kprun()
        .args(["doctor", "--mcp", "openai"])
        .assert()
        .success()
        .stderr(predicates::str::contains(
            "kprun doctor --mcp openai -- npx -y @org/mcp-server",
        ));

    let value: Value =
        serde_json::from_slice(&assert.get_output().stdout).expect("stdout must be valid JSON");
    let args = value
        .get("args")
        .and_then(Value::as_array)
        .expect("args field");
    assert_eq!(
        args.iter().map(|v| v.as_str().unwrap()).collect::<Vec<_>>(),
        vec!["run", "openai", "--"]
    );
}

#[test]
fn doctor_mcp_with_child_command_prints_full_args() {
    let output = kprun()
        .args([
            "doctor",
            "--mcp",
            "qdrant",
            "--",
            "npx",
            "-y",
            "@modelcontextprotocol/server-qdrant",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output).expect("stdout must be valid JSON");
    let args = value
        .get("args")
        .and_then(Value::as_array)
        .expect("args field");
    assert_eq!(
        args.iter().map(|v| v.as_str().unwrap()).collect::<Vec<_>>(),
        vec![
            "run",
            "qdrant",
            "--",
            "npx",
            "-y",
            "@modelcontextprotocol/server-qdrant"
        ]
    );
}
