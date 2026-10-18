mod common;

use std::path::Path;

use assert_cmd::Command;
use serde_json::Value;

use common::{create_vault_with_entries, kprun_cmd, test_env};

fn setup_vault(db: &Path) {
    create_vault_with_entries(db, &[("github", &[("GITHUB_TOKEN", "ghp_secret")])]);
}

/// kprun pointed at a fake HOME (both `HOME` and `USERPROFILE`, matching
/// kprun-core's `home_dir()`) with `COPILOT_HOME` unset: doctor reads the
/// global agent files, so the developer's real ones must never leak in.
fn kprun_with_home(home: &Path) -> Command {
    let mut cmd = kprun_cmd();
    cmd.env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("COPILOT_HOME");
    cmd
}

#[test]
fn doctor_reports_vault_unlock_and_binary() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_vault(&db);
    let home = tempfile::tempdir().unwrap();

    let output = kprun_with_home(home.path())
        .envs(test_env(&db))
        .current_dir(dir.path())
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
    assert!(stdout.contains("agents: not configured (run: kprun agents install)"));
}

#[test]
fn doctor_mcp_github_prints_json_fragment() {
    let output = kprun_cmd()
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
    let assert = kprun_cmd()
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
    let output = kprun_cmd()
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

#[test]
fn doctor_reports_agents_policy_installed() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_vault(&db);
    let home = tempfile::tempdir().unwrap();
    let copilot_home = tempfile::tempdir().unwrap();
    let doctor = || {
        let output = kprun_with_home(home.path())
            .env("COPILOT_HOME", copilot_home.path())
            .envs(test_env(&db))
            .current_dir(dir.path())
            .args(["doctor"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        String::from_utf8_lossy(&output).into_owned()
    };

    // Global install only (#70): doctor must find the files `-g` wrote,
    // resolving COPILOT_HOME the same way the installer does.
    kprun_with_home(home.path())
        .env("COPILOT_HOME", copilot_home.path())
        .current_dir(dir.path())
        .args(["agents", "install", "-g", "--target", "claude,copilot"])
        .assert()
        .success();
    let stdout = doctor();
    assert!(
        stdout.contains("agents: policy installed (global: claude, copilot)"),
        "stdout was: {stdout}"
    );

    // Repo-level install on top: both scopes are listed.
    kprun_cmd()
        .current_dir(dir.path())
        .args(["agents", "install"])
        .assert()
        .success();
    let stdout = doctor();
    assert!(
        stdout.contains("agents: policy installed (AGENTS.md, CLAUDE.md; global: claude, copilot)"),
        "stdout was: {stdout}"
    );
}

#[test]
fn doctor_reports_agents_installed_from_claude_md_only() {
    // Regression guard for the OR check: `agents install` writes both
    // AGENTS.md and CLAUDE.md, so doctor must recognize either file — a repo
    // carrying only CLAUDE.md is configured, not "not configured".
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_vault(&db);

    kprun_cmd()
        .current_dir(dir.path())
        .args(["agents", "install"])
        .assert()
        .success();
    // Leave only CLAUDE.md behind.
    std::fs::remove_file(dir.path().join("AGENTS.md")).unwrap();
    let home = tempfile::tempdir().unwrap();

    let output = kprun_with_home(home.path())
        .envs(test_env(&db))
        .current_dir(dir.path())
        .args(["doctor"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8_lossy(&output);
    assert!(
        stdout.contains("agents: policy installed (CLAUDE.md)"),
        "stdout was: {stdout}"
    );
}
