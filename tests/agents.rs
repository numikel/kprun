//! Integration tests for `kprun agents`. Vault-free: no `test-hooks`
//! feature, no master password, no keyring — the agents branch never
//! unlocks the vault (pattern: `tests/scan.rs`).

use assert_cmd::Command;

/// kprun with vault-related env stripped: proves `agents` needs no vault.
fn kprun() -> Command {
    let mut cmd = Command::cargo_bin("kprun").unwrap();
    cmd.env_remove("KPRUN_DB")
        .env_remove("KPRUN_KEYFILE")
        .env_remove("COPILOT_HOME");
    cmd
}

#[test]
fn print_writes_policy_block_to_stdout() {
    let output = kprun()
        .args(["agents", "print"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();
    assert!(stdout.starts_with("<!-- kprun:agent-policy:start -->\n"));
    assert!(stdout.ends_with("<!-- kprun:agent-policy:end -->\n"));
    assert!(stdout.contains("## Secrets policy (kprun preferred)"));
}

#[test]
fn install_creates_agents_and_claude_md() {
    let dir = tempfile::tempdir().unwrap();
    kprun()
        .args(["agents", "install", "--path", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicates::str::contains("created"));
    let agents = std::fs::read(dir.path().join("AGENTS.md")).unwrap();
    let claude = std::fs::read(dir.path().join("CLAUDE.md")).unwrap();
    assert_eq!(agents, claude, "both files carry the identical block");
}

#[test]
fn print_block_matches_installed_agents_md() {
    let dir = tempfile::tempdir().unwrap();
    let stdout = kprun()
        .args(["agents", "print"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    kprun()
        .args(["agents", "install", "--path", dir.path().to_str().unwrap()])
        .assert()
        .success();
    let installed = std::fs::read(dir.path().join("AGENTS.md")).unwrap();
    assert_eq!(stdout, installed, "print and install share one constant");
}

#[test]
fn second_install_is_unchanged_and_byte_identical() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_str().unwrap().to_string();
    kprun()
        .args(["agents", "install", "--path", &path])
        .assert()
        .success();
    let before = std::fs::read(dir.path().join("AGENTS.md")).unwrap();
    kprun()
        .args(["agents", "install", "--path", &path])
        .assert()
        .success()
        .stderr(predicates::str::contains("unchanged"));
    let after = std::fs::read(dir.path().join("AGENTS.md")).unwrap();
    assert_eq!(before, after);
}

#[test]
fn install_appends_to_existing_claude_md_preserving_content() {
    let dir = tempfile::tempdir().unwrap();
    let claude = dir.path().join("CLAUDE.md");
    std::fs::write(&claude, "# Project notes\n").unwrap();
    kprun()
        .args(["agents", "install", "--path", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicates::str::contains("updated"));
    let content = std::fs::read_to_string(&claude).unwrap();
    assert!(content.starts_with("# Project notes\n\n<!-- kprun:agent-policy:start -->"));
    assert!(content
        .trim_end()
        .ends_with("<!-- kprun:agent-policy:end -->"));
}

#[test]
fn reinstall_restores_manual_edits_inside_markers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_str().unwrap().to_string();
    let agents_md = dir.path().join("AGENTS.md");
    std::fs::write(&agents_md, "# Kept intro\n").unwrap();
    kprun()
        .args(["agents", "install", "--path", &path])
        .assert()
        .success();
    let tampered = std::fs::read_to_string(&agents_md)
        .unwrap()
        .replace("## Secrets policy (kprun preferred)", "## HACKED");
    std::fs::write(&agents_md, tampered).unwrap();
    kprun()
        .args(["agents", "install", "--path", &path])
        .assert()
        .success()
        .stderr(predicates::str::contains("updated"));
    let restored = std::fs::read_to_string(&agents_md).unwrap();
    assert!(
        restored.starts_with("# Kept intro\n\n"),
        "content outside markers untouched"
    );
    assert!(restored.contains("## Secrets policy (kprun preferred)"));
    assert!(!restored.contains("## HACKED"));
}

#[test]
fn corrupted_markers_error_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let agents_md = dir.path().join("AGENTS.md");
    let corrupted = "intro\n<!-- kprun:agent-policy:start -->\nno end marker\n";
    std::fs::write(&agents_md, corrupted).unwrap();
    kprun()
        .args(["agents", "install", "--path", dir.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicates::str::contains("marker"));
    assert_eq!(std::fs::read_to_string(&agents_md).unwrap(), corrupted);
    // AGENTS.md is processed first and fails fast — CLAUDE.md is never written.
    assert!(!dir.path().join("CLAUDE.md").exists());
}
