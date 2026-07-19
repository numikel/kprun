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
