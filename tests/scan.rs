//! Integration tests for `kprun scan`. Vault-free: no `test-hooks`
//! feature, no master password, no keyring.
//!
//! Synthetic secrets are always built by concatenation so this file never
//! triggers a secret scanner itself (GitHub push protection included).

use std::path::Path;
use std::process::Command as GitCommand;

use assert_cmd::Command;
use predicates::prelude::*;

/// Run `git -C <dir> <args>` with a fixed identity and signing disabled,
/// so commits work on any CI runner regardless of global git config.
fn git(dir: &Path, args: &[&str]) {
    let status = GitCommand::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.email=test@example.com",
            "-c",
            "user.name=kprun-tests",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .status()
        .expect("failed to spawn git");
    assert!(status.success(), "git {args:?} failed");
}

fn init_repo(dir: &Path) {
    git(dir, &["init", "-q"]);
}

fn commit_all(dir: &Path, message: &str) {
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "-m", message]);
}

fn scan_cmd(dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("kprun").unwrap();
    cmd.arg("scan").arg("--path").arg(dir);
    cmd
}

#[test]
fn clean_repo_exits_zero_with_empty_stdout() {
    let tmp = tempfile::tempdir().unwrap();
    init_repo(tmp.path());
    std::fs::write(tmp.path().join("README.md"), "# demo\n").unwrap();
    commit_all(tmp.path(), "initial");
    scan_cmd(tmp.path()).assert().code(0).stdout("");
}

#[test]
fn path_outside_a_repo_exits_two() {
    let tmp = tempfile::tempdir().unwrap();
    // Ceiling stops git's upward discovery at the temp dir's parent, so the
    // test cannot accidentally find an enclosing repository.
    scan_cmd(tmp.path())
        .env("GIT_CEILING_DIRECTORIES", tmp.path().parent().unwrap())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn tracked_env_file_is_a_finding() {
    let tmp = tempfile::tempdir().unwrap();
    init_repo(tmp.path());
    std::fs::write(tmp.path().join(".env"), "APP_SECRET=value\n").unwrap();
    commit_all(tmp.path(), "add env");
    scan_cmd(tmp.path())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("[env-file]").and(predicate::str::contains(".env")));
}

#[test]
fn env_example_without_secrets_is_clean() {
    let tmp = tempfile::tempdir().unwrap();
    init_repo(tmp.path());
    std::fs::write(tmp.path().join(".env.example"), "APP_SECRET=\n").unwrap();
    commit_all(tmp.path(), "add template");
    scan_cmd(tmp.path()).assert().code(0).stdout("");
}

#[test]
fn gitignored_untracked_env_is_clean() {
    let tmp = tempfile::tempdir().unwrap();
    init_repo(tmp.path());
    std::fs::write(tmp.path().join(".gitignore"), ".env\n").unwrap();
    commit_all(tmp.path(), "ignore env");
    std::fs::write(tmp.path().join(".env"), "APP_SECRET=value\n").unwrap();
    scan_cmd(tmp.path()).assert().code(0).stdout("");
}

#[test]
fn working_tree_secret_is_found_and_masked() {
    let tmp = tempfile::tempdir().unwrap();
    init_repo(tmp.path());
    let secret = "AKIA".to_string() + &"A7".repeat(8); // 16 chars after prefix
    std::fs::write(
        tmp.path().join("config.txt"),
        format!("aws_key = \"{secret}\"\n"),
    )
    .unwrap();
    commit_all(tmp.path(), "add config");
    scan_cmd(tmp.path()).assert().code(1).stdout(
        predicate::str::contains("[aws-access-key-id]")
            .and(predicate::str::contains("config.txt:1"))
            // Masking criterion: the full value must never reach stdout.
            .and(predicate::str::contains(secret.as_str()).not()),
    );
}

#[test]
fn secret_inside_env_example_is_still_scanned() {
    let tmp = tempfile::tempdir().unwrap();
    init_repo(tmp.path());
    let secret = "sk-proj-".to_string() + &"q".repeat(24);
    std::fs::write(
        tmp.path().join(".env.example"),
        format!("OPENAI_API_KEY={secret}\n"),
    )
    .unwrap();
    commit_all(tmp.path(), "add template with real key");
    scan_cmd(tmp.path()).assert().code(1).stdout(
        predicate::str::contains("[openai-project-key]")
            .and(predicate::str::contains("[env-file]").not())
            .and(predicate::str::contains(secret.as_str()).not()),
    );
}

#[test]
fn removed_secret_is_found_only_with_history() {
    let tmp = tempfile::tempdir().unwrap();
    init_repo(tmp.path());
    let secret = "AKIA".to_string() + &"C".repeat(16);
    std::fs::write(tmp.path().join("deploy.sh"), format!("KEY={secret}\n")).unwrap();
    commit_all(tmp.path(), "add secret");
    std::fs::write(tmp.path().join("deploy.sh"), "KEY=redacted\n").unwrap();
    commit_all(tmp.path(), "remove secret");

    // Working tree is clean now.
    scan_cmd(tmp.path()).assert().code(0);

    // The introducing commit (HEAD~1) must be named in the finding.
    let out = GitCommand::new("git")
        .arg("-C")
        .arg(tmp.path())
        .args(["rev-parse", "HEAD~1"])
        .output()
        .unwrap();
    let full_hash = String::from_utf8(out.stdout).unwrap();
    let short_hash = full_hash.trim()[..12].to_string();

    let mut cmd = scan_cmd(tmp.path());
    cmd.arg("--history");
    cmd.assert().code(1).stdout(
        predicate::str::contains("[aws-access-key-id]")
            .and(predicate::str::contains(format!("commit {short_hash}")))
            .and(predicate::str::contains("deploy.sh"))
            .and(predicate::str::contains(secret.as_str()).not()),
    );
}

#[test]
fn json_output_is_one_parsable_document_with_masked_values() {
    let tmp = tempfile::tempdir().unwrap();
    init_repo(tmp.path());
    let secret = "AKIA".to_string() + &"D".repeat(16);
    std::fs::write(tmp.path().join(".env"), "APP_SECRET=value\n").unwrap();
    std::fs::write(tmp.path().join("cfg.txt"), format!("k={secret}\n")).unwrap();
    commit_all(tmp.path(), "add files");

    let mut cmd = scan_cmd(tmp.path());
    cmd.arg("--json");
    let assert = cmd.assert().code(1);
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["version"], 1);
    assert_eq!(v["stats"]["history_commits"], 0);
    assert!(v["stats"]["files_scanned"].as_u64().unwrap() >= 2);

    let findings = v["findings"].as_array().unwrap();
    assert!(findings
        .iter()
        .any(|f| f["kind"] == "tracked_env_file" && f["path"] == ".env"));
    assert!(findings.iter().any(|f| f["kind"] == "secret"
        && f["pattern"] == "aws-access-key-id"
        && f["origin"] == "working_tree"
        && f["path"] == "cfg.txt"
        && f["line"] == 1));
    assert!(
        !stdout.contains(&secret),
        "full value must never reach stdout"
    );
}

#[test]
fn json_output_on_clean_repo_has_empty_findings_and_exit_zero() {
    let tmp = tempfile::tempdir().unwrap();
    init_repo(tmp.path());
    std::fs::write(tmp.path().join("README.md"), "# demo\n").unwrap();
    commit_all(tmp.path(), "initial");

    let mut cmd = scan_cmd(tmp.path());
    cmd.arg("--json");
    let assert = cmd.assert().code(0);
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["version"], 1);
    assert_eq!(v["findings"].as_array().unwrap().len(), 0);
}

#[test]
fn committed_binary_file_is_skipped_not_scanned() {
    let tmp = tempfile::tempdir().unwrap();
    init_repo(tmp.path());
    let secret = "AKIA".to_string() + &"F".repeat(16);
    // A NUL byte in the first 8 KiB marks the file binary; the secret bytes
    // that follow must never be pattern-scanned.
    let mut content = vec![0u8, 1, 2, 3];
    content.extend_from_slice(format!("KEY={secret}\n").as_bytes());
    std::fs::write(tmp.path().join("blob.bin"), content).unwrap();
    commit_all(tmp.path(), "add binary");

    let mut cmd = scan_cmd(tmp.path());
    cmd.arg("--json");
    let assert = cmd.assert().code(0);
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(!stdout.contains(&secret));
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["findings"].as_array().unwrap().len(), 0);
    assert!(v["stats"]["files_skipped"].as_u64().unwrap() >= 1);
}

#[test]
fn non_utf8_content_is_still_scanned() {
    let tmp = tempfile::tempdir().unwrap();
    init_repo(tmp.path());
    let secret = "AKIA".to_string() + &"G".repeat(16);
    // 0xFF is invalid UTF-8 but not a NUL, so the file is treated as text and
    // matched via lossy conversion — the ASCII secret must still be found.
    let mut content = format!("key={secret} ").into_bytes();
    content.push(0xFF);
    content.push(b'\n');
    std::fs::write(tmp.path().join("weird.txt"), content).unwrap();
    commit_all(tmp.path(), "add non-utf8");

    scan_cmd(tmp.path()).assert().code(1).stdout(
        predicate::str::contains("[aws-access-key-id]")
            .and(predicate::str::contains(secret.as_str()).not()),
    );
}

#[test]
fn file_over_5_mib_is_skipped_with_warning() {
    let tmp = tempfile::tempdir().unwrap();
    init_repo(tmp.path());
    let secret = "AKIA".to_string() + &"H".repeat(16);
    // Over the 5 MiB cap: the size guard skips it before pattern scanning.
    let mut content = vec![b'x'; 5 * 1024 * 1024 + 1];
    content.extend_from_slice(format!("\nKEY={secret}\n").as_bytes());
    std::fs::write(tmp.path().join("big.txt"), content).unwrap();
    commit_all(tmp.path(), "add big file");

    scan_cmd(tmp.path())
        .assert()
        .code(0)
        .stderr(predicate::str::contains("larger than 5 MiB"));
}

#[test]
fn full_history_scans_without_commit_limit() {
    let tmp = tempfile::tempdir().unwrap();
    init_repo(tmp.path());
    let secret = "AKIA".to_string() + &"J".repeat(16);
    std::fs::write(tmp.path().join("old.sh"), format!("KEY={secret}\n")).unwrap();
    commit_all(tmp.path(), "introduce secret");
    std::fs::write(tmp.path().join("old.sh"), "KEY=redacted\n").unwrap();
    commit_all(tmp.path(), "redact");

    let mut cmd = scan_cmd(tmp.path());
    cmd.args(["--history", "--full-history", "--json"]);
    let assert = cmd.assert().code(1);
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // Both commits parsed with no `-n` cap: exercises the `None` limit path.
    assert_eq!(v["stats"]["history_commits"], 2);
    assert!(v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["origin"] == "history"));
    assert!(!stdout.contains(&secret));
}

#[test]
fn history_scan_respects_path_scope() {
    let tmp = tempfile::tempdir().unwrap();
    init_repo(tmp.path());
    std::fs::create_dir(tmp.path().join("a")).unwrap();
    std::fs::create_dir(tmp.path().join("b")).unwrap();
    let secret = "AKIA".to_string() + &"K".repeat(16);
    std::fs::write(tmp.path().join("a/deploy.sh"), format!("KEY={secret}\n")).unwrap();
    std::fs::write(tmp.path().join("b/readme.txt"), "nothing\n").unwrap();
    commit_all(tmp.path(), "add secret under a");
    // Remove from the working tree so only history carries the secret.
    std::fs::write(tmp.path().join("a/deploy.sh"), "KEY=redacted\n").unwrap();
    commit_all(tmp.path(), "redact");

    // Scanning b/ must not surface a/'s historical secret.
    let mut in_b = Command::cargo_bin("kprun").unwrap();
    in_b.arg("scan")
        .arg("--path")
        .arg(tmp.path().join("b"))
        .arg("--history");
    in_b.assert().code(0);

    // Scanning a/ must surface it.
    let mut in_a = Command::cargo_bin("kprun").unwrap();
    in_a.arg("scan")
        .arg("--path")
        .arg(tmp.path().join("a"))
        .arg("--history");
    in_a.assert()
        .code(1)
        .stdout(predicate::str::contains("[aws-access-key-id]"));
}

#[test]
fn history_scan_survives_non_utf8_content_in_older_commit() {
    let tmp = tempfile::tempdir().unwrap();
    init_repo(tmp.path());
    // Oldest commit: latin-1 text (high bytes, no NUL) — git prints it as a
    // text patch, so the log stream carries invalid UTF-8. Because `git log`
    // is newest-first, this bad patch is parsed *after* the secret below;
    // the scan must keep the already-collected finding, not drop it.
    std::fs::write(tmp.path().join("legacy.txt"), b"caf\xE9 \xFF bar\n").unwrap();
    commit_all(tmp.path(), "add latin-1 text");
    let secret = "AKIA".to_string() + &"E".repeat(16);
    std::fs::write(tmp.path().join("deploy.sh"), format!("KEY={secret}\n")).unwrap();
    commit_all(tmp.path(), "add secret");
    std::fs::write(tmp.path().join("deploy.sh"), "KEY=redacted\n").unwrap();
    commit_all(tmp.path(), "remove secret");

    let mut cmd = scan_cmd(tmp.path());
    cmd.arg("--history");
    cmd.assert()
        .code(1)
        .stdout(
            predicate::str::contains("[aws-access-key-id]")
                .and(predicate::str::contains(secret.as_str()).not()),
        )
        .stderr(predicate::str::contains("history scan failed").not());
}
