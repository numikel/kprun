mod common;

use std::path::Path;

use kprun_core::test_support;
use kprun_core::unlock::{build_database_key, UnlockContext};
use kprun_core::vault::create_vault;
use serde_json::Value;

use common::{create_vault_with_entries, kprun_cmd, test_env};

fn setup_multi_entry_vault(db: &Path) {
    create_vault_with_entries(
        db,
        &[
            ("github", &[("GITHUB_TOKEN", "ghp_secret")]),
            ("postgres", &[("DATABASE_URL", "postgres://local")]),
        ],
    );
}

#[test]
fn export_json_hides_values_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_multi_entry_vault(&db);

    let output = kprun_cmd()
        .envs(test_env(&db))
        .args(["export", "--stdout"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: Value = serde_json::from_slice(&output).unwrap();
    let entries = parsed["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);

    for entry in entries {
        let keys = &entry["keys"];
        assert!(keys.is_array());
        assert!(keys.as_object().is_none());
    }

    let text = String::from_utf8_lossy(&output);
    assert!(!text.contains("ghp_secret"));
    assert!(!text.contains("postgres://local"));
}

#[test]
fn export_json_reveal_includes_values_and_warns() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_multi_entry_vault(&db);

    let assert = kprun_cmd()
        .envs(test_env(&db))
        .args(["export", "--stdout", "--reveal"])
        .assert()
        .success()
        .stderr(predicates::str::contains(
            "WARNING: secret values are displayed in the terminal",
        ));

    let output = assert.get_output().stdout.clone();
    let parsed: Value = serde_json::from_slice(&output).unwrap();
    let github = parsed["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["title"] == "github")
        .unwrap();
    assert_eq!(github["keys"]["GITHUB_TOKEN"], "ghp_secret");
}

#[test]
fn export_dotenv_formats_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_multi_entry_vault(&db);

    let hidden = kprun_cmd()
        .envs(test_env(&db))
        .args(["export", "--format", "dotenv", "--stdout"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let hidden_text = String::from_utf8_lossy(&hidden);
    assert!(hidden_text.contains("# github"));
    assert!(hidden_text.contains("# GITHUB_TOKEN"));
    assert!(!hidden_text.contains("ghp_secret"));

    let revealed = kprun_cmd()
        .envs(test_env(&db))
        .args(["export", "--format", "dotenv", "--stdout", "--reveal"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let revealed_text = String::from_utf8_lossy(&revealed);
    assert!(revealed_text.contains("GITHUB_TOKEN=\"ghp_secret\""));
    assert!(revealed_text.contains("# postgres"));
    assert!(revealed_text.contains("DATABASE_URL=\"postgres://local\""));
}

#[test]
fn import_json_merge_preserves_unmentioned_entries() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let import_file = dir.path().join("import.json");
    setup_multi_entry_vault(&db);

    std::fs::write(
        &import_file,
        r#"{
  "entries": [
    { "title": "github", "keys": { "GITHUB_TOKEN": "ghp_new" } },
    { "title": "stripe", "keys": { "STRIPE_KEY": "sk_test" } }
  ]
}"#,
    )
    .unwrap();

    kprun_cmd()
        .envs(test_env(&db))
        .args(["import", import_file.to_str().unwrap(), "--merge"])
        .assert()
        .success();

    let list = kprun_cmd()
        .envs(test_env(&db))
        .args(["list", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let entries: Value = serde_json::from_slice(&list).unwrap();
    let titles: Vec<&str> = entries
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["title"].as_str().unwrap())
        .collect();
    assert!(titles.contains(&"github"));
    assert!(titles.contains(&"postgres"));
    assert!(titles.contains(&"stripe"));

    let reveal = kprun_cmd()
        .envs(test_env(&db))
        .args(["get", "github", "--reveal"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let reveal_text = String::from_utf8_lossy(&reveal);
    assert!(reveal_text.contains("ghp_new"));
}

#[test]
fn import_json_without_merge_removes_unmentioned_entries() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let import_file = dir.path().join("import.json");
    setup_multi_entry_vault(&db);

    std::fs::write(
        &import_file,
        r#"{
  "entries": [
    { "title": "github", "keys": { "GITHUB_TOKEN": "ghp_only" } }
  ]
}"#,
    )
    .unwrap();

    kprun_cmd()
        .envs(test_env(&db))
        .args(["import", import_file.to_str().unwrap()])
        .assert()
        .success();

    let list = kprun_cmd()
        .envs(test_env(&db))
        .args(["list", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let entries: Value = serde_json::from_slice(&list).unwrap();
    let titles: Vec<&str> = entries
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, vec!["github"]);
}

#[test]
fn import_dotenv_hidden_without_merge_rejects_and_preserves_vault() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let import_file = dir.path().join("hidden.env");
    setup_multi_entry_vault(&db);

    let exported = kprun_cmd()
        .envs(test_env(&db))
        .args(["export", "--format", "dotenv", "--stdout"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    std::fs::write(&import_file, &exported).unwrap();

    kprun_cmd()
        .envs(test_env(&db))
        .args(["import", import_file.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "structure-only dotenv export cannot be imported",
        ));

    let list = kprun_cmd()
        .envs(test_env(&db))
        .args(["list", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let entries: Value = serde_json::from_slice(&list).unwrap();
    let titles: Vec<&str> = entries
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles.len(), 2);
    assert!(titles.contains(&"github"));
    assert!(titles.contains(&"postgres"));
}

#[test]
fn import_dotenv_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let export_file = dir.path().join("export.env");
    let import_db = dir.path().join("imported.kdbx");
    setup_multi_entry_vault(&db);

    kprun_cmd()
        .envs(test_env(&db))
        .args(["export", "--format", "dotenv", "--stdout", "--reveal"])
        .assert()
        .success()
        .stdout(predicates::str::contains("GITHUB_TOKEN=\"ghp_secret\""));

    let exported = kprun_cmd()
        .envs(test_env(&db))
        .args(["export", "--format", "dotenv", "--stdout", "--reveal"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    std::fs::write(&export_file, &exported).unwrap();

    let ctx = UnlockContext {
        keyfile: None,
        db_path: db.to_path_buf(),
    };
    let key = build_database_key(&ctx, test_support::vault_password()).unwrap();
    create_vault(&import_db, key, "kprun").unwrap();

    kprun_cmd()
        .envs(test_env(&import_db))
        .args(["import", export_file.to_str().unwrap(), "--merge"])
        .assert()
        .success();

    kprun_cmd()
        .envs(test_env(&import_db))
        .args(["get", "github", "--reveal"])
        .assert()
        .success()
        .stdout(predicates::str::contains("ghp_secret"));
}

#[test]
fn import_dotenv_trims_value_whitespace() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let import_file = dir.path().join("trim.env");

    let ctx = UnlockContext {
        keyfile: None,
        db_path: db.to_path_buf(),
    };
    let key = build_database_key(&ctx, test_support::vault_password()).unwrap();
    create_vault(&db, key, "kprun").unwrap();

    std::fs::write(&import_file, "# trimtest\nTRIM_KEY= value \n").unwrap();

    kprun_cmd()
        .envs(test_env(&db))
        .args(["import", import_file.to_str().unwrap(), "--merge"])
        .assert()
        .success();

    kprun_cmd()
        .envs(test_env(&db))
        .args(["get", "trimtest", "--reveal"])
        .assert()
        .success()
        .stdout(predicates::str::contains("TRIM_KEY=value"));
}

#[test]
fn import_writes_audit_record_with_names_only() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let log = dir.path().join("access.log");
    let import_file = dir.path().join("import.json");
    setup_multi_entry_vault(&db);
    std::fs::write(
        &import_file,
        r#"{ "entries": [ { "title": "stripe", "keys": { "STRIPE_KEY": "sk_test" } } ] }"#,
    )
    .unwrap();

    kprun_cmd()
        .envs(test_env(&db))
        .env("KPRUN_LOG", log.to_str().unwrap())
        .args(["import", import_file.to_str().unwrap(), "--merge"])
        .assert()
        .success();

    let content = std::fs::read_to_string(&log).unwrap();
    assert!(content.contains(r#""command":"import""#), "got: {content}");
    assert!(content.contains("stripe"));
    assert!(content.contains("STRIPE_KEY"));
    assert!(!content.contains("sk_test"));
}

#[test]
fn export_writes_audit_record_for_every_run() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let log = dir.path().join("access.log");
    setup_multi_entry_vault(&db);

    kprun_cmd()
        .envs(test_env(&db))
        .env("KPRUN_LOG", log.to_str().unwrap())
        .args(["export", "--stdout"])
        .assert()
        .success();
    kprun_cmd()
        .envs(test_env(&db))
        .env("KPRUN_LOG", log.to_str().unwrap())
        .args(["export", "--stdout", "--reveal"])
        .assert()
        .success();

    let content = std::fs::read_to_string(&log).unwrap();
    assert!(content.contains(r#""command":"export""#), "got: {content}");
    assert!(
        content.contains(r#""command":"export --reveal""#),
        "got: {content}"
    );
    assert!(content.contains("GITHUB_TOKEN"));
    assert!(!content.contains("ghp_secret"));
}
