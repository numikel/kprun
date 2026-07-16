mod common;

use std::path::{Path, PathBuf};

use common::{create_vault_with_entries, kprun_cmd, test_env};
use predicates::prelude::PredicateBooleanExt;

/// Create `<parent>/<dir>/.env` with `content` and return its path.
fn write_env_file(parent: &Path, dir: &str, content: &str) -> PathBuf {
    let project = parent.join(dir);
    std::fs::create_dir(&project).unwrap();
    let env_file = project.join(".env");
    std::fs::write(&env_file, content).unwrap();
    env_file
}

#[test]
fn migrate_imports_keys_and_updates_gitignore_without_duplicates() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    create_vault_with_entries(&db, &[]);
    let env_file = write_env_file(
        dir.path(),
        "backend",
        "API_KEY=sk-123\nDB_URL=postgres://x\n",
    );

    kprun_cmd()
        .envs(test_env(&db))
        .args(["migrate", env_file.to_str().unwrap(), "--gitignore"])
        .assert()
        .success();

    // Keys land in the vault under the directory-derived title.
    kprun_cmd()
        .envs(test_env(&db))
        .args(["get", "backend", "--reveal"])
        .assert()
        .success()
        .stdout(predicates::str::contains("API_KEY=sk-123"))
        .stdout(predicates::str::contains("DB_URL=postgres://x"));

    // .gitignore created next to the file; source file untouched.
    let gitignore = env_file.parent().unwrap().join(".gitignore");
    assert_eq!(std::fs::read_to_string(&gitignore).unwrap(), ".env\n");
    assert!(env_file.exists());

    // A second run adds no duplicate line.
    kprun_cmd()
        .envs(test_env(&db))
        .args([
            "migrate",
            env_file.to_str().unwrap(),
            "--gitignore",
            "--merge",
        ])
        .assert()
        .success();
    assert_eq!(std::fs::read_to_string(&gitignore).unwrap(), ".env\n");
}

#[test]
fn migrate_delete_removes_source_file_after_import() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    create_vault_with_entries(&db, &[]);
    let env_file = write_env_file(dir.path(), "svc", "TOKEN=abc\n");

    kprun_cmd()
        .envs(test_env(&db))
        .args([
            "migrate",
            env_file.to_str().unwrap(),
            "--gitignore",
            "--delete",
        ])
        .assert()
        .success();

    assert!(!env_file.exists());
    kprun_cmd()
        .envs(test_env(&db))
        .args(["get", "svc", "--reveal"])
        .assert()
        .success()
        .stdout(predicates::str::contains("TOKEN=abc"));
}

#[test]
fn migrate_non_tty_skips_gitignore_with_hint_and_keeps_file() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    create_vault_with_entries(&db, &[]);
    let env_file = write_env_file(dir.path(), "svc", "TOKEN=abc\n");

    // Test stdin is a pipe -> is_terminal() is false -> non-TTY branch.
    kprun_cmd()
        .envs(test_env(&db))
        .args(["migrate", env_file.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicates::str::contains(
            "use --gitignore to update .gitignore non-interactively",
        ))
        .stderr(predicates::str::contains("use --delete to remove it"));

    assert!(!env_file.parent().unwrap().join(".gitignore").exists());
    assert!(env_file.exists());
    kprun_cmd()
        .envs(test_env(&db))
        .args(["get", "svc", "--keys"])
        .assert()
        .success()
        .stdout(predicates::str::contains("TOKEN"));
}

#[test]
fn migrate_entry_flag_overrides_directory_default() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    create_vault_with_entries(&db, &[]);
    let env_file = write_env_file(dir.path(), "backend", "A=1\n");

    kprun_cmd()
        .envs(test_env(&db))
        .args([
            "migrate",
            env_file.to_str().unwrap(),
            "--entry",
            "custom-name",
        ])
        .assert()
        .success();

    kprun_cmd()
        .envs(test_env(&db))
        .args(["get", "custom-name", "--keys"])
        .assert()
        .success()
        .stdout(predicates::str::contains("A"));
}

#[test]
fn migrate_existing_entry_requires_merge_and_merge_preserves_keys() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    create_vault_with_entries(&db, &[("backend", &[("OLD_KEY", "old-value")])]);
    let env_file = write_env_file(dir.path(), "backend", "NEW_KEY=new-value\n");

    // Without --merge: hard error suggesting the flag; nothing imported.
    kprun_cmd()
        .envs(test_env(&db))
        .args(["migrate", env_file.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicates::str::contains("--merge"));
    kprun_cmd()
        .envs(test_env(&db))
        .args(["get", "backend", "--keys"])
        .assert()
        .success()
        .stdout(predicates::str::contains("NEW_KEY").not());

    // With --merge: keys added, pre-existing keys survive.
    kprun_cmd()
        .envs(test_env(&db))
        .args(["migrate", env_file.to_str().unwrap(), "--merge"])
        .assert()
        .success();
    kprun_cmd()
        .envs(test_env(&db))
        .args(["get", "backend", "--reveal"])
        .assert()
        .success()
        .stdout(predicates::str::contains("OLD_KEY=old-value"))
        .stdout(predicates::str::contains("NEW_KEY=new-value"));
}

#[test]
fn migrate_missing_file_fails_without_touching_vault() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    create_vault_with_entries(&db, &[("existing", &[("K", "v")])]);
    let missing = dir.path().join("nope").join(".env");

    kprun_cmd()
        .envs(test_env(&db))
        .args(["migrate", missing.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicates::str::contains("cannot read"));

    let list = kprun_cmd()
        .envs(test_env(&db))
        .args(["list", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let entries: serde_json::Value = serde_json::from_slice(&list).unwrap();
    assert_eq!(entries.as_array().unwrap().len(), 1);
}

#[test]
fn migrate_skips_empty_value_with_warning() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    create_vault_with_entries(&db, &[]);
    let env_file = write_env_file(dir.path(), "svc", "EMPTY=\nFULL=x\n");

    // Empty values cannot survive the KDBX save/reload round-trip (the keepass
    // backend drops empty field values), so migrate warns and skips them
    // rather than silently losing the key.
    kprun_cmd()
        .envs(test_env(&db))
        .args(["migrate", env_file.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicates::str::contains("skipping key 'EMPTY'"));

    kprun_cmd()
        .envs(test_env(&db))
        .args(["get", "svc", "--reveal"])
        .assert()
        .success()
        .stdout(predicates::str::contains("FULL=x"))
        .stdout(predicates::str::contains("EMPTY").not());
}

#[test]
fn migrate_all_empty_values_errors_before_unlock_and_no_entry_created() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    create_vault_with_entries(&db, &[]);
    // A file whose only key has an empty value: nothing is storable, so this
    // must fail before the vault is unlocked, leaving no entry behind.
    let env_file = write_env_file(dir.path(), "svc", "EMPTY=\n");

    kprun_cmd()
        .envs(test_env(&db))
        .args(["migrate", env_file.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "no non-empty KEY=value lines found",
        ));

    // No entry created — vault untouched.
    kprun_cmd()
        .envs(test_env(&db))
        .args(["list", "--json"])
        .assert()
        .success()
        .stdout(predicates::str::contains("svc").not());
}

#[test]
fn migrate_gitignore_failure_skips_delete_and_explains_next_steps() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    create_vault_with_entries(&db, &[]);
    let env_file = write_env_file(dir.path(), "svc", "TOKEN=abc\n");
    // A *directory* named .gitignore makes read_to_string fail portably
    // (IsADirectory on Unix, access denied on Windows).
    std::fs::create_dir(env_file.parent().unwrap().join(".gitignore")).unwrap();

    kprun_cmd()
        .envs(test_env(&db))
        .args([
            "migrate",
            env_file.to_str().unwrap(),
            "--entry",
            "custom-name",
            "--gitignore",
            "--delete",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("NOT deleted"))
        .stderr(predicates::str::contains("--merge"))
        // The rerun hint must target the entry that now holds the keys, not
        // the directory-derived default.
        .stderr(predicates::str::contains("--entry custom-name"));

    // Destructive-last: the source file survives; the import happened.
    assert!(env_file.exists());
    kprun_cmd()
        .envs(test_env(&db))
        .args(["get", "custom-name", "--keys"])
        .assert()
        .success()
        .stdout(predicates::str::contains("TOKEN"));
}

#[test]
fn migrate_writes_audit_record_with_key_names_only() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let log = dir.path().join("access.log");
    create_vault_with_entries(&db, &[]);
    let env_file = write_env_file(dir.path(), "svc", "TOKEN=super-secret\n");

    kprun_cmd()
        .envs(test_env(&db))
        .env("KPRUN_LOG", log.to_str().unwrap())
        .args(["migrate", env_file.to_str().unwrap(), "--delete"])
        .assert()
        .success();

    let content = std::fs::read_to_string(&log).unwrap();
    assert!(
        content.contains(r#""command":"migrate --delete""#),
        "got: {content}"
    );
    assert!(content.contains("svc"));
    assert!(content.contains("TOKEN"));
    assert!(!content.contains("super-secret"));
}
