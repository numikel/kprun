mod common;

use std::path::Path;

use kprun_core::test_support;
use kprun_core::unlock::{build_database_key, UnlockContext};
use kprun_core::vault::create_vault;
use predicates::prelude::PredicateBooleanExt;

use common::{create_vault_with_entries, kprun_cmd, test_env};

fn setup_openai_vault(db: &Path) {
    create_vault_with_entries(db, &[("openai", &[("OPENAI_API_KEY", "sk-secret-value")])]);
}

#[test]
fn list_shows_entry_keys_not_values() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_openai_vault(&db);

    let output = kprun_cmd()
        .envs(test_env(&db))
        .args(["list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8_lossy(&output);
    assert!(stdout.contains("openai"));
    assert!(stdout.contains("OPENAI_API_KEY"));
    assert!(!stdout.contains("sk-secret"));
    assert!(!stdout.contains("sk-"));
}

#[test]
fn get_reveal_audits_access() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let log = dir.path().join("access.log");
    setup_openai_vault(&db);

    kprun_cmd()
        .envs(test_env(&db))
        .env("KPRUN_LOG", log.to_str().unwrap())
        .args(["get", "openai", "--reveal"])
        .assert()
        .success()
        .stderr(predicates::str::contains(
            "WARNING: secret values are displayed in the terminal",
        ));

    let log_content = std::fs::read_to_string(&log).unwrap();
    assert!(log_content.contains("openai"));
    assert!(log_content.contains("OPENAI_API_KEY"));
    assert!(!log_content.contains("sk-secret"));
    assert!(!log_content.contains("sk-"));
}

#[test]
fn get_keys_audits_access() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let log = dir.path().join("access.log");
    setup_openai_vault(&db);

    kprun_cmd()
        .envs(test_env(&db))
        .env("KPRUN_LOG", log.to_str().unwrap())
        .args(["get", "openai", "--keys"])
        .assert()
        .success();

    let log_content = std::fs::read_to_string(&log).unwrap();
    assert!(log_content.contains("openai"));
    assert!(log_content.contains("OPENAI_API_KEY"));
}

#[test]
fn set_unset_delete_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let ctx = UnlockContext {
        keyfile: None,
        db_path: db.to_path_buf(),
    };
    let key = build_database_key(&ctx, test_support::vault_password()).unwrap();
    create_vault(&db, key, "kprun").unwrap();

    let env = test_env(&db);

    kprun_cmd()
        .envs(env)
        .args(["set", "demo", "DEMO_KEY=demo-val", "OTHER=1"])
        .assert()
        .success();

    kprun_cmd()
        .envs(env)
        .args(["get", "demo", "--keys"])
        .assert()
        .success()
        .stdout(predicates::str::contains("DEMO_KEY"))
        .stdout(predicates::str::contains("OTHER"));

    kprun_cmd()
        .envs(env)
        .args(["unset", "demo", "OTHER"])
        .assert()
        .success();

    kprun_cmd()
        .envs(env)
        .args(["get", "demo", "--keys"])
        .assert()
        .success()
        .stdout(predicates::str::contains("DEMO_KEY"))
        .stdout(predicates::str::contains("OTHER").not());

    kprun_cmd()
        .envs(env)
        .args(["delete", "demo"])
        .assert()
        .success();

    kprun_cmd()
        .envs(env)
        .args(["list"])
        .assert()
        .success()
        .stdout(predicates::str::contains("demo").not());
}

#[test]
fn set_stdin_reads_pairs_skipping_blanks_and_comments() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    create_vault_with_entries(&db, &[("seed", &[("SEED_KEY", "v")])]);

    kprun_cmd()
        .envs(test_env(&db))
        .args(["set", "github", "--stdin"])
        .write_stdin("GITHUB_TOKEN=ghp_stdin_test\n\n# comment line\nORG=acme\n")
        .assert()
        .success();

    kprun_cmd()
        .envs(test_env(&db))
        .args(["get", "github", "--keys"])
        .assert()
        .success()
        .stdout(predicates::str::contains("GITHUB_TOKEN"))
        .stdout(predicates::str::contains("ORG"));
}

#[test]
fn set_stdin_malformed_line_fails_without_echoing_it() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    create_vault_with_entries(&db, &[("seed", &[("SEED_KEY", "v")])]);

    kprun_cmd()
        .envs(test_env(&db))
        .args(["set", "github", "--stdin"])
        .write_stdin("this-line-has-no-equals-and-is-sensitive\n")
        .assert()
        .failure()
        .stderr(predicates::str::contains("no-equals-and-is-sensitive").not());
}

// --- Error message contract -------------------------------------------------
//
// `KprunError`'s `Display` (derived via thiserror) is what users see as
// `error: <message>` on stderr. These tests pin the exact text so that a
// dependency bump cannot silently change user-facing messages.

#[test]
fn kprun_error_display_texts_are_stable() {
    use kprun_core::KprunError;
    use std::path::PathBuf;

    let cases: Vec<(KprunError, &str)> = vec![
        (
            KprunError::DatabaseNotFound(PathBuf::from("/v/secrets.kdbx")),
            "database not found at /v/secrets.kdbx; run `kprun init`",
        ),
        (
            KprunError::EntryNotFound("openai".into()),
            "entry 'openai' not found",
        ),
        (KprunError::UnlockFailed, "failed to unlock vault"),
        (
            KprunError::DatabaseLocked,
            "database is locked; close KeePassXC or retry",
        ),
        (
            KprunError::InvalidKeyVal,
            "invalid KEY=VALUE pair: missing '='",
        ),
        (KprunError::EmptyKey, "invalid KEY=VALUE pair: empty key"),
        (
            KprunError::DuplicateEntry("dup".into()),
            "multiple entries share the title 'dup'; titles must be unique",
        ),
        (
            KprunError::WeakPassword(12),
            "master password too short: minimum 12 characters required",
        ),
        (
            KprunError::UnknownTemplateField("NOPE".into()),
            "template references unknown field 'NOPE' (not present on the vault entry)",
        ),
        (
            KprunError::MalformedTemplate("unclosed '{{'".into()),
            "malformed template: unclosed '{{'",
        ),
        (
            KprunError::NonInteractiveUnlock,
            "cannot unlock vault non-interactively; store the master password with `kprun init` or set KPRUN_KEYFILE for a keyfile-only vault",
        ),
        (
            KprunError::VaultOpen("bad key".into()),
            "failed to open vault: bad key",
        ),
        (KprunError::Other("free text".into()), "free text"),
    ];
    for (err, expected) in cases {
        assert_eq!(err.to_string(), expected, "Display of {err:?}");
    }
}

#[test]
fn kprun_error_from_conversions_keep_message_and_source() {
    use kprun_core::KprunError;
    use std::error::Error as _;

    let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no access");
    let err = KprunError::from(io);
    assert!(matches!(err, KprunError::Io(_)));
    assert_eq!(err.to_string(), "no access");
    assert_eq!(
        err.source().map(|s| s.to_string()).as_deref(),
        Some("no access")
    );

    let json_err = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
    let json_msg = json_err.to_string();
    let err = KprunError::from(json_err);
    assert!(matches!(err, KprunError::Json(_)));
    assert_eq!(err.to_string(), json_msg);
    assert_eq!(err.source().map(|s| s.to_string()), Some(json_msg));

    // Variants without #[from]/#[source] expose no source.
    assert!(KprunError::UnlockFailed.source().is_none());
}

#[test]
fn cli_prints_exact_entry_not_found_error() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_openai_vault(&db);

    kprun_cmd()
        .envs(test_env(&db))
        .args(["get", "missing"])
        .assert()
        .code(1)
        .stdout("")
        .stderr("error: entry 'missing' not found\n");
}

#[test]
fn cli_prints_exact_database_not_found_error() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("absent.kdbx");

    kprun_cmd()
        .envs(test_env(&db))
        .args(["list"])
        .assert()
        .code(1)
        .stdout("")
        .stderr(format!(
            "error: database not found at {}; run `kprun init`\n",
            db.display()
        ));
}
