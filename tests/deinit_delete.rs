mod common;

use common::{kprun_cmd, quick_env};

#[test]
fn deinit_delete_vault_yes_removes_file_and_keystore_entry() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let ks = dir.path().join("keystore");
    let log = dir.path().join("access.log");
    let kf = dir.path().join("kprun.keyfile");

    kprun_cmd()
        .envs(quick_env(&db, &ks))
        .args(["init", "--quick"])
        .assert()
        .success();
    std::fs::write(&log, "{}\n").unwrap();
    std::fs::write(&kf, "not-a-real-keyfile").unwrap();
    assert_eq!(std::fs::read_dir(&ks).unwrap().count(), 1);

    kprun_cmd()
        .envs(quick_env(&db, &ks))
        .env("KPRUN_LOG", log.to_str().unwrap())
        .env("KPRUN_KEYFILE", kf.to_str().unwrap())
        .args(["deinit", "--delete-vault", "--yes"])
        .assert()
        .success();

    assert!(!db.exists(), "vault file must be deleted");
    assert_eq!(
        std::fs::read_dir(&ks).unwrap().count(),
        0,
        "keystore entry must be deleted"
    );
    assert!(log.exists(), "audit log must never be touched");
    assert!(kf.exists(), "keyfile must never be touched");
}

#[test]
fn deinit_delete_vault_without_yes_or_tty_errors() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let ks = dir.path().join("keystore");

    kprun_cmd()
        .envs(quick_env(&db, &ks))
        .args(["init", "--quick"])
        .assert()
        .success();

    // assert_cmd pipes stdin, so there is no TTY — must refuse and hint --yes.
    kprun_cmd()
        .envs(quick_env(&db, &ks))
        .args(["deinit", "--delete-vault"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("--yes"));

    assert!(db.exists(), "vault must survive a refused deletion");
    assert_eq!(
        std::fs::read_dir(&ks).unwrap().count(),
        1,
        "keystore entry must survive a refused deletion"
    );
}

#[test]
fn deinit_delete_vault_missing_file_is_note_not_error() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let ks = dir.path().join("keystore");

    kprun_cmd()
        .envs(quick_env(&db, &ks))
        .args(["init", "--quick"])
        .assert()
        .success();
    std::fs::remove_file(&db).unwrap();

    kprun_cmd()
        .envs(quick_env(&db, &ks))
        .args(["deinit", "--delete-vault", "--yes"])
        .assert()
        .success()
        .stderr(predicates::str::contains("not found (nothing to delete)"));

    // The keychain account is derived lexically (std::path::absolute), so it is
    // identical whether or not the vault file exists. deinit therefore still
    // removes the stored entry even though the file was already gone. This is
    // the regression guard for the old canonicalize-based digest, which fell
    // back to a different (raw-path) account once the file vanished and left
    // the entry orphaned — notably on Windows (\\?\ prefix) and macOS (/tmp
    // symlink).
    assert_eq!(
        std::fs::read_dir(&ks).unwrap().count(),
        0,
        "keystore entry must be removed even when the vault file is already gone"
    );
}
