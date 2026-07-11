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

    // NOTE: no assertion on the keystore dir here. The keychain account is
    // derived from the *canonicalized* db path (computed while the file
    // existed); once the file is gone, canonicalization falls back to the
    // raw path, which may differ (Windows \\?\ prefix, macOS /tmp symlink),
    // so the stored entry may legitimately survive as a NoEntry-tolerated
    // orphan — which is exactly the behavior this test exercises.
}
