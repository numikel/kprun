mod common;

use common::{kprun_cmd, quick_env};
use kprun_core::unlock::{build_database_key, UnlockContext};
use kprun_core::vault::{open_vault, OpenMode};

#[test]
fn quick_creates_vault_and_prints_password_on_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let ks = dir.path().join("keystore");

    let output = kprun_cmd()
        .envs(quick_env(&db, &ks))
        .args(["init", "--quick"])
        .assert()
        .success()
        .stderr(predicates::str::contains("shown once"))
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).unwrap();
    assert_eq!(
        stdout.lines().count(),
        1,
        "stdout must carry only the password line"
    );
    let password = stdout.trim_end_matches(['\r', '\n']);
    assert_eq!(password.len(), 39);

    // The captured password alone (no keyfile) must open the vault —
    // KeePassXC-compatible by construction.
    let ctx = UnlockContext {
        keyfile: None,
        db_path: db.clone(),
    };
    let key = build_database_key(&ctx, password).unwrap();
    open_vault(&db, key, OpenMode::ReadOnly).unwrap();

    // Exactly one stored credential (the probe entry was cleaned up).
    assert_eq!(std::fs::read_dir(&ks).unwrap().count(), 1);
}

#[test]
fn quick_refuses_existing_vault_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let ks = dir.path().join("keystore");

    kprun_cmd()
        .envs(quick_env(&db, &ks))
        .args(["init", "--quick"])
        .assert()
        .success();
    let before = std::fs::read(&db).unwrap();

    kprun_cmd()
        .envs(quick_env(&db, &ks))
        .args(["init", "--quick"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("Vault already exists"));

    assert_eq!(
        std::fs::read(&db).unwrap(),
        before,
        "existing vault must be byte-identical"
    );
}

#[test]
fn quick_ignores_kprun_keyfile_and_creates_password_only_vault() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let ks = dir.path().join("keystore");
    let kf = dir.path().join("kprun.keyfile");

    let output = kprun_cmd()
        .envs(quick_env(&db, &ks))
        .env("KPRUN_KEYFILE", kf.to_str().unwrap())
        .args(["init", "--quick"])
        .assert()
        .success()
        .stderr(predicates::str::contains("ignoring KPRUN_KEYFILE"))
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).unwrap();
    let password = stdout.trim_end_matches(['\r', '\n']);
    let ctx = UnlockContext {
        keyfile: None,
        db_path: db.clone(),
    };
    let key = build_database_key(&ctx, password).unwrap();
    open_vault(&db, key, OpenMode::ReadOnly).unwrap();
    assert!(!kf.exists(), "--quick must not generate a keyfile");
}

#[test]
fn quick_force_without_tty_errors_and_preserves_vault() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let ks = dir.path().join("keystore");

    kprun_cmd()
        .envs(quick_env(&db, &ks))
        .args(["init", "--quick"])
        .assert()
        .success();
    let before = std::fs::read(&db).unwrap();

    // assert_cmd pipes stdin, so there is no TTY — overwrite must refuse.
    kprun_cmd()
        .envs(quick_env(&db, &ks))
        .args(["init", "--quick", "--force"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("interactive confirmation"));

    assert_eq!(std::fs::read(&db).unwrap(), before);
}
