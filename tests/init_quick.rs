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

// --- Real OS keychain unavailable (keyring crate contract) -------------------
//
// These tests exercise the real `keyring` backend — no KPRUN_TEST_KEYSTORE
// seam, no KPRUN_TEST_MASTER bypass. They run on Linux only, with the D-Bus
// session address pointed at a socket that does not exist, so the
// secret-service backend fails deterministically and nothing ever touches a
// developer's real keychain.

#[cfg(target_os = "linux")]
mod keychain_unavailable {
    use super::common::{create_vault_with_entries, kprun_cmd};
    use std::path::Path;

    fn no_keychain_env(db: &Path, dir: &Path) -> [(&'static str, String); 2] {
        [
            ("KPRUN_DB", db.to_str().unwrap().to_string()),
            (
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}", dir.join("no-such-bus").display()),
            ),
        ]
    }

    /// Cause reported by the keyring backend when no secret service is reachable.
    const BACKEND_CAUSE: &str =
        "Platform failure: no secret service provider or dbus session found";

    #[test]
    fn quick_init_reports_keychain_cause_and_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("secrets.kdbx");

        kprun_cmd()
            .envs(no_keychain_env(&db, dir.path()))
            .args(["init", "--quick"])
            .assert()
            .code(1)
            .stdout("")
            .stderr(format!(
                "Checking OS keychain availability\n\
                 error: OS keychain unavailable ({BACKEND_CAUSE}). \
                 Run 'kprun init' to choose a password interactively.\n"
            ));
        assert!(!db.exists(), "no vault may be created without a keychain");
    }

    #[test]
    fn reveal_master_reports_keychain_cause_with_hint() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("secrets.kdbx");
        create_vault_with_entries(&db, &[("demo", &[("K", "v")])]);

        kprun_cmd()
            .envs(no_keychain_env(&db, dir.path()))
            .args(["reveal-master"])
            .assert()
            .code(1)
            .stdout("")
            .stderr(format!(
                "error: OS keychain unavailable while reading the stored master password \
                 ({BACKEND_CAUSE}). On headless Linux start/unlock a secret-service store; \
                 on macOS approve the keychain access prompt. Vault: {}\n",
                db.display()
            ));
    }

    #[test]
    fn deinit_reports_keychain_cause() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("secrets.kdbx");
        create_vault_with_entries(&db, &[("demo", &[("K", "v")])]);

        kprun_cmd()
            .envs(no_keychain_env(&db, dir.path()))
            .args(["deinit"])
            .assert()
            .code(1)
            .stdout("")
            .stderr(format!("error: {BACKEND_CAUSE}\n"));
        assert!(db.exists(), "deinit without --delete-vault keeps the vault");
    }
}
