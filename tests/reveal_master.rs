mod common;

use common::{kprun_cmd, quick_env};

#[test]
fn reveal_master_prints_the_quick_password() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let ks = dir.path().join("keystore");
    let log = dir.path().join("access.log");

    let init_out = kprun_cmd()
        .envs(quick_env(&db, &ks))
        .args(["init", "--quick"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let init_stdout = String::from_utf8(init_out).unwrap();
    let password = init_stdout.trim_end_matches(['\r', '\n']);

    let reveal_out = kprun_cmd()
        .envs(quick_env(&db, &ks))
        .env("KPRUN_LOG", log.to_str().unwrap())
        .args(["reveal-master"])
        .assert()
        .success()
        .stderr(predicates::str::contains(
            "WARNING: secret values are displayed in the terminal",
        ))
        .get_output()
        .stdout
        .clone();
    let reveal_stdout = String::from_utf8(reveal_out).unwrap();
    assert_eq!(
        reveal_stdout.lines().count(),
        1,
        "stdout must carry only the password line (pipe-friendly)"
    );
    assert_eq!(reveal_stdout.trim_end_matches(['\r', '\n']), password);

    // Audited by command name and db_id only — never the value.
    let log_content = std::fs::read_to_string(&log).unwrap();
    assert!(log_content.contains("reveal-master"));
    assert!(!log_content.contains(password));
}

#[test]
fn reveal_master_without_stored_password_fails_clearly() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let ks = dir.path().join("keystore");
    std::fs::create_dir_all(&ks).unwrap();

    kprun_cmd()
        .envs(quick_env(&db, &ks))
        .args(["reveal-master"])
        .assert()
        .failure()
        .stdout(predicates::str::is_empty())
        .stderr(predicates::str::contains("No master password stored"));
}
