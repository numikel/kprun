use assert_cmd::Command;

#[test]
fn init_creates_database() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    Command::cargo_bin("kprun")
        .unwrap()
        .env("KPRUN_DB", db.to_str().unwrap())
        .args(["init", "--no-store", "--db"])
        .arg(&db)
        .write_stdin("test-passphrase\ntest-passphrase\n")
        .assert()
        .success();
    assert!(db.exists());
}
