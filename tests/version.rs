use assert_cmd::Command;

#[test]
fn prints_version() {
    Command::cargo_bin("kprun")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains("0.2.1"));
}
