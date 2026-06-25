use assert_cmd::Command;

#[test]
fn prints_version() {
    let expected = env!("CARGO_PKG_VERSION");
    Command::cargo_bin("kprun")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains(expected));
}
