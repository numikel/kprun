mod common;

use std::path::Path;

use common::{create_vault_with_entries, kprun_cmd, test_env};

fn setup_demo_vault(db: &Path) {
    create_vault_with_entries(db, &[("demo", &[("DEMO_KEY", "secret")])]);
}

#[test]
fn run_injects_env_var() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_demo_vault(&db);

    let child_args: Vec<&str> = if cfg!(windows) {
        vec!["cmd", "/C", "echo", "%DEMO_KEY%"]
    } else {
        vec!["sh", "-c", "echo $DEMO_KEY"]
    };

    let expected_stdout = if cfg!(windows) {
        "secret\r\n"
    } else {
        "secret\n"
    };

    kprun_cmd()
        .envs(test_env(&db))
        .args(["run", "demo", "--"])
        .args(child_args)
        .assert()
        .success()
        .stdout(expected_stdout);
}

/// Everything after `--` must reach the child verbatim, including values
/// that look like kprun/clap flags (`trailing_var_arg` + `allow_hyphen_values`).
#[cfg(unix)]
#[test]
fn run_passes_hyphenated_args_after_double_dash_verbatim() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_demo_vault(&db);

    kprun_cmd()
        .envs(test_env(&db))
        .args([
            "run",
            "demo",
            "--",
            "sh",
            "-c",
            r#"printf '%s|' "$@""#,
            "sh",
        ])
        .args(["--help", "-V", "--clean-env", "a b", "--", "-x"])
        .assert()
        .success()
        .stdout("--help|-V|--clean-env|a b|--|-x|");
}

/// Multiple entries before `--` are all injected.
#[test]
fn run_accepts_multiple_entries_before_double_dash() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    create_vault_with_entries(
        &db,
        &[
            ("one", &[("ONE_KEY", "first")]),
            ("two", &[("TWO_KEY", "second")]),
        ],
    );

    let (child_args, expected): (Vec<&str>, &str) = if cfg!(windows) {
        (
            vec!["cmd", "/C", "echo", "%ONE_KEY%-%TWO_KEY%"],
            "first-second\r\n",
        )
    } else {
        (vec!["sh", "-c", "echo $ONE_KEY-$TWO_KEY"], "first-second\n")
    };

    kprun_cmd()
        .envs(test_env(&db))
        .args(["run", "one", "two", "--"])
        .args(child_args)
        .assert()
        .success()
        .stdout(expected);
}

/// The child's exit status is kprun's exit status.
#[test]
fn run_propagates_child_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_demo_vault(&db);

    let child_args: Vec<&str> = if cfg!(windows) {
        vec!["cmd", "/C", "exit 7"]
    } else {
        vec!["sh", "-c", "exit 7"]
    };

    kprun_cmd()
        .envs(test_env(&db))
        .args(["run", "demo", "--"])
        .args(child_args)
        .assert()
        .code(7);
}

/// A command token that looks like a flag (`--version`) is still the child
/// program, not a kprun option: clap must not intercept it after `--`.
#[test]
fn run_treats_flag_like_command_after_double_dash_as_program() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_demo_vault(&db);

    kprun_cmd()
        .envs(test_env(&db))
        .args(["run", "demo", "--", "--version"])
        .assert()
        .code(1)
        .stdout("")
        .stderr(predicates::str::starts_with("error: "));
}
