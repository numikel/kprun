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

// --- CLI surface contract (clap) ---------------------------------------------
//
// Golden `--help` snapshots for every (sub)command plus exit-code and
// argument-passthrough checks. They pin the command-line interface so a clap
// bump cannot silently change flags, help text or parsing behavior.
//
// Regenerate goldens only for an intentional CLI change:
//   KPRUN_UPDATE_HELP_GOLDEN=1 cargo test --test version

use std::path::PathBuf;

const HELP_TARGETS: &[&[&str]] = &[
    &[],
    &["init"],
    &["run"],
    &["list"],
    &["get"],
    &["set"],
    &["unset"],
    &["delete"],
    &["export"],
    &["import"],
    &["migrate"],
    &["doctor"],
    &["mcp"],
    &["reveal-master"],
    &["deinit"],
    &["scan"],
    &["agents"],
    &["agents", "print"],
    &["agents", "install"],
];

fn help_golden_path(target: &[&str]) -> PathBuf {
    let name = if target.is_empty() {
        "kprun".to_string()
    } else {
        format!("kprun-{}", target.join("-"))
    };
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/help")
        .join(format!("{name}.txt"))
}

fn normalize_help(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .replace("\r\n", "\n")
        .replace("kprun.exe", "kprun")
}

#[test]
fn help_output_matches_golden_snapshots() {
    let update = std::env::var_os("KPRUN_UPDATE_HELP_GOLDEN").is_some();
    let mut mismatches = Vec::new();
    for target in HELP_TARGETS {
        let out = Command::cargo_bin("kprun")
            .unwrap()
            .args(*target)
            .arg("--help")
            .env("NO_COLOR", "1")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let actual = normalize_help(&out);
        let path = help_golden_path(target);
        if update {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &actual).unwrap();
            continue;
        }
        let expected = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("missing golden {}: {e}", path.display()))
            .replace("\r\n", "\n");
        if actual != expected {
            mismatches.push(format!(
                "--- {} ---\nexpected:\n{expected}\nactual:\n{actual}",
                path.display()
            ));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[test]
fn usage_errors_exit_with_code_2_on_stderr() {
    let cases: &[(&[&str], &str)] = &[
        (&["--no-such-flag"], "unexpected argument '--no-such-flag'"),
        (
            &["no-such-command"],
            "unrecognized subcommand 'no-such-command'",
        ),
        (
            &["init", "--quick", "--no-store"],
            "the argument '--quick' cannot be used with '--no-store'",
        ),
        (
            &["init", "--force"],
            "the following required arguments were not provided",
        ),
        (
            &["run", "openai"],
            "the following required arguments were not provided",
        ),
        (
            &["export", "--format", "yaml"],
            "invalid value 'yaml' for '--format <FORMAT>'",
        ),
        (
            &["agents", "install", "--path", "x", "-g"],
            "the argument '--path <PATH>' cannot be used with '--global'",
        ),
    ];
    for (args, needle) in cases {
        let assert = Command::cargo_bin("kprun")
            .unwrap()
            .args(*args)
            .env("NO_COLOR", "1")
            .assert()
            .code(2)
            .stdout("");
        let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
        assert!(
            stderr.contains(needle),
            "args {args:?}: expected stderr to contain {needle:?}, got:\n{stderr}"
        );
    }
}
