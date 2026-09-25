//! KeePassXC compatibility: verifies kprun can open a database created in KeePassXC.
//!
//! ## Manual fixture workflow
//!
//! 1. In KeePassXC, create `tests/fixtures/keepassxc.kdbx` (gitignored; not committed).
//! 2. Add an entry with title `fixture` and a custom attribute `FIXTURE_KEY` (any non-empty value).
//! 3. Export or save the database. Note the master password.
//! 4. Run the test locally:
//!
//! ```bash
//! export KPRUN_KEEPASSXC_FIXTURE=1
//! export KPRUN_TEST_MASTER='your-master-password'
//! cargo test reads_keepassxc_fixture -- --ignored
//! ```
//!
//! CI skips this test by default (`#[ignore]`). Set `KPRUN_KEEPASSXC_FIXTURE` when running
//! with `--ignored` in pipelines that provide the fixture.

mod common;

use std::path::PathBuf;

use kprun_core::unlock::{build_database_key, UnlockContext};
use kprun_core::vault::{open_vault, OpenMode};

#[test]
#[ignore = "requires tests/fixtures/keepassxc.kdbx created in KeePassXC"]
fn reads_keepassxc_fixture() {
    if !common::keepassxc_fixture_enabled() {
        panic!(
            "set KPRUN_KEEPASSXC_FIXTURE=1 to run this test (fixture: {})",
            common::keepassxc_fixture_path().display()
        );
    }

    let path = common::keepassxc_fixture_path();
    assert!(
        path.exists(),
        "fixture missing at {}; create it in KeePassXC first",
        path.display()
    );

    let master = common::keepassxc_fixture_password().expect(
        "set KPRUN_TEST_MASTER or KPRUN_KEEPASSXC_PASSWORD for the fixture master password",
    );

    let ctx = UnlockContext {
        keyfile: std::env::var_os("KPRUN_KEYFILE").map(PathBuf::from),
        db_path: path.clone(),
    };
    let key = build_database_key(&ctx, &master).expect("failed to build database key");
    let vault =
        open_vault(&path, key, OpenMode::ReadOnly).expect("failed to open KeePassXC fixture");

    let id = vault
        .find_entry_by_title("fixture")
        .expect("entry 'fixture' not found in KeePassXC database");
    let values = vault.entry_custom_values(id);

    let value = values
        .get("FIXTURE_KEY")
        .expect("custom attribute FIXTURE_KEY not found on entry 'fixture'");
    assert!(!value.is_empty(), "FIXTURE_KEY must be a non-empty string");
}

// --- KDBX format contract (keepass crate) ------------------------------------
//
// `tests/fixtures/golden/kprun-v0.7.1.kdbx` was written by kprun 0.7.1
// (keepass 0.13.20) and is committed on purpose: it is the only way to catch
// a KDBX read/write regression *between* keepass versions. It holds no real
// secrets (master password: `kprun_core::test_support::vault_password()`).
// It contains empty, unicode, multi-line, `=`-containing and padded values,
// plus an entry removed with `kprun delete` (which must stay absent). kprun
// deletes untracked (`EntryMut::remove`), so the file's <DeletedObjects> is
// empty — verified by dumping the fixture's XML with keepass 0.13.20.
//
// Tests always work on a temporary copy; the committed file is never
// modified. Regenerate only deliberately (it pins the *old* writer):
//   cargo test --test keepassxc_compat --features test-hooks \
//     generate_golden_fixture -- --ignored

use std::path::Path;

use common::{create_vault_with_entries, create_vault_with_keyfile_entries, kprun_cmd, test_env};

const GOLDEN_ALPHA: &[(&str, &str)] = &[
    ("EMPTY", ""),
    ("UNICODE", "zażółć gęślą jaźń — 🔑"),
    ("MULTI", "line1\nline2\r\nline3"),
    ("EQUALS", "a=b==c"),
    ("PADDED", "  padded value  "),
];
const GOLDEN_BETA: &[(&str, &str)] = &[("TOKEN", "beta-token-123")];

fn golden_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/golden/kprun-v0.7.1.kdbx")
}

fn golden_copy(dir: &Path) -> PathBuf {
    let copy = dir.join("golden-copy.kdbx");
    std::fs::copy(golden_fixture_path(), &copy).expect("golden fixture missing");
    copy
}

fn expected_export(entries: &[(&str, &[(&str, &str)])]) -> serde_json::Value {
    let mut entries: Vec<_> = entries
        .iter()
        .map(|(title, pairs)| {
            let keys: serde_json::Map<String, serde_json::Value> = pairs
                .iter()
                .map(|(k, v)| (k.to_string(), serde_json::Value::from(*v)))
                .collect();
            serde_json::json!({ "title": title, "keys": keys })
        })
        .collect();
    entries.sort_by(|a, b| a["title"].as_str().cmp(&b["title"].as_str()));
    serde_json::json!({ "entries": entries })
}

fn export_all(db: &Path) -> serde_json::Value {
    let out = kprun_cmd()
        .envs(test_env(db))
        .args(["export", "--stdout", "--reveal"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let mut value: serde_json::Value = serde_json::from_slice(&out).unwrap();
    value["entries"]
        .as_array_mut()
        .unwrap()
        .sort_by(|a, b| a["title"].as_str().cmp(&b["title"].as_str()));
    value
}

#[test]
#[ignore = "regenerates the committed golden fixture; run deliberately"]
fn generate_golden_fixture() {
    let path = golden_fixture_path();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let _ = std::fs::remove_file(&path);
    create_vault_with_entries(
        &path,
        &[
            ("alpha", GOLDEN_ALPHA),
            ("beta", GOLDEN_BETA),
            ("gone", &[("GONE_KEY", "deleted")]),
        ],
    );
    kprun_cmd()
        .envs(test_env(&path))
        .args(["delete", "gone"])
        .assert()
        .success();
}

#[test]
fn reads_golden_fixture_written_by_kprun_0_7_1() {
    let dir = tempfile::tempdir().unwrap();
    let db = golden_copy(dir.path());

    assert_eq!(
        export_all(&db),
        expected_export(&[("alpha", GOLDEN_ALPHA), ("beta", GOLDEN_BETA)]),
        "values read from the kprun 0.7.1 vault changed"
    );
}

#[test]
fn golden_fixture_injects_exact_values_into_child() {
    let dir = tempfile::tempdir().unwrap();
    let db = golden_copy(dir.path());

    let (args, expected): (Vec<&str>, &str) = if cfg!(windows) {
        (vec!["cmd", "/C", "echo", "%TOKEN%"], "beta-token-123\r\n")
    } else {
        (vec!["sh", "-c", "echo \"$TOKEN\""], "beta-token-123\n")
    };
    kprun_cmd()
        .envs(test_env(&db))
        .args(["run", "beta", "--"])
        .args(args)
        .assert()
        .success()
        .stdout(expected);
}

#[test]
fn golden_fixture_survives_modify_save_reload_with_current_writer() {
    let dir = tempfile::tempdir().unwrap();
    let db = golden_copy(dir.path());

    kprun_cmd()
        .envs(test_env(&db))
        .args(["set", "beta", "ADDED=new value"])
        .assert()
        .success();
    kprun_cmd()
        .envs(test_env(&db))
        .args(["unset", "alpha", "PADDED"])
        .assert()
        .success();
    kprun_cmd()
        .envs(test_env(&db))
        .args(["set", "gamma", "G=1"])
        .assert()
        .success();
    kprun_cmd()
        .envs(test_env(&db))
        .args(["delete", "gamma"])
        .assert()
        .success();

    let alpha: Vec<(&str, &str)> = GOLDEN_ALPHA
        .iter()
        .copied()
        .filter(|(k, _)| *k != "PADDED")
        .collect();
    let beta: Vec<(&str, &str)> = GOLDEN_BETA
        .iter()
        .copied()
        .chain([("ADDED", "new value")])
        .collect();
    assert_eq!(
        export_all(&db),
        expected_export(&[("alpha", &alpha), ("beta", &beta)])
    );
}

#[test]
fn wrong_master_password_is_rejected_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let db = golden_copy(dir.path());

    kprun_cmd()
        .env("KPRUN_DB", &db)
        .env("KPRUN_TEST_MASTER", "not-the-password")
        .args(["list"])
        .assert()
        .code(1)
        .stdout("")
        .stderr("error: failed to open vault: Incorrect key\n");
}

#[test]
fn truncated_vault_is_rejected_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let db = golden_copy(dir.path());
    let bytes = std::fs::read(&db).unwrap();
    std::fs::write(&db, &bytes[..300]).unwrap();

    kprun_cmd()
        .envs(test_env(&db))
        .args(["list"])
        .assert()
        .code(1)
        .stdout("")
        .stderr("error: failed to open vault: Unexpected end of file\n");
}

#[test]
fn password_plus_keyfile_vault_requires_both() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let keyfile = dir.path().join("vault.keyfile");
    create_vault_with_keyfile_entries(&db, &keyfile, &[("kf", &[("KF_KEY", "kf-value")])]);

    kprun_cmd()
        .envs(test_env(&db))
        .env("KPRUN_KEYFILE", &keyfile)
        .args(["export", "--stdout", "--reveal"])
        .assert()
        .success()
        .stdout(predicates::str::contains("kf-value"));

    kprun_cmd()
        .envs(test_env(&db))
        .env_remove("KPRUN_KEYFILE")
        .args(["list"])
        .assert()
        .code(1)
        .stdout("")
        .stderr("error: failed to open vault: Incorrect key\n");
}
