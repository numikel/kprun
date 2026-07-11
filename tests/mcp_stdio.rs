mod common;

use std::path::Path;

use common::{create_vault_with_entries, kprun_cmd, test_env};

fn setup_demo_vault(db: &Path) {
    create_vault_with_entries(db, &[("demo", &[("DEMO_KEY", "secret")])]);
}

#[test]
fn run_writes_nothing_to_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_demo_vault(&db);

    let expected_stdout = if cfg!(windows) {
        "child\r\n"
    } else {
        "child\n"
    };

    let mut cmd = kprun_cmd();
    cmd.envs(test_env(&db)).args(["run", "demo", "--"]);

    if cfg!(windows) {
        cmd.args(["cmd", "/C", "echo", "child"]);
    } else {
        cmd.args(["echo", "child"]);
    }

    cmd.assert().success().stdout(expected_stdout);
}

use common::create_vault_with_keyfile_entries;
use common::mcp_mock::{MockResponse, MockServer};

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
const LIST: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
const INIT_RESULT: &str =
    r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{}}}"#;
const LIST_RESULT: &str = r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}"#;

fn mock_mcp_server() -> MockServer {
    MockServer::start(|req| {
        if req.method != "POST" {
            return MockResponse::Empty {
                status: 405,
                headers: vec![],
            };
        }
        if req.body.contains("\"initialize\"") {
            MockResponse::Json {
                status: 200,
                headers: vec![("Mcp-Session-Id".into(), "sess-1".into())],
                body: INIT_RESULT.into(),
            }
        } else {
            MockResponse::Json {
                status: 200,
                headers: vec![],
                body: LIST_RESULT.into(),
            }
        }
    })
}

#[test]
fn mcp_unlocks_composite_password_keyfile_vault() {
    // #38 T14b (automated half): a vault keyed with password + keyfile
    // must unlock non-interactively when both components are available
    // (password via unlock hook, keyfile via KPRUN_KEYFILE) and pass the
    // T1 expectations: 2 JSON frames on stdout, exit 0, no prompt.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let kf = dir.path().join("kprun.keyfile");
    create_vault_with_keyfile_entries(&db, &kf, &[("github", &[("TOKEN", "github_pat_test")])]);

    let server = mock_mcp_server();

    let assert = kprun_cmd()
        .envs(test_env(&db))
        .env("KPRUN_KEYFILE", &kf)
        .args([
            "mcp",
            "-e",
            "github",
            "--bearer",
            "TOKEN",
            &server.url("/mcp/"),
        ])
        .write_stdin(format!("{INIT}\n{LIST}\n"))
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        vec![INIT_RESULT, LIST_RESULT]
    );

    // Sanity: the same vault must NOT unlock without the keyfile — proves
    // the key above was genuinely composite, not password-only.
    kprun_cmd()
        .envs(test_env(&db))
        .args([
            "mcp",
            "-e",
            "github",
            "--bearer",
            "TOKEN",
            &server.url("/mcp/"),
        ])
        .write_stdin(format!("{INIT}\n"))
        .assert()
        .failure();
}

#[test]
fn mcp_missing_keyfile_fails_fast_with_clear_error() {
    // #38 failure mode: KPRUN_KEYFILE pointing at a nonexistent file must
    // produce a clear stderr error naming the keyfile — no prompt, no
    // network request, nothing on stdout.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let kf = dir.path().join("kprun.keyfile");
    create_vault_with_keyfile_entries(&db, &kf, &[("github", &[("TOKEN", "github_pat_test")])]);

    let server = mock_mcp_server();
    let missing = dir.path().join("no-such.keyfile");

    kprun_cmd()
        .envs(test_env(&db))
        .env("KPRUN_KEYFILE", &missing)
        .args([
            "mcp",
            "-e",
            "github",
            "--bearer",
            "TOKEN",
            &server.url("/mcp/"),
        ])
        .write_stdin(format!("{INIT}\n"))
        .assert()
        .failure()
        .stdout("")
        .stderr(predicates::str::contains("cannot read keyfile"));

    assert!(
        server.requests.lock().unwrap().is_empty(),
        "unlock failure must happen before any network request"
    );
}
