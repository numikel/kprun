mod common;

use std::io::{Read, Write};
use std::net::TcpStream;

use common::mcp_mock::{MockResponse, MockServer};

/// Sanity check of the mock itself (raw TCP client — integration tests
/// cannot use ureq, which is a dependency of the binary, not a dev-dep).
#[test]
fn mock_server_roundtrip() {
    let server = MockServer::start(|req| {
        assert_eq!(req.method, "POST");
        MockResponse::Json {
            status: 200,
            headers: vec![("Mcp-Session-Id".into(), "s1".into())],
            body: r#"{"ok":true}"#.into(),
        }
    });

    let addr = server.url("").strip_prefix("http://").unwrap().to_string();
    let mut sock = TcpStream::connect(addr).unwrap();
    let body = r#"{"jsonrpc":"2.0"}"#;
    write!(
        sock,
        "POST /mcp/ HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer t\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut response = String::new();
    sock.read_to_string(&mut response).unwrap();

    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains("Mcp-Session-Id: s1"));
    assert!(response.ends_with(r#"{"ok":true}"#));

    let requests = server.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/mcp/");
    assert_eq!(
        requests[0].headers.get("authorization").map(String::as_str),
        Some("Bearer t")
    );
    assert_eq!(requests[0].body, body);
}

use std::path::Path;

use common::{create_vault_with_entries, kprun_cmd, test_env};

fn setup_vault(db: &Path) {
    create_vault_with_entries(db, &[("github", &[("TOKEN", "github_pat_test")])]);
}

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
const LIST: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
const NOTIFY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

const INIT_RESULT: &str =
    r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{}}}"#;
const LIST_RESULT: &str = r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}"#;

fn init_response() -> MockResponse {
    MockResponse::Json {
        status: 200,
        headers: vec![("Mcp-Session-Id".into(), "sess-1".into())],
        body: INIT_RESULT.into(),
    }
}

#[test]
fn streamable_json_bridges_frames_and_headers() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_vault(&db);

    let server = MockServer::start(|req| {
        if req.method != "POST" {
            return MockResponse::Empty {
                status: 405,
                headers: vec![],
            };
        }
        if req.body.contains("\"initialize\"") {
            init_response()
        } else {
            MockResponse::Json {
                status: 200,
                headers: vec![],
                body: LIST_RESULT.into(),
            }
        }
    });

    let assert = kprun_cmd()
        .envs(test_env(&db))
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
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines, vec![INIT_RESULT, LIST_RESULT]);

    let requests = server.requests.lock().unwrap();
    // initialize + tools/list (+ best-effort DELETE on shutdown, + a GET
    // stream probe that the mock rejects with 405).
    let posts: Vec<_> = requests.iter().filter(|r| r.method == "POST").collect();
    assert_eq!(posts[0].body, INIT);
    assert_eq!(
        posts[0].headers.get("authorization").map(String::as_str),
        Some("Bearer github_pat_test")
    );
    assert_eq!(
        posts[0].headers.get("accept").map(String::as_str),
        Some("application/json, text/event-stream")
    );
    assert!(!posts[0].headers.contains_key("mcp-session-id"));
    assert_eq!(posts[1].body, LIST);
    assert_eq!(
        posts[1].headers.get("mcp-session-id").map(String::as_str),
        Some("sess-1")
    );
    assert_eq!(
        posts[1]
            .headers
            .get("mcp-protocol-version")
            .map(String::as_str),
        Some("2025-06-18")
    );
}

#[test]
fn streamable_sse_response_forwards_all_events() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_vault(&db);

    let server = MockServer::start(|req| {
        if req.method != "POST" {
            return MockResponse::Empty {
                status: 405,
                headers: vec![],
            };
        }
        if req.body.contains("\"initialize\"") {
            init_response()
        } else {
            MockResponse::Sse {
                status: 200,
                payload: format!(
                    "event: message\ndata: {}\n\nevent: message\ndata: {}\n\n",
                    r#"{"jsonrpc":"2.0","method":"notifications/progress"}"#, LIST_RESULT
                ),
            }
        }
    });

    let assert = kprun_cmd()
        .envs(test_env(&db))
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
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0], INIT_RESULT);
    assert!(lines[1].contains("notifications/progress"));
    assert_eq!(lines[2], LIST_RESULT);
}

#[test]
fn notification_202_writes_nothing_to_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_vault(&db);

    let server = MockServer::start(|req| {
        if req.body.contains("\"initialize\"") {
            init_response()
        } else {
            MockResponse::Empty {
                status: 202,
                headers: vec![],
            }
        }
    });

    let assert = kprun_cmd()
        .envs(test_env(&db))
        .args([
            "mcp",
            "-e",
            "github",
            "--bearer",
            "TOKEN",
            &server.url("/mcp/"),
        ])
        .write_stdin(format!("{INIT}\n{NOTIFY}\n"))
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert_eq!(stdout.lines().collect::<Vec<_>>(), vec![INIT_RESULT]);
}

#[test]
fn unknown_template_field_fails_before_any_request() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_vault(&db);

    let server = MockServer::start(|_| MockResponse::Empty {
        status: 500,
        headers: vec![],
    });

    kprun_cmd()
        .envs(test_env(&db))
        .args([
            "mcp",
            "-e",
            "github",
            "--bearer",
            "NOPE",
            &server.url("/mcp/"),
        ])
        .write_stdin(format!("{INIT}\n"))
        .assert()
        .failure()
        .stdout("")
        .stderr(predicates::str::contains("NOPE"));

    assert!(server.requests.lock().unwrap().is_empty());
}

#[test]
fn audit_log_records_names_and_host_never_values() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let log = dir.path().join("access.log");
    setup_vault(&db);

    let server = MockServer::start(|_| init_response());

    kprun_cmd()
        .envs(test_env(&db))
        .env("KPRUN_LOG", &log)
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
        .success();

    let audit = std::fs::read_to_string(&log).unwrap();
    assert!(audit.contains("github"));
    assert!(audit.contains("Authorization"));
    assert!(audit.contains("127.0.0.1"));
    assert!(!audit.contains("github_pat_test"));
    assert!(!audit.contains("/mcp/"));
}

#[test]
fn session_404_triggers_transparent_reinit_and_retry() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_vault(&db);

    use std::sync::atomic::{AtomicUsize, Ordering};
    let post_count = std::sync::Arc::new(AtomicUsize::new(0));
    let counter = post_count.clone();
    let server = MockServer::start(move |req| {
        if req.method != "POST" {
            return MockResponse::Empty {
                status: 405,
                headers: vec![],
            };
        }
        let n = counter.fetch_add(1, Ordering::SeqCst);
        match n {
            0 => init_response(), // initialize → sess-1
            1 => MockResponse::Empty {
                status: 404,
                headers: vec![],
            }, // session expired
            2 => MockResponse::Json {
                // transparent re-init → sess-2
                status: 200,
                headers: vec![("Mcp-Session-Id".into(), "sess-2".into())],
                body: INIT_RESULT.into(),
            },
            _ => MockResponse::Json {
                // retried tools/list
                status: 200,
                headers: vec![],
                body: LIST_RESULT.into(),
            },
        }
    });

    let assert = kprun_cmd()
        .envs(test_env(&db))
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
    // Exactly two frames: the original init response and the retried list
    // response. The transparent re-init response must NOT be forwarded.
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        vec![INIT_RESULT, LIST_RESULT]
    );

    let requests = server.requests.lock().unwrap();
    let posts: Vec<_> = requests.iter().filter(|r| r.method == "POST").collect();
    assert_eq!(posts.len(), 4);
    assert_eq!(posts[2].body, INIT); // re-init reuses the raw initialize frame
    assert_eq!(posts[3].body, LIST); // then the original frame is retried
    assert_eq!(
        posts[3].headers.get("mcp-session-id").map(String::as_str),
        Some("sess-2")
    );
}

#[test]
fn get_stream_survives_session_reinit() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_vault(&db);

    const SERVER_NOTE: &str = r#"{"jsonrpc":"2.0","method":"notifications/message"}"#;

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let post_count = std::sync::Arc::new(AtomicUsize::new(0));
    let get_count = std::sync::Arc::new(AtomicUsize::new(0));
    let get_sess2_seen = std::sync::Arc::new(AtomicBool::new(false));

    let posts = post_count.clone();
    let gets = get_count.clone();
    let seen = get_sess2_seen.clone();
    let server = MockServer::start(move |req| {
        if req.method == "GET" {
            let n = gets.fetch_add(1, Ordering::SeqCst);
            // Force the very first GET (whatever session id it carries) to
            // look like a stale/unknown session, mirroring the spec's 404
            // behavior for session-carrying requests. Only once the bridge
            // retries with the *current* session id (sess-2, captured after
            // re-init) does the stream succeed.
            if n == 0 {
                return MockResponse::Empty {
                    status: 404,
                    headers: vec![],
                };
            }
            return match req.headers.get("mcp-session-id").map(String::as_str) {
                Some("sess-2") => {
                    seen.store(true, Ordering::SeqCst);
                    MockResponse::Sse {
                        status: 200,
                        payload: format!("data: {SERVER_NOTE}\n\n"),
                    }
                }
                _ => MockResponse::Empty {
                    status: 404,
                    headers: vec![],
                },
            };
        }
        if req.method == "DELETE" {
            return MockResponse::Empty {
                status: 200,
                headers: vec![],
            };
        }
        let n = posts.fetch_add(1, Ordering::SeqCst);
        match n {
            0 => init_response(), // initialize -> sess-1
            1 => MockResponse::Empty {
                status: 404,
                headers: vec![],
            }, // tools/list: session expired
            2 => MockResponse::Json {
                // transparent re-init -> sess-2
                status: 200,
                headers: vec![("Mcp-Session-Id".into(), "sess-2".into())],
                body: INIT_RESULT.into(),
            },
            _ => {
                // Retried tools/list. Block the response until the
                // background GET-stream thread has retried with the new
                // session id and received the server-initiated frame —
                // otherwise the main thread races ahead, flips `shutdown`,
                // and the process exits before the GET thread's next
                // reconnect attempt runs.
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while !seen.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                MockResponse::Json {
                    status: 200,
                    headers: vec![],
                    body: LIST_RESULT.into(),
                }
            }
        }
    });

    let assert = kprun_cmd()
        .envs(test_env(&db))
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
    assert!(
        stdout.contains(SERVER_NOTE),
        "server-initiated frame after session re-init never reached stdout: {stdout:?}"
    );
    assert!(stdout.lines().any(|l| l == INIT_RESULT));
    assert!(stdout.lines().any(|l| l == LIST_RESULT));
    assert!(get_sess2_seen.load(Ordering::SeqCst));
}

#[test]
fn sse_error_after_partial_forward_skips_duplicate_error() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_vault(&db);

    let server = MockServer::start(|req| {
        if req.method != "POST" {
            return MockResponse::Empty {
                status: 405,
                headers: vec![],
            };
        }
        if req.body.contains("\"initialize\"") {
            init_response()
        } else {
            // Forward one complete, valid event (the tools/list result),
            // then the connection breaks mid-stream (TCP RST) before any
            // terminating blank line for a would-be next event — a genuine
            // read error, not a clean EOF.
            MockResponse::SseReset {
                status: 200,
                prefix: format!("event: message\ndata: {LIST_RESULT}\n\n"),
            }
        }
    });

    let assert = kprun_cmd()
        .envs(test_env(&db))
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
    let lines: Vec<&str> = stdout.lines().collect();
    // The result was already forwarded when the stream broke; the bridge
    // must NOT also emit a -32603 error for the same request id.
    assert_eq!(
        lines,
        vec![INIT_RESULT, LIST_RESULT],
        "duplicate result+error (or missing result) for id 2: {lines:?}"
    );
}

#[test]
fn failed_request_emits_jsonrpc_error_and_bridge_survives() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_vault(&db);

    let server = MockServer::start(|req| {
        if req.body.contains("\"initialize\"") {
            init_response()
        } else if req.body.contains("tools/list") {
            MockResponse::Empty {
                status: 500,
                headers: vec![],
            }
        } else {
            MockResponse::Json {
                status: 200,
                headers: vec![],
                body: r#"{"jsonrpc":"2.0","id":3,"result":{}}"#.into(),
            }
        }
    });

    let assert = kprun_cmd()
        .envs(test_env(&db))
        .args([
            "mcp",
            "-e",
            "github",
            "--bearer",
            "TOKEN",
            &server.url("/mcp/"),
        ])
        .write_stdin(format!(
            "{INIT}\n{LIST}\n{}\n",
            r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#
        ))
        .assert()
        .success(); // bridge survives the 500

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3);
    let error_frame: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(error_frame["id"], 2);
    assert_eq!(error_frame["error"]["code"], -32603);
    assert!(lines[2].contains("\"id\":3"));
}

#[test]
fn server_get_stream_messages_reach_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_vault(&db);

    const SERVER_NOTE: &str = r#"{"jsonrpc":"2.0","method":"notifications/message"}"#;
    let server = MockServer::start(|req| {
        if req.method == "GET" {
            MockResponse::Sse {
                status: 200,
                payload: format!("data: {SERVER_NOTE}\n\n"),
            }
        } else if req.body.contains("\"initialize\"") {
            init_response()
        } else {
            MockResponse::Json {
                status: 200,
                headers: vec![],
                body: LIST_RESULT.into(),
            }
        }
    });

    let assert = kprun_cmd()
        .envs(test_env(&db))
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
    assert!(stdout.contains(SERVER_NOTE));

    let requests = server.requests.lock().unwrap();
    let get = requests.iter().find(|r| r.method == "GET").unwrap();
    assert_eq!(
        get.headers.get("mcp-session-id").map(String::as_str),
        Some("sess-1")
    );
    assert_eq!(
        get.headers.get("accept").map(String::as_str),
        Some("text/event-stream")
    );
}

#[test]
fn legacy_fallback_on_405_bridges_via_sse() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_vault(&db);

    let server = MockServer::start(|req| {
        match (req.method.as_str(), req.path.as_str()) {
            // Streamable probe: old server answers 405 → fallback.
            ("POST", "/sse") => MockResponse::Empty { status: 405, headers: vec![] },
            // Legacy GET stream: endpoint event, then the init response.
            ("GET", "/sse") => MockResponse::Sse {
                status: 200,
                payload: format!(
                    "event: endpoint\ndata: /messages?sid=legacy-1\n\nevent: message\ndata: {INIT_RESULT}\n\nevent: message\ndata: {LIST_RESULT}\n\n"
                ),
            },
            // Client messages POSTed to the endpoint from the event.
            ("POST", "/messages?sid=legacy-1") => {
                MockResponse::Empty { status: 202, headers: vec![] }
            }
            _ => MockResponse::Empty { status: 500, headers: vec![] },
        }
    });

    let assert = kprun_cmd()
        .envs(test_env(&db))
        .args([
            "mcp",
            "-e",
            "github",
            "--bearer",
            "TOKEN",
            &server.url("/sse"),
        ])
        .write_stdin(format!("{INIT}\n{LIST}\n"))
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert_eq!(
        stdout.lines().collect::<Vec<_>>(),
        vec![INIT_RESULT, LIST_RESULT]
    );

    let requests = server.requests.lock().unwrap();
    let legacy_posts: Vec<_> = requests
        .iter()
        .filter(|r| r.path == "/messages?sid=legacy-1")
        .collect();
    assert_eq!(legacy_posts.len(), 2);
    assert_eq!(legacy_posts[0].body, INIT);
    assert_eq!(
        legacy_posts[0]
            .headers
            .get("authorization")
            .map(String::as_str),
        Some("Bearer github_pat_test")
    );
}

#[test]
fn unauthorized_401_never_falls_back() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_vault(&db);

    let server = MockServer::start(|_| MockResponse::Empty {
        status: 401,
        headers: vec![],
    });

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
        .failure()
        .stdout("")
        .stderr(predicates::str::contains("authentication failed"));

    let requests = server.requests.lock().unwrap();
    assert!(requests.iter().all(|r| r.method == "POST"));
    assert_eq!(requests.len(), 1); // no GET probe, no retry
}

#[test]
fn explicit_transport_sse_skips_streamable_probe() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_vault(&db);

    let server = MockServer::start(|req| match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/sse") => MockResponse::Sse {
            status: 200,
            payload: format!(
                "event: endpoint\ndata: /messages\n\nevent: message\ndata: {INIT_RESULT}\n\n"
            ),
        },
        ("POST", "/messages") => MockResponse::Empty {
            status: 202,
            headers: vec![],
        },
        _ => MockResponse::Empty {
            status: 500,
            headers: vec![],
        },
    });

    kprun_cmd()
        .envs(test_env(&db))
        .args([
            "mcp",
            "-e",
            "github",
            "--bearer",
            "TOKEN",
            "--transport",
            "sse",
            &server.url("/sse"),
        ])
        .write_stdin(format!("{INIT}\n"))
        .assert()
        .success()
        .stdout(format!("{INIT_RESULT}\n"));

    let requests = server.requests.lock().unwrap();
    assert_eq!(requests[0].method, "GET"); // no streamable POST probe
}

#[test]
fn transport_error_never_prints_substituted_url_secret() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_vault(&db);

    // Reserve a port, then drop the listener: connecting is refused, which
    // provokes a transport error after {{TOKEN}} was substituted into the URL.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };

    let assert = kprun_cmd()
        .envs(test_env(&db))
        .args([
            "mcp",
            "-e",
            "github",
            &format!("http://127.0.0.1:{port}/mcp/?key={{{{TOKEN}}}}"),
        ])
        .write_stdin(format!("{INIT}\n"))
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        !stderr.contains("github_pat_test"),
        "substituted secret leaked to stderr: {stderr}"
    );
}

#[test]
fn invalid_resolved_url_error_cites_template_not_secret() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_vault(&db);

    // "{{TOKEN}}" alone resolves to "github_pat_test" — not a valid absolute
    // URL. The error must cite the template, never the resolved value.
    let assert = kprun_cmd()
        .envs(test_env(&db))
        .args(["mcp", "-e", "github", "{{TOKEN}}"])
        .write_stdin(format!("{INIT}\n"))
        .assert()
        .failure()
        .stdout("");

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        !stderr.contains("github_pat_test"),
        "secret on stderr: {stderr}"
    );
    assert!(stderr.contains("{{TOKEN}}"), "template not cited: {stderr}");
}
