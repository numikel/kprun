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
