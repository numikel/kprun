//! Minimal scriptable HTTP server for MCP bridge integration tests.
//!
//! By default every response carries `Connection: close` and the server
//! handles exactly one request per connection. `MockServer::start_keep_alive`
//! instead serves `Json`/`Empty` responses with `Connection: keep-alive` and
//! keeps reading requests from the same connection, so ureq's connection
//! pool is exercised the way a real server would.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

pub struct MockRequest {
    pub method: String,
    pub path: String,
    /// Header names lowercased.
    pub headers: HashMap<String, String>,
    pub body: String,
}

pub enum MockResponse {
    Json {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    },
    /// Streams `payload` as `text/event-stream`, then closes the connection.
    Sse { status: u16, payload: String },
    /// Streams `prefix` as `text/event-stream`, then writes a couple of
    /// invalid-UTF-8 bytes with no terminating newline before closing.
    /// `BufRead::read_line` surfaces that as a genuine `io::Error`
    /// (`InvalidData`) on the client's next read — simulating a connection
    /// that breaks mid-stream, as opposed to a graceful EOF (which the SSE
    /// parser treats as a normal, silent end of stream).
    SseReset { status: u16, prefix: String },
    /// Streams SSE chunks with a delay before each chunk, then closes.
    /// Exercises response bodies that outlive the per-request timeout.
    SseDelayed {
        status: u16,
        chunks: Vec<(std::time::Duration, String)>,
    },
    Empty {
        status: u16,
        headers: Vec<(String, String)>,
    },
    /// Sleeps for `delay` before writing anything (no status line, no
    /// headers), then sends `then`. Exercises header timeouts.
    Delayed {
        delay: std::time::Duration,
        then: Box<MockResponse>,
    },
    /// `text/event-stream` body using `Transfer-Encoding: chunked`, one HTTP
    /// chunk per element (chunk boundaries may split SSE lines/events).
    SseChunked { status: u16, chunks: Vec<String> },
}

pub struct MockServer {
    addr: SocketAddr,
    pub requests: Arc<Mutex<Vec<MockRequest>>>,
    /// Number of TCP connections accepted so far.
    pub connections: Arc<AtomicUsize>,
}

impl MockServer {
    pub fn start(handler: impl Fn(&MockRequest) -> MockResponse + Send + Sync + 'static) -> Self {
        Self::start_inner(handler, false)
    }

    /// Like `start`, but `Json`/`Empty` responses keep the connection open
    /// for further requests (HTTP/1.1 keep-alive).
    pub fn start_keep_alive(
        handler: impl Fn(&MockRequest) -> MockResponse + Send + Sync + 'static,
    ) -> Self {
        Self::start_inner(handler, true)
    }

    pub fn connection_count(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn start_inner(
        handler: impl Fn(&MockRequest) -> MockResponse + Send + Sync + 'static,
        keep_alive: bool,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let requests: Arc<Mutex<Vec<MockRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let connections = Arc::new(AtomicUsize::new(0));
        let accepted = connections.clone();
        let handler = Arc::new(handler);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let stream = match stream {
                    Ok(stream) => stream,
                    // A pending connection reset/aborted before `accept()`
                    // finished (observed as WSAECONNRESET on Windows) is a
                    // property of that one connection attempt, not of the
                    // listener — skip it and keep serving instead of
                    // tearing down the whole mock server mid-test.
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                        ) =>
                    {
                        continue;
                    }
                    Err(_) => break,
                };
                accepted.fetch_add(1, Ordering::SeqCst);
                let recorded = recorded.clone();
                let handler = handler.clone();
                thread::spawn(move || handle_connection(stream, recorded, handler, keep_alive));
            }
        });
        MockServer {
            addr,
            requests,
            connections,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

type Handler = dyn Fn(&MockRequest) -> MockResponse + Send + Sync;

fn handle_connection(
    mut stream: TcpStream,
    recorded: Arc<Mutex<Vec<MockRequest>>>,
    handler: Arc<Handler>,
    keep_alive: bool,
) {
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    // One reader per connection: with keep-alive, bytes of the next request
    // may already sit in its buffer.
    let mut reader = BufReader::new(read_half);
    loop {
        let Some(request) = read_request(&mut reader) else {
            return;
        };
        let response = handler(&request);
        recorded.lock().unwrap().push(request);
        let reusable = keep_alive
            && matches!(
                response,
                MockResponse::Json { .. } | MockResponse::Empty { .. }
            );
        write_response(&mut stream, response, reusable);
        if !reusable {
            return;
        }
    }
}

/// Reads one line. A reset/aborted connection — the client closing
/// mid-request, observed as `io::ErrorKind::ConnectionReset` /
/// `ConnectionAborted` (WSAECONNRESET on Windows) — is treated the same as
/// a clean EOF: no request here, not a bug to unwrap/panic on. Any other
/// read error gets the same treatment for this one-shot mock.
fn read_line_or_eof(reader: &mut BufReader<TcpStream>, buf: &mut String) -> Option<usize> {
    reader.read_line(buf).ok()
}

fn read_request(reader: &mut BufReader<TcpStream>) -> Option<MockRequest> {
    let mut request_line = String::new();
    if read_line_or_eof(reader, &mut request_line)? == 0 {
        return None;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        if read_line_or_eof(reader, &mut line)? == 0 {
            return None;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    if length > 0 {
        // Same treatment as read_line_or_eof for a reset mid-body
        // (ConnectionReset / ConnectionAborted, or any other read error):
        // end the request quietly rather than unwrapping/panicking.
        reader.read_exact(&mut body).ok()?;
    }
    Some(MockRequest {
        method,
        path,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

fn write_response(stream: &mut TcpStream, response: MockResponse, keep_alive: bool) {
    let connection = if keep_alive { "keep-alive" } else { "close" };
    match response {
        MockResponse::Json {
            status,
            headers,
            body,
        } => {
            let mut head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {connection}\r\n",
                body.len()
            );
            for (name, value) in headers {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
            head.push_str("\r\n");
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body.as_bytes());
        }
        MockResponse::Sse { status, payload } => {
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(payload.as_bytes());
            let _ = stream.flush();
        }
        MockResponse::SseReset { status, prefix } => {
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(prefix.as_bytes());
            // Invalid UTF-8, no terminating newline: forces a genuine
            // read error rather than a clean EOF once the connection closes.
            let _ = stream.write_all(&[0xFF, 0xFE]);
            let _ = stream.flush();
        }
        MockResponse::SseDelayed { status, chunks } => {
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.flush();
            for (delay, chunk) in chunks {
                thread::sleep(delay);
                let _ = stream.write_all(chunk.as_bytes());
                let _ = stream.flush();
            }
        }
        MockResponse::Empty { status, headers } => {
            let mut head =
                format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: {connection}\r\n");
            for (name, value) in headers {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
            head.push_str("\r\n");
            let _ = stream.write_all(head.as_bytes());
        }
        MockResponse::Delayed { delay, then } => {
            thread::sleep(delay);
            write_response(stream, *then, false);
        }
        MockResponse::SseChunked { status, chunks } => {
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.flush();
            for chunk in chunks {
                let _ = write!(stream, "{:x}\r\n{chunk}\r\n", chunk.len());
                let _ = stream.flush();
            }
            let _ = stream.write_all(b"0\r\n\r\n");
        }
    }
    let _ = stream.flush();
}
