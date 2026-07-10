//! Minimal scriptable HTTP server for MCP bridge integration tests.
//!
//! Every response carries `Connection: close` — ureq pools keep-alive
//! connections, and this server handles exactly one request per connection.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
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
}

pub struct MockServer {
    addr: SocketAddr,
    pub requests: Arc<Mutex<Vec<MockRequest>>>,
}

impl MockServer {
    pub fn start(handler: impl Fn(&MockRequest) -> MockResponse + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let requests: Arc<Mutex<Vec<MockRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let handler = Arc::new(handler);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let recorded = recorded.clone();
                let handler = handler.clone();
                thread::spawn(move || handle_connection(stream, recorded, handler));
            }
        });
        MockServer { addr, requests }
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
) {
    let Some(request) = read_request(&stream) else {
        return;
    };
    let response = handler(&request);
    recorded.lock().unwrap().push(request);
    write_response(&mut stream, response);
}

fn read_request(stream: &TcpStream) -> Option<MockRequest> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).ok()? == 0 {
        return None;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
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
        reader.read_exact(&mut body).ok()?;
    }
    Some(MockRequest {
        method,
        path,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

fn write_response(stream: &mut TcpStream, response: MockResponse) {
    match response {
        MockResponse::Json {
            status,
            headers,
            body,
        } => {
            let mut head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
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
                format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n");
            for (name, value) in headers {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
            head.push_str("\r\n");
            let _ = stream.write_all(head.as_bytes());
        }
    }
    let _ = stream.flush();
}
