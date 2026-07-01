use crate::cli::McpTransport;

pub fn execute(
    _entry: String,
    _headers: Vec<String>,
    _bearer: Option<String>,
    _transport: McpTransport,
    _timeout: u64,
    _url: String,
) -> i32 {
    eprintln!("error: kprun mcp is not implemented yet");
    1
}
