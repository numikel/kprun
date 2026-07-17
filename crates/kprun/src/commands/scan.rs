use crate::scan;
use crate::ui;

/// Own exit-code match instead of `run_command`: scan follows the
/// grep/gitleaks-style contract 0 = clean, 1 = findings, 2 = execution
/// error — a documented departure from the repo's binary 0/1 convention.
pub fn execute(path: Option<String>, _history: bool, _full_history: bool, json: bool) -> i32 {
    if !json {
        ui::maybe_banner();
    }
    let dir = path.unwrap_or_else(|| ".".to_string());
    match scan::run_scan(&dir) {
        Ok(()) => 0,
        Err(msg) => {
            eprintln!("error: {msg}");
            2
        }
    }
}
