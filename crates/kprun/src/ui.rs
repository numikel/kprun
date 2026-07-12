use std::io::{self, IsTerminal};

/// Whether decorative CLI output (banner, steps) should be shown.
pub fn is_interactive() -> bool {
    io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

/// Print the ASCII banner when running in an interactive terminal.
pub fn maybe_banner() {
    if is_interactive() {
        print_banner();
    }
}

fn print_banner() {
    let version = env!("CARGO_PKG_VERSION");
    eprintln!(
        r"
  _  __  ____  ____  _   _ _   _
 | |/ / |  _ \|  _ \| | | | \ | |
 | ' /  | |_) | |_) | | | |  \| |
 | . \  |  __/|  _ <| |_| | |\  |
 |_|\_\ |_|   |_| \_\\___/|_| \_|

 local secrets injector · v{version}
"
    );
}

/// Progress step for multi-stage commands (init).
pub fn step(current: u32, total: u32, message: &str) {
    if is_interactive() {
        eprintln!("[{current}/{total}] {message}");
    } else {
        eprintln!("{message}");
    }
}

/// Success confirmation on stderr (never prints secret values).
pub fn success(message: &str) {
    if is_interactive() {
        eprintln!("✓ {message}");
    } else {
        eprintln!("{message}");
    }
}

/// Informational message on stderr.
pub fn info(message: &str) {
    eprintln!("{message}");
}

/// Short hint for non-interactive or supplemental guidance.
pub fn hint(message: &str) {
    eprintln!("hint: {message}");
}

/// Print a one-time credential on stdout with stderr spacing when interactive.
/// Stdout stays a single line (pipe-safe); bold is used only when stdout is a TTY.
pub fn print_once_stdout(value: &str) {
    if is_interactive() {
        eprintln!();
    }
    if io::stdout().is_terminal() && is_interactive() {
        println!("\x1b[1m{value}\x1b[0m");
    } else {
        println!("{value}");
    }
    if is_interactive() {
        eprintln!();
    }
}

/// Copy-pasteable next steps after setup commands.
pub fn next_steps(lines: &[&str]) {
    if !is_interactive() {
        if let Some(first) = lines.first() {
            hint(first);
        }
        return;
    }
    eprintln!();
    eprintln!("Next steps:");
    for line in lines {
        eprintln!("  {line}");
    }
}
