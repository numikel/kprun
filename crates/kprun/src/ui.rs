use std::io::{self, BufRead, IsTerminal, Write};

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

/// Ask a yes/no question on stderr with a `[Y/n]` / `[y/N]` suffix derived
/// from `default`, reading the answer from stdin. Empty input, EOF, and
/// unrecognized input fall back to `default`. Callers are responsible for
/// TTY detection — this always reads.
pub fn confirm(question: &str, default: bool) -> io::Result<bool> {
    confirm_from(&mut io::stdin().lock(), question, default)
}

fn confirm_from<R: BufRead>(reader: &mut R, question: &str, default: bool) -> io::Result<bool> {
    let suffix = if default { "[Y/n]" } else { "[y/N]" };
    eprint!("{question} {suffix} ");
    io::stderr().flush().ok();
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(default); // EOF
    }
    Ok(match line.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => true,
        "n" | "no" => false,
        _ => default,
    })
}

#[cfg(test)]
mod tests {
    use super::confirm_from;

    #[test]
    fn accepts_yes_variants_case_insensitive() {
        assert!(confirm_from(&mut "y\n".as_bytes(), "Q?", false).unwrap());
        assert!(confirm_from(&mut "YES\n".as_bytes(), "Q?", false).unwrap());
    }

    #[test]
    fn accepts_no_variants_case_insensitive() {
        assert!(!confirm_from(&mut "n\n".as_bytes(), "Q?", true).unwrap());
        assert!(!confirm_from(&mut "No\n".as_bytes(), "Q?", true).unwrap());
    }

    #[test]
    fn empty_line_returns_default() {
        assert!(confirm_from(&mut "\n".as_bytes(), "Q?", true).unwrap());
        assert!(!confirm_from(&mut "\n".as_bytes(), "Q?", false).unwrap());
    }

    #[test]
    fn garbage_input_returns_default() {
        assert!(confirm_from(&mut "banana\n".as_bytes(), "Q?", true).unwrap());
        assert!(!confirm_from(&mut "banana\n".as_bytes(), "Q?", false).unwrap());
    }

    #[test]
    fn eof_returns_default() {
        assert!(confirm_from(&mut "".as_bytes(), "Q?", true).unwrap());
        assert!(!confirm_from(&mut "".as_bytes(), "Q?", false).unwrap());
    }
}
