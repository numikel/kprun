use kprun_core::parse::{parse_key_val, parse_key_vals};
use kprun_core::Result;

use crate::ui;

use super::{mutate_vault, run_command};

pub fn execute(entry: String, pairs: Vec<String>, stdin: bool) -> i32 {
    run_command(|| run(&entry, &pairs, stdin))
}

fn run(entry: &str, pair_args: &[String], stdin: bool) -> Result<()> {
    ui::maybe_banner();
    let pairs = if stdin {
        read_stdin_pairs()?
    } else {
        let items: Vec<&str> = pair_args.iter().map(String::as_str).collect();
        parse_key_vals(items)?
    };
    let key_names: Vec<String> = pairs.iter().map(|(k, _)| k.clone()).collect();
    mutate_vault(|vault| {
        vault.set_attributes(entry, &pairs)?;
        Ok(())
    })?;
    ui::success(&format!(
        "Updated entry '{entry}': {}",
        key_names.join(", ")
    ));
    Ok(())
}

/// Read KEY=value lines from stdin until EOF. Blank lines and lines starting
/// with `#` are skipped; each remaining line must parse like an argv pair
/// (parse errors deliberately do not echo the offending line — it may hold
/// a secret).
fn read_stdin_pairs() -> Result<Vec<(String, String)>> {
    use std::io::BufRead;
    let stdin = std::io::stdin();
    let mut pairs = Vec::new();
    for line in stdin.lock().lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        pairs.push(parse_key_val(trimmed)?);
    }
    Ok(pairs)
}
