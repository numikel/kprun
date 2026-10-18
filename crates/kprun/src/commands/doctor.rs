use std::path::{Path, PathBuf};

use clap::ValueEnum;
use kprun_core::config::Config;
use kprun_core::unlock::keystore_has_master;
use kprun_core::Result;
use serde_json::json;

use crate::ui;

use super::{
    agents::{policy, targets},
    run_command, unlock_vault_readonly,
};

pub fn execute(mcp: Option<String>, command: Vec<String>) -> i32 {
    run_command(|| run(mcp, command))
}

fn run(mcp: Option<String>, command: Vec<String>) -> Result<()> {
    if let Some(entry) = mcp {
        print_mcp_fragment(&entry, &command)?;
        return Ok(());
    }

    if !command.is_empty() {
        return Err(kprun_core::KprunError::Other(
            "child command requires --mcp <entry>".into(),
        ));
    }

    print_diagnostics()?;
    Ok(())
}

fn print_diagnostics() -> Result<()> {
    ui::maybe_banner();
    let cfg = Config::from_env();

    if cfg.db_path.exists() {
        println!("vault: ok ({})", cfg.db_path.display());
    } else {
        let name = cfg
            .db_path
            .file_name()
            .map(|f| f.to_string_lossy())
            .unwrap_or_else(|| cfg.db_path.to_string_lossy());
        println!("vault: missing ({name})");
        return Err(kprun_core::KprunError::Other(
            "vault database not found".into(),
        ));
    }

    unlock_vault_readonly()?;
    println!("unlock: ok");

    let keystore = if keystore_has_master(&cfg.db_path) {
        "present"
    } else {
        "absent"
    };
    println!("keystore: {keystore}");

    match &cfg.keyfile {
        Some(path) => println!("keyfile: configured ({})", path.display()),
        None => println!("keyfile: not configured"),
    }

    let binary = std::env::current_exe()?;
    println!("binary: {}", binary.display());

    println!("{}", agents_status());

    Ok(())
}

/// The `agents:` status line, from read-only marker checks (same helper the
/// installer uses). Repo level, in cwd: `agents install` writes both
/// AGENTS.md and CLAUDE.md, so either file carrying the block counts.
/// Global: the files `agents install -g` writes, resolved from HOME and
/// COPILOT_HOME like the installer does — every target is checked, not just
/// detected ones, because `--target` installs for undetected tools too.
fn agents_status() -> String {
    let repo: Vec<&str> = ["AGENTS.md", "CLAUDE.md"]
        .into_iter()
        .filter(|name| policy::has_policy_block(Path::new(name)))
        .collect();
    let home = kprun_core::config::home_dir();
    let copilot_home = std::env::var_os("COPILOT_HOME").map(PathBuf::from);
    let global: Vec<String> = targets::ALL_TARGETS
        .into_iter()
        .filter(|tool| {
            targets::target_file(*tool, &home, copilot_home.as_deref())
                .is_some_and(|file| policy::has_policy_block(&file))
        })
        .filter_map(|tool| tool.to_possible_value().map(|v| v.get_name().to_owned()))
        .collect();

    let mut parts = Vec::new();
    if !repo.is_empty() {
        parts.push(repo.join(", "));
    }
    if !global.is_empty() {
        parts.push(format!("global: {}", global.join(", ")));
    }
    if parts.is_empty() {
        "agents: not configured (run: kprun agents install)".into()
    } else {
        format!("agents: policy installed ({})", parts.join("; "))
    }
}

fn print_mcp_fragment(entry: &str, child_command: &[String]) -> Result<()> {
    if entry == "github" && child_command.is_empty() {
        eprintln!(
            "NOTE: npx auto-install without a lockfile is a supply-chain risk; pin the MCP server version in production."
        );
    } else if child_command.is_empty() {
        eprintln!(
            "NOTE: append your MCP server command after `--`, e.g. kprun doctor --mcp {entry} -- npx -y @org/mcp-server"
        );
    }
    let command = mcp_command()?;
    let args = mcp_args(entry, child_command);
    let fragment = json!({
        "command": command,
        "args": args,
    });
    println!("{}", serde_json::to_string_pretty(&fragment)?);
    Ok(())
}

fn mcp_command() -> Result<String> {
    let exe = std::env::current_exe()?;
    if cfg!(windows) {
        return Ok(exe.display().to_string());
    }
    if which::which("kprun").is_ok() {
        return Ok("kprun".into());
    }
    Ok(exe.display().to_string())
}

fn mcp_args(entry: &str, child_command: &[String]) -> Vec<String> {
    let mut args = vec!["run".into(), entry.to_string(), "--".into()];
    if child_command.is_empty() {
        if entry == "github" {
            args.extend([
                "npx".into(),
                "-y".into(),
                "@modelcontextprotocol/server-github@2025.4.8".into(),
            ]);
        }
    } else {
        args.extend(child_command.iter().cloned());
    }
    args
}
