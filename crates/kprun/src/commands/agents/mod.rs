//! `kprun agents` — install a secrets policy for coding agents.
//! This branch never unlocks the vault.

use std::path::{Path, PathBuf};

use kprun_core::Result;

use crate::ui;

use super::run_command;

pub(crate) mod policy;
pub(crate) mod targets;

use policy::WriteOutcome;
use targets::Target;

#[derive(clap::Subcommand)]
pub(crate) enum AgentsAction {
    /// Print the canonical policy block to stdout
    Print,
    /// Install the policy block into agent instruction files
    Install {
        /// Target directory for repo-level install (default: current directory)
        #[arg(long, conflicts_with = "global")]
        path: Option<String>,
        /// Write the global instruction files of installed agents instead of repo files
        #[arg(short = 'g', long)]
        global: bool,
        /// Comma-separated tools to install for, skipping auto-detection (requires -g)
        #[arg(long, value_delimiter = ',', requires = "global")]
        target: Vec<Target>,
    },
}

pub(crate) fn execute(action: AgentsAction) -> i32 {
    run_command(|| match action {
        AgentsAction::Print => print(),
        AgentsAction::Install {
            path,
            global,
            target,
        } => {
            if global {
                install_global(target)
            } else {
                install_repo(path)
            }
        }
    })
}

fn print() -> Result<()> {
    // Plain markdown on stdout, no decoration: stdout = machine data.
    // Write directly instead of `print!`: a closed reader (`agents print |
    // head`) then yields a handled error rather than the panic the print
    // macros raise on a failed stdout write. A broken pipe is a clean exit.
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    match out
        .write_all(policy::POLICY_BLOCK.as_bytes())
        .and_then(|()| out.flush())
    {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(kprun_core::KprunError::Io(e)),
    }
}

/// Repo-level install: `AGENTS.md` for every tool reading the open
/// standard natively, plus a native `CLAUDE.md` with the same full block.
/// Both refresh together so they cannot drift.
fn install_repo(path: Option<String>) -> Result<()> {
    let dir = path
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    for name in ["AGENTS.md", "CLAUDE.md"] {
        let file = dir.join(name);
        let outcome = policy::install_block(&file)?;
        report(&file, outcome);
    }
    Ok(())
}

/// Global install: write the policy block into the global instruction
/// files of detected (or explicitly targeted) agents. One file's failure
/// does not abort the rest; exit is non-zero when anything failed.
fn install_global(explicit: Vec<Target>) -> Result<()> {
    let home = kprun_core::config::home_dir();
    let copilot_home = std::env::var_os("COPILOT_HOME").map(PathBuf::from);
    let auto_detected = explicit.is_empty();
    let tools = if auto_detected {
        targets::detect_installed(&home, copilot_home.as_deref())
    } else {
        explicit
    };

    if auto_detected {
        ui::info(
            "copilot (VS Code): no global file — covered by repo-level AGENTS.md / \
             .github/copilot-instructions.md; global instructions live in VS Code settings",
        );
        if tools.is_empty() {
            ui::info(
                "no supported agents detected in HOME; use --target <tool> to install explicitly",
            );
            return Ok(());
        }
    }

    let mut attempted = 0usize;
    let mut failed = 0usize;
    for tool in tools {
        let Some(file) = targets::target_file(tool, &home, copilot_home.as_deref()) else {
            ui::info("cursor: global rules are GUI-only; repo-level AGENTS.md covers Cursor");
            continue;
        };
        attempted += 1;
        match policy::install_block(&file) {
            Ok(outcome) => {
                report(&file, outcome);
                if tool == Target::Windsurf {
                    warn_windsurf_limit(&file);
                }
            }
            Err(e) => {
                failed += 1;
                ui::info(&format!("error: {e}"));
            }
        }
    }
    if failed > 0 {
        return Err(kprun_core::KprunError::Other(format!(
            "{failed} of {attempted} global installs failed"
        )));
    }
    Ok(())
}

/// Windsurf reads a single always-on global rules file capped at 6,000
/// characters; warn when the freshly written file exceeds it (Windsurf
/// may ignore the overflow) but never refuse the write.
const WINDSURF_CHAR_LIMIT: usize = 6_000;

fn warn_windsurf_limit(file: &Path) {
    let Ok(content) = std::fs::read_to_string(file) else {
        return;
    };
    if content.chars().count() > WINDSURF_CHAR_LIMIT {
        ui::info(&format!(
            "warning: {} exceeds Windsurf's 6,000-character global rules limit; \
             Windsurf may ignore content beyond the limit",
            file.display()
        ));
    }
}

fn report(file: &Path, outcome: WriteOutcome) {
    match outcome {
        WriteOutcome::Created => ui::success(&format!("{}: created", file.display())),
        WriteOutcome::Updated => ui::success(&format!("{}: updated", file.display())),
        WriteOutcome::Unchanged => ui::info(&format!("{}: unchanged", file.display())),
    }
}
