//! `kprun agents` — install a secrets policy for coding agents.
//! This branch never unlocks the vault.

use std::path::{Path, PathBuf};

use kprun_core::Result;

use crate::ui;

use super::run_command;

pub(crate) mod policy;

use policy::WriteOutcome;

#[derive(clap::Subcommand)]
pub(crate) enum AgentsAction {
    /// Print the canonical policy block to stdout
    Print,
    /// Install the policy block into AGENTS.md and CLAUDE.md
    Install {
        /// Target directory (default: current directory)
        #[arg(long)]
        path: Option<String>,
    },
}

pub(crate) fn execute(action: AgentsAction) -> i32 {
    run_command(|| match action {
        AgentsAction::Print => print(),
        AgentsAction::Install { path } => install_repo(path),
    })
}

fn print() -> Result<()> {
    // Plain markdown on stdout, no decoration: stdout = machine data.
    print!("{}", policy::POLICY_BLOCK);
    Ok(())
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

fn report(file: &Path, outcome: WriteOutcome) {
    match outcome {
        WriteOutcome::Created => ui::success(&format!("{}: created", file.display())),
        WriteOutcome::Updated => ui::success(&format!("{}: updated", file.display())),
        WriteOutcome::Unchanged => ui::info(&format!("{}: unchanged", file.display())),
    }
}
