//! `kprun agents` — install a secrets policy for coding agents.
//! This branch never unlocks the vault.

use kprun_core::Result;

use super::run_command;

pub(crate) mod policy;

#[derive(clap::Subcommand)]
pub(crate) enum AgentsAction {
    /// Print the canonical policy block to stdout
    Print,
}

pub(crate) fn execute(action: AgentsAction) -> i32 {
    run_command(|| match action {
        AgentsAction::Print => print(),
    })
}

fn print() -> Result<()> {
    // Plain markdown on stdout, no decoration: stdout = machine data.
    print!("{}", policy::POLICY_BLOCK);
    Ok(())
}
