use kprun_core::vault::OpenMode;
use kprun_core::Result;

use crate::ui;

use super::{run_command, unlock_vault};

pub fn execute(entry: String) -> i32 {
    run_command(|| run(&entry))
}

fn run(entry: &str) -> Result<()> {
    ui::maybe_banner();
    let (_cfg, _ctx, mut vault, db_key) = unlock_vault(OpenMode::ReadWrite)?;
    vault.delete_entry(entry)?;
    vault.save(db_key)?;
    ui::success(&format!("Deleted entry '{entry}'"));
    Ok(())
}
