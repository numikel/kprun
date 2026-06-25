use kprun_core::Result;

use crate::ui;

use super::{mutate_vault, run_command};

pub fn execute(entry: String) -> i32 {
    run_command(|| run(&entry))
}

fn run(entry: &str) -> Result<()> {
    ui::maybe_banner();
    mutate_vault(|vault| {
        vault.delete_entry(entry)?;
        Ok(())
    })?;
    ui::success(&format!("Deleted entry '{entry}'"));
    Ok(())
}
