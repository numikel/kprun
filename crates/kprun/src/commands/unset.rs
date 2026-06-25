use kprun_core::Result;

use crate::ui;

use super::{mutate_vault, run_command};

pub fn execute(entry: String, keys: Vec<String>) -> i32 {
    run_command(|| run(&entry, &keys))
}

fn run(entry: &str, keys: &[String]) -> Result<()> {
    ui::maybe_banner();
    mutate_vault(|vault| {
        vault.unset_attributes(entry, keys)?;
        Ok(())
    })?;
    ui::success(&format!(
        "Removed from entry '{entry}': {}",
        keys.join(", ")
    ));
    Ok(())
}
