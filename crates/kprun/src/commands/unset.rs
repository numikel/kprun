use kprun_core::vault::OpenMode;
use kprun_core::Result;

use crate::ui;

use super::unlock_vault;

pub fn execute(entry: String, keys: Vec<String>) -> i32 {
    match run(&entry, &keys) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn run(entry: &str, keys: &[String]) -> Result<()> {
    ui::maybe_banner();
    let (_cfg, _ctx, mut vault, db_key) = unlock_vault(OpenMode::ReadWrite)?;
    vault.unset_attributes(entry, keys)?;
    vault.save(db_key)?;
    ui::success(&format!(
        "Removed from entry '{entry}': {}",
        keys.join(", ")
    ));
    Ok(())
}
