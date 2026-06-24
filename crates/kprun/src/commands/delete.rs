use kprun_core::vault::OpenMode;
use kprun_core::Result;

use crate::ui;

use super::unlock_vault;

pub fn execute(entry: String) -> i32 {
    match run(&entry) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn run(entry: &str) -> Result<()> {
    ui::maybe_banner();
    let (_cfg, _ctx, mut vault, db_key) = unlock_vault(OpenMode::ReadWrite)?;
    vault.delete_entry(entry)?;
    vault.save_with_key(db_key)?;
    ui::success(&format!("Deleted entry '{entry}'"));
    Ok(())
}
