use kprun_core::vault::OpenMode;
use kprun_core::Result;

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
    let (_cfg, ctx, mut vault) = unlock_vault(OpenMode::ReadWrite)?;
    vault.delete_entry(entry)?;
    vault.save_with_unlock(&ctx)?;
    Ok(())
}
