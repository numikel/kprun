use kprun_core::vault::OpenMode;
use kprun_core::Result;

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
    let (_cfg, ctx, mut vault) = unlock_vault(OpenMode::ReadWrite)?;
    vault.unset_attributes(entry, keys)?;
    vault.save_with_unlock(&ctx)?;
    Ok(())
}
