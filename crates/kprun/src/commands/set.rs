use kprun_core::parse::parse_key_vals;
use kprun_core::vault::OpenMode;
use kprun_core::Result;

use super::unlock_vault;

pub fn execute(entry: String, pairs: Vec<String>) -> i32 {
    match run(&entry, &pairs) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn run(entry: &str, pair_args: &[String]) -> Result<()> {
    let items: Vec<&str> = pair_args.iter().map(String::as_str).collect();
    let pairs = parse_key_vals(items)?;
    let (_cfg, ctx, mut vault) = unlock_vault(OpenMode::ReadWrite)?;
    vault.set_attributes(entry, &pairs)?;
    vault.save_with_unlock(&ctx)?;
    Ok(())
}
