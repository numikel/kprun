use kprun_core::parse::parse_key_vals;
use kprun_core::vault::OpenMode;
use kprun_core::Result;

use crate::ui;

use super::{run_command, unlock_vault};

pub fn execute(entry: String, pairs: Vec<String>) -> i32 {
    run_command(|| run(&entry, &pairs))
}

fn run(entry: &str, pair_args: &[String]) -> Result<()> {
    ui::maybe_banner();
    let items: Vec<&str> = pair_args.iter().map(String::as_str).collect();
    let pairs = parse_key_vals(items)?;
    let key_names: Vec<String> = pairs.iter().map(|(k, _)| k.clone()).collect();
    let (_cfg, _ctx, mut vault, db_key) = unlock_vault(OpenMode::ReadWrite)?;
    vault.set_attributes(entry, &pairs)?;
    vault.save(db_key)?;
    ui::success(&format!(
        "Updated entry '{entry}': {}",
        key_names.join(", ")
    ));
    Ok(())
}
