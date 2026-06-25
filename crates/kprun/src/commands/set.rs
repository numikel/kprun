use kprun_core::parse::parse_key_vals;
use kprun_core::Result;

use crate::ui;

use super::{mutate_vault, run_command};

pub fn execute(entry: String, pairs: Vec<String>) -> i32 {
    run_command(|| run(&entry, &pairs))
}

fn run(entry: &str, pair_args: &[String]) -> Result<()> {
    ui::maybe_banner();
    let items: Vec<&str> = pair_args.iter().map(String::as_str).collect();
    let pairs = parse_key_vals(items)?;
    let key_names: Vec<String> = pairs.iter().map(|(k, _)| k.clone()).collect();
    mutate_vault(|vault| {
        vault.set_attributes(entry, &pairs)?;
        Ok(())
    })?;
    ui::success(&format!(
        "Updated entry '{entry}': {}",
        key_names.join(", ")
    ));
    Ok(())
}
