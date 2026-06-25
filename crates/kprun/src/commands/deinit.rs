use kprun_core::config::Config;
use kprun_core::unlock::delete_master_from_keystore;
use kprun_core::Result;

use crate::ui;

use super::run_command;

pub fn execute() -> i32 {
    run_command(run)
}

fn run() -> Result<()> {
    ui::maybe_banner();
    let cfg = Config::from_env();
    delete_master_from_keystore(&cfg.db_path)?;
    ui::success(&format!(
        "Removed stored master password for {} from keychain",
        cfg.db_path.display()
    ));
    Ok(())
}
