use kprun_core::config::Config;
use kprun_core::unlock::delete_master_from_keystore;

use crate::ui;

pub fn execute() -> i32 {
    ui::maybe_banner();
    let cfg = Config::from_env();
    match delete_master_from_keystore(&cfg.db_path) {
        Ok(()) => {
            ui::success(&format!(
                "Removed stored master password for {} from keychain",
                cfg.db_path.display()
            ));
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}
