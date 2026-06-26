use kprun_core::vault::OpenMode;
use kprun_core::Result;
use serde::Serialize;

use crate::ui;

use super::{run_command, unlock_vault};

#[derive(Serialize)]
struct ListEntry<'a> {
    title: &'a str,
    keys: &'a [String],
}

pub fn execute(json: bool) -> i32 {
    run_command(|| run(json))
}

fn run(json: bool) -> Result<()> {
    if !json {
        ui::maybe_banner();
    }
    let (_cfg, vault, _db_key) = unlock_vault(OpenMode::ReadOnly)?;
    let entries = vault.list_entries();

    if json {
        let payload: Vec<ListEntry<'_>> = entries
            .iter()
            .map(|e| ListEntry {
                title: &e.title,
                keys: &e.keys,
            })
            .collect();
        println!("{}", serde_json::to_string(&payload)?);
    } else if entries.is_empty() {
        ui::hint("No entries yet. Add secrets with: kprun set <entry> KEY=val ...");
    } else {
        println!("{:<20} KEYS", "TITLE");
        for e in &entries {
            println!("{:<20} {}", e.title, e.keys.join(", "));
        }
    }

    Ok(())
}
