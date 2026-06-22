use kprun_core::vault::OpenMode;
use kprun_core::Result;
use serde::Serialize;

use super::unlock_vault;

#[derive(Serialize)]
struct ListEntry<'a> {
    title: &'a str,
    keys: &'a [String],
}

pub fn execute(json: bool) -> i32 {
    match run(json) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn run(json: bool) -> Result<()> {
    let (_cfg, _ctx, vault) = unlock_vault(OpenMode::ReadOnly)?;
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
    } else {
        println!("{:<20} {}", "TITLE", "KEYS");
        for e in &entries {
            println!("{:<20} {}", e.title, e.keys.join(", "));
        }
    }

    Ok(())
}
