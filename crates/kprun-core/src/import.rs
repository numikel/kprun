use std::collections::HashSet;

use crate::vault::Vault;
use crate::{KprunError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportMode {
    Merge,
    Replace,
}

#[derive(Debug, Clone)]
pub struct ImportEntry {
    pub title: String,
    pub pairs: Vec<(String, String)>,
}

pub fn apply_import(vault: &mut Vault, entries: &[ImportEntry], mode: ImportMode) -> Result<()> {
    if mode == ImportMode::Replace && entries.is_empty() {
        return Err(KprunError::Other(
            "import file contains no entries; refusing to replace vault".into(),
        ));
    }

    if mode == ImportMode::Replace {
        let imported_titles: HashSet<String> = entries.iter().map(|e| e.title.clone()).collect();
        for summary in vault.list_entries() {
            if !imported_titles.contains(&summary.title) {
                vault.delete_entry(&summary.title)?;
            }
        }
    }

    for entry in entries {
        if mode == ImportMode::Replace {
            if let Ok(id) = vault.find_entry_by_title(&entry.title) {
                let existing = vault.entry_custom_keys(id);
                let imported_keys: HashSet<&str> =
                    entry.pairs.iter().map(|(k, _)| k.as_str()).collect();
                let to_remove: Vec<String> = existing
                    .into_iter()
                    .filter(|k| !imported_keys.contains(k.as_str()))
                    .collect();
                if !to_remove.is_empty() {
                    vault.unset_attributes(&entry.title, &to_remove)?;
                }
            }
        }
        vault.set_attributes(&entry.title, &entry.pairs)?;
    }

    Ok(())
}
