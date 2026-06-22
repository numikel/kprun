use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};

use keepass::db::{fields, EntryId, EntryRef};
use keepass::Database;

use crate::{KprunError, Result};

const STANDARD_FIELDS: &[&str] = &[
    "Title", "UserName", "Password", "URL", "Notes", "Expires",
    "Created", "LastAccess", "LastModification", "Tags",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone)]
pub struct EntrySummary {
    pub title: String,
    pub keys: Vec<String>,
}

pub struct Vault {
    db: Database,
    path: PathBuf,
    mode: OpenMode,
}

impl Vault {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn database(&self) -> &Database {
        &self.db
    }

    pub fn database_mut(&mut self) -> &mut Database {
        &mut self.db
    }
}

pub fn open_vault(path: &Path, key: keepass::DatabaseKey, mode: OpenMode) -> Result<Vault> {
    if !path.exists() {
        return Err(KprunError::DatabaseNotFound(path.to_path_buf()));
    }
    let mut file = File::open(path)?;
    let db = Database::open(&mut file, key)?;
    Ok(Vault {
        db,
        path: path.to_path_buf(),
        mode,
    })
}

pub fn create_vault(path: &Path, key: keepass::DatabaseKey, db_name: &str) -> Result<()> {
    if path.exists() {
        return Err(KprunError::Other(format!(
            "database already exists: {}",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut db = Database::new();
    db.meta.database_name = Some(db_name.to_string());
    let mut file = File::create(path)?;
    db.save(&mut file, key).map_err(map_save_error)
}

impl Vault {
    pub fn find_entry_by_title(&self, title: &str) -> Result<EntryId> {
        let title_lower = title.to_ascii_lowercase();
        for entry in self.db.iter_all_entries() {
            if entry
                .get_title()
                .map(|t| t.to_ascii_lowercase() == title_lower)
                .unwrap_or(false)
            {
                return Ok(entry.id());
            }
        }
        Err(KprunError::EntryNotFound(title.to_string()))
    }

    pub fn list_entries(&self) -> Vec<EntrySummary> {
        self.db
            .iter_all_entries()
            .filter_map(|e| {
                let title = e.get_title()?.to_string();
                let keys = custom_field_names(&e);
                Some(EntrySummary { title, keys })
            })
            .collect()
    }

    pub fn entry_custom_keys(&self, id: EntryId) -> Vec<String> {
        self.db
            .entry(id)
            .map(|e| custom_field_names(&e))
            .unwrap_or_default()
    }

    pub fn entry_custom_values(&self, id: EntryId) -> HashMap<String, String> {
        self.db
            .entry(id)
            .map(|e| custom_fields(&e))
            .unwrap_or_default()
    }

    pub fn set_attributes(&mut self, title: &str, pairs: &[(String, String)]) -> Result<()> {
        let mode_check = self.mode == OpenMode::ReadWrite;
        if !mode_check {
            return Err(KprunError::Other("vault opened read-only".into()));
        }
        let title_owned = title.to_string();
        let result = self.find_entry_by_title(&title_owned);
        match result {
            Ok(id) => {
                if let Some(mut entry) = self.db.entry_mut(id) {
                    for (k, v) in pairs {
                        entry.set_unprotected(k.clone(), v.clone());
                    }
                }
                Ok(())
            }
            Err(KprunError::EntryNotFound(_)) => {
                self.db.root_mut().add_entry().edit(|e| {
                    e.set_unprotected(fields::TITLE, title_owned);
                    for (k, v) in pairs {
                        e.set_unprotected(k.clone(), v.clone());
                    }
                });
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn unset_attributes(&mut self, title: &str, keys: &[String]) -> Result<()> {
        let id = self.find_entry_by_title(title)?;
        if let Some(mut entry) = self.db.entry_mut(id) {
            for k in keys {
                entry.fields.remove(k);
            }
        }
        Ok(())
    }

    pub fn delete_entry(&mut self, title: &str) -> Result<()> {
        let id = self.find_entry_by_title(title)?;
        if let Some(entry) = self.db.entry_mut(id) {
            entry.remove();
            Ok(())
        } else {
            Err(KprunError::EntryNotFound(title.to_string()))
        }
    }

    pub fn save(&mut self, key: keepass::DatabaseKey) -> Result<()> {
        let mut tmp = tempfile::NamedTempFile::new_in(
            self.path.parent().unwrap_or_else(|| Path::new(".")),
        )?;
        self.db
            .save(tmp.as_file_mut(), key)
            .map_err(map_save_error)?;
        tmp.persist(&self.path).map_err(|e| KprunError::Io(e.error))?;
        Ok(())
    }
}

fn is_standard_field(name: &str) -> bool {
    STANDARD_FIELDS
        .iter()
        .any(|f| f.eq_ignore_ascii_case(name))
}

fn custom_field_names(entry: &EntryRef<'_>) -> Vec<String> {
    entry
        .fields
        .keys()
        .filter(|k| !is_standard_field(k))
        .cloned()
        .collect()
}

fn custom_fields(entry: &EntryRef<'_>) -> HashMap<String, String> {
    entry
        .fields
        .keys()
        .filter(|k| !is_standard_field(k))
        .filter_map(|k| entry.get(k).map(|val| (k.clone(), val.to_string())))
        .collect()
}

fn map_save_error(e: impl std::fmt::Display) -> KprunError {
    let msg = e.to_string();
    if msg.to_lowercase().contains("lock") {
        KprunError::DatabaseLocked
    } else {
        KprunError::Other(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unlock::{build_database_key, UnlockContext};
    use keepass::db::fields;
    use tempfile::tempdir;

    fn create_test_vault(path: &Path, password: &str) -> Result<()> {
        use keepass::Database;
        let mut db = Database::new();
        db.root_mut().add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "github");
            e.set_unprotected("GITHUB_TOKEN", "ghp_test");
        });
        let ctx = UnlockContext { keyfile: None };
        let key = build_database_key(&ctx, password)?;
        let mut file = std::fs::File::create(path)?;
        db.save(&mut file, key)
            .map_err(|e| KprunError::Other(e.to_string()))
    }

    #[test]
    fn find_entry_by_title_case_insensitive() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.kdbx");
        create_test_vault(&db_path, "pass").unwrap();
        let ctx = UnlockContext { keyfile: None };
        let key = build_database_key(&ctx, "pass").unwrap();
        let vault = open_vault(&db_path, key, OpenMode::ReadOnly).unwrap();
        let id = vault.find_entry_by_title("GitHub").unwrap();
        let keys = vault.entry_custom_keys(id);
        assert_eq!(keys, vec!["GITHUB_TOKEN".to_string()]);
    }

    #[test]
    fn set_attributes_persists_after_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("w.kdbx");
        let ctx = UnlockContext { keyfile: None };
        let key = build_database_key(&ctx, "pass").unwrap();
        create_vault(&path, key.clone(), "kprun").unwrap();

        let mut vault = open_vault(&path, key.clone(), OpenMode::ReadWrite).unwrap();
        vault
            .set_attributes(
                "openai",
                &[("OPENAI_API_KEY".into(), "sk-test".into())],
            )
            .unwrap();
        vault.save(key.clone()).unwrap();

        let vault2 = open_vault(&path, key, OpenMode::ReadOnly).unwrap();
        let id = vault2.find_entry_by_title("openai").unwrap();
        let vals = vault2.entry_custom_values(id);
        assert_eq!(
            vals.get("OPENAI_API_KEY").map(String::as_str),
            Some("sk-test")
        );
    }
}
