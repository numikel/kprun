use std::collections::HashMap;

use crate::vault::Vault;
use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectResult {
    pub env: HashMap<String, String>,
    pub injected_keys: Vec<String>,
    pub entries: Vec<String>,
}

pub fn resolve_injection(vault: &Vault, entry_names: &[String]) -> Result<InjectResult> {
    let mut env = HashMap::new();
    let mut injected_keys = Vec::new();
    for name in entry_names {
        let id = vault.find_entry_by_title(name)?;
        for (k, v) in vault.entry_custom_values(id) {
            if env.insert(k.clone(), v).is_some() {
                // later entry overrides — document behavior
            }
            injected_keys.push(k);
        }
    }
    Ok(InjectResult {
        env,
        injected_keys,
        entries: entry_names.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::resolve_injection;
    use crate::{KprunError, Result};
    use crate::unlock::{build_database_key, UnlockContext};
    use crate::vault::{open_vault, OpenMode};
    use keepass::db::fields;
    use std::path::Path;
    use tempfile::tempdir;

    fn create_test_vault(path: &Path, password: &str) -> Result<()> {
        use keepass::Database;
        let mut db = Database::new();
        db.root_mut().add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "openai");
            e.set_unprotected("OPENAI_API_KEY", "sk-test-secret");
        });
        db.root_mut().add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "postgres");
            e.set_unprotected("DATABASE_URL", "postgres://user:pass@localhost/db");
        });
        let ctx = UnlockContext { keyfile: None };
        let key = build_database_key(&ctx, password)?;
        let mut file = std::fs::File::create(path)?;
        db.save(&mut file, key)
            .map_err(|e| KprunError::Other(e.to_string()))
    }

    #[test]
    fn merges_multiple_entries() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.kdbx");
        create_test_vault(&db_path, "pass").unwrap();
        let ctx = UnlockContext { keyfile: None };
        let key = build_database_key(&ctx, "pass").unwrap();
        let vault = open_vault(&db_path, key, OpenMode::ReadOnly).unwrap();
        let names = vec!["openai".into(), "postgres".into()];
        let result = resolve_injection(&vault, &names).unwrap();
        assert_eq!(result.entries, names);
        assert_eq!(result.env["OPENAI_API_KEY"], "sk-test-secret");
        assert_eq!(
            result.env["DATABASE_URL"],
            "postgres://user:pass@localhost/db"
        );
        assert_eq!(
            result.injected_keys,
            vec!["OPENAI_API_KEY".to_string(), "DATABASE_URL".to_string()]
        );
    }
}
