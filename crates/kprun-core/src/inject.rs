use std::collections::HashMap;

use crate::vault::Vault;
use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectResult {
    pub env: HashMap<String, String>,
    pub injected_keys: Vec<String>,
    pub entries: Vec<String>,
}

fn collision_warning_message(key: &str, entry: &str) -> String {
    format!("warning: key '{key}' from entry '{entry}' overrides an earlier value")
}

/// Environment variable names that can subvert process execution or library loading.
/// Injecting these from a vault is refused (skipped with a warning).
const DANGEROUS_ENV: &[&str] = &[
    "PATH",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "NODE_OPTIONS",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "BASH_ENV",
    "ENV",
    "IFS",
];

fn is_dangerous_env(key: &str) -> bool {
    DANGEROUS_ENV.iter().any(|d| d.eq_ignore_ascii_case(key))
}

fn dangerous_skip_message(key: &str, entry: &str) -> String {
    format!("warning: refusing to inject dangerous variable '{key}' from entry '{entry}'")
}

pub fn resolve_injection(vault: &Vault, entry_names: &[String]) -> Result<InjectResult> {
    let mut env = HashMap::new();
    let mut injected_keys = Vec::new();
    let mut seen_keys = std::collections::HashSet::new();
    for name in entry_names {
        let id = vault.find_entry_by_title(name)?;
        for (k, v) in vault.entry_custom_values(id) {
            if is_dangerous_env(&k) {
                eprintln!("{}", dangerous_skip_message(&k, name));
                continue;
            }
            if env.insert(k.clone(), v).is_some() {
                eprintln!("{}", collision_warning_message(&k, name));
            }
            if seen_keys.insert(k.clone()) {
                injected_keys.push(k);
            }
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
    use super::{collision_warning_message, resolve_injection};
    use crate::unlock::{build_database_key, UnlockContext};
    use crate::vault::{open_vault, OpenMode};
    use crate::{KprunError, Result};
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

    #[test]
    fn skips_dangerous_env_names() {
        use keepass::Database;
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("danger.kdbx");
        let mut db = Database::new();
        db.root_mut().add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "svc");
            e.set_unprotected("PATH", "/evil/bin");
            e.set_unprotected("SAFE_KEY", "ok");
        });
        let ctx = UnlockContext { keyfile: None };
        let key = build_database_key(&ctx, "pass").unwrap();
        let mut file = std::fs::File::create(&db_path).unwrap();
        db.save(&mut file, key.clone()).unwrap();

        let vault = open_vault(&db_path, key, OpenMode::ReadOnly).unwrap();
        let result = resolve_injection(&vault, &["svc".into()]).unwrap();
        assert!(!result.env.contains_key("PATH"));
        assert_eq!(result.env.get("SAFE_KEY").map(String::as_str), Some("ok"));
        assert!(!result.injected_keys.iter().any(|k| k == "PATH"));
    }

    #[test]
    fn warns_on_key_collision() {
        use keepass::Database;
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("collision.kdbx");
        let mut db = Database::new();
        db.root_mut().add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "entry_a");
            e.set_unprotected("SHARED_KEY", "value_a");
        });
        db.root_mut().add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "entry_b");
            e.set_unprotected("SHARED_KEY", "value_b");
        });
        let ctx = UnlockContext { keyfile: None };
        let key = build_database_key(&ctx, "pass").unwrap();
        let mut file = std::fs::File::create(&db_path).unwrap();
        db.save(&mut file, key.clone()).unwrap();

        let vault = open_vault(&db_path, key, OpenMode::ReadOnly).unwrap();
        let names = vec!["entry_a".into(), "entry_b".into()];
        let result = resolve_injection(&vault, &names).unwrap();

        assert_eq!(result.env["SHARED_KEY"], "value_b");
        assert_eq!(result.injected_keys, vec!["SHARED_KEY".to_string()]);
        assert_eq!(
            collision_warning_message("SHARED_KEY", "entry_b"),
            "warning: key 'SHARED_KEY' from entry 'entry_b' overrides an earlier value"
        );
    }
}
