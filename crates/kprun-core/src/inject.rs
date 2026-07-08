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

/// Case-insensitive prefixes of environment variable families that can subvert
/// process execution (dynamic loaders, git exec hooks, exported bash functions).
/// These families are parameterized (`GIT_CONFIG_KEY_0..n`, `BASH_FUNC_<name>%%`),
/// so exact-match listing cannot cover them.
const DANGEROUS_ENV_PREFIXES: &[&str] = &["LD_", "DYLD_", "GIT_", "BASH_FUNC_"];

/// Environment variable names that can subvert process execution or library loading.
/// Injecting these from a vault is refused (skipped with a warning).
/// Names covered by `DANGEROUS_ENV_PREFIXES` are intentionally absent.
const DANGEROUS_ENV: &[&str] = &[
    "PATH",
    "NODE_OPTIONS",
    "NODE_EXTRA_CA_CERTS",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "PERL5LIB",
    "PERL5OPT",
    "RUBYLIB",
    "RUBYOPT",
    "JAVA_TOOL_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "_JAVA_OPTIONS",
    "LESSOPEN",
    "LESSCLOSE",
    "BASH_ENV",
    "ENV",
    "IFS",
];

fn is_dangerous_env(key: &str) -> bool {
    DANGEROUS_ENV.iter().any(|d| d.eq_ignore_ascii_case(key))
        || DANGEROUS_ENV_PREFIXES.iter().any(|p| {
            key.get(..p.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(p))
        })
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
    use crate::test_fixtures::{create_multi_entry_test_vault, test_vault_password};
    use crate::unlock::{build_database_key, UnlockContext};
    use crate::vault::{open_vault, OpenMode};
    use keepass::db::fields;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn merges_multiple_entries() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.kdbx");
        create_multi_entry_test_vault(&db_path, test_vault_password()).unwrap();
        let ctx = UnlockContext {
            keyfile: None,
            db_path: PathBuf::from("test.kdbx"),
        };
        let key = build_database_key(&ctx, test_vault_password()).unwrap();
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
        let ctx = UnlockContext {
            keyfile: None,
            db_path: PathBuf::from("test.kdbx"),
        };
        let key = build_database_key(&ctx, test_vault_password()).unwrap();
        let mut file = std::fs::File::create(&db_path).unwrap();
        db.save(&mut file, key.clone().into_inner()).unwrap();

        let vault = open_vault(&db_path, key, OpenMode::ReadOnly).unwrap();
        let result = resolve_injection(&vault, &["svc".into()]).unwrap();
        assert!(!result.env.contains_key("PATH"));
        assert_eq!(result.env.get("SAFE_KEY").map(String::as_str), Some("ok"));
        assert!(!result.injected_keys.iter().any(|k| k == "PATH"));
    }

    #[test]
    fn skips_extended_dangerous_env_names_and_prefixes() {
        use keepass::Database;
        // Every newly blocked exact name plus one representative per prefix
        // family (including a lowercase variant for case-insensitivity).
        const BLOCKED: &[&str] = &[
            // new exact names
            "NODE_EXTRA_CA_CERTS",
            "PYTHONHOME",
            "PYTHONINSPECT",
            "PERL5LIB",
            "PERL5OPT",
            "RUBYLIB",
            "RUBYOPT",
            "JAVA_TOOL_OPTIONS",
            "JDK_JAVA_OPTIONS",
            "_JAVA_OPTIONS",
            "LESSOPEN",
            "LESSCLOSE",
            // prefix families
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_KEY_0",
            "GIT_CONFIG_VALUE_0",
            "GIT_EXTERNAL_DIFF",
            "GIT_PROXY_COMMAND",
            "GIT_PAGER",
            "BASH_FUNC_foo%%",
            "DYLD_FALLBACK_LIBRARY_PATH",
            "DYLD_VERSIONED_LIBRARY_PATH",
            "LD_AUDIT",
            // case-insensitivity through the prefix path
            "ld_preload",
        ];
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("danger-ext.kdbx");
        let mut db = Database::new();
        db.root_mut().add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "svc");
            for key in BLOCKED {
                e.set_unprotected(*key, "evil");
            }
            e.set_unprotected("SAFE_KEY", "ok");
        });
        let ctx = UnlockContext {
            keyfile: None,
            db_path: PathBuf::from("test.kdbx"),
        };
        let key = build_database_key(&ctx, test_vault_password()).unwrap();
        let mut file = std::fs::File::create(&db_path).unwrap();
        db.save(&mut file, key.clone().into_inner()).unwrap();

        let vault = open_vault(&db_path, key, OpenMode::ReadOnly).unwrap();
        let result = resolve_injection(&vault, &["svc".into()]).unwrap();
        for key in BLOCKED {
            assert!(!result.env.contains_key(*key), "{key} must be blocked");
            assert!(
                !result.injected_keys.iter().any(|k| k == key),
                "{key} must not be reported as injected"
            );
        }
        assert_eq!(result.env.get("SAFE_KEY").map(String::as_str), Some("ok"));
        assert_eq!(result.injected_keys, vec!["SAFE_KEY".to_string()]);
    }

    #[test]
    fn github_prefixed_names_are_not_blocked() {
        use keepass::Database;
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("github.kdbx");
        let mut db = Database::new();
        db.root_mut().add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "svc");
            e.set_unprotected("GITHUB_TOKEN", "ghp_test");
        });
        let ctx = UnlockContext {
            keyfile: None,
            db_path: PathBuf::from("test.kdbx"),
        };
        let key = build_database_key(&ctx, test_vault_password()).unwrap();
        let mut file = std::fs::File::create(&db_path).unwrap();
        db.save(&mut file, key.clone().into_inner()).unwrap();

        let vault = open_vault(&db_path, key, OpenMode::ReadOnly).unwrap();
        let result = resolve_injection(&vault, &["svc".into()]).unwrap();
        // GIT_ prefix requires the underscore: GITHUB_* must pass through.
        assert_eq!(
            result.env.get("GITHUB_TOKEN").map(String::as_str),
            Some("ghp_test")
        );
        assert_eq!(result.injected_keys, vec!["GITHUB_TOKEN".to_string()]);
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
        let ctx = UnlockContext {
            keyfile: None,
            db_path: PathBuf::from("test.kdbx"),
        };
        let key = build_database_key(&ctx, test_vault_password()).unwrap();
        let mut file = std::fs::File::create(&db_path).unwrap();
        db.save(&mut file, key.clone().into_inner()).unwrap();

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
