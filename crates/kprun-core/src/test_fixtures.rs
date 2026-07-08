#[cfg(test)]
use std::path::Path;

#[cfg(test)]
use keepass::db::fields;
#[cfg(test)]
use keepass::Database;

#[cfg(test)]
use crate::test_support;
#[cfg(test)]
use crate::unlock::{build_database_key, UnlockContext};
#[cfg(test)]
use crate::{KprunError, Result};

#[cfg(test)]
pub(crate) fn test_vault_password() -> &'static str {
    test_support::vault_password()
}

#[cfg(test)]
pub(crate) fn create_test_vault(path: &Path, password: &str) -> Result<()> {
    let mut db = Database::new();
    db.root_mut().add_entry().edit(|e| {
        e.set_unprotected(fields::TITLE, "github");
        e.set_unprotected("GITHUB_TOKEN", "ghp_test");
    });
    let ctx = UnlockContext {
        keyfile: None,
        db_path: path.to_path_buf(),
    };
    let key = build_database_key(&ctx, password)?;
    let mut file = std::fs::File::create(path)?;
    db.save(&mut file, key.into_inner())
        .map_err(|e| KprunError::Other(e.to_string()))
}

#[cfg(test)]
pub(crate) fn create_multi_entry_test_vault(path: &Path, password: &str) -> Result<()> {
    let mut db = Database::new();
    db.root_mut().add_entry().edit(|e| {
        e.set_unprotected(fields::TITLE, "openai");
        e.set_unprotected("OPENAI_API_KEY", "sk-test-secret");
    });
    db.root_mut().add_entry().edit(|e| {
        e.set_unprotected(fields::TITLE, "postgres");
        e.set_unprotected("DATABASE_URL", "postgres://user:pass@localhost/db");
    });
    let ctx = UnlockContext {
        keyfile: None,
        db_path: path.to_path_buf(),
    };
    let key = build_database_key(&ctx, password)?;
    let mut file = std::fs::File::create(path)?;
    db.save(&mut file, key.into_inner())
        .map_err(|e| KprunError::Other(e.to_string()))
}
