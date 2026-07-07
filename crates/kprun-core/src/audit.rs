use std::io::Write;
use std::path::Path;

use chrono::Local;
use serde::Serialize;

use crate::config::Config;
use crate::Result;

#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    pub ts: String,
    pub pid: u32,
    /// Non-identifying vault identifier (truncated SHA-256 of the canonical
    /// db path) — never the raw path, which would embed the OS username.
    pub db_id: String,
    pub entries: Vec<String>,
    pub injected_keys: Vec<String>,
    pub command: Option<String>,
}

impl AuditRecord {
    pub fn new(
        db_path: &Path,
        entries: Vec<String>,
        injected_keys: Vec<String>,
        command: Option<String>,
    ) -> Self {
        Self {
            ts: Local::now().format("%Y-%m-%dT%H:%M:%S%z").to_string(),
            pid: std::process::id(),
            db_id: crate::unlock::vault_id(db_path),
            entries,
            injected_keys,
            command,
        }
    }
}

pub fn log_access(cfg: &Config, record: &AuditRecord) -> Result<()> {
    cfg.ensure_parent_dirs(&cfg.log_path)?;
    let line = serde_json::to_string(record)?;
    let mut f = crate::secure_fs::open_append_restricted(&cfg.log_path)?;
    writeln!(f, "{line}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn appends_json_line_without_values() {
        let dir = tempdir().unwrap();
        let log = dir.path().join("access.log");
        let cfg = Config::from_env_overrides(None, None, Some(log.clone()));
        log_access(
            &cfg,
            &AuditRecord::new(
                Path::new("/db.kdbx"),
                vec!["openai".into()],
                vec!["OPENAI_API_KEY".into()],
                Some("python".into()),
            ),
        )
        .unwrap();
        let content = std::fs::read_to_string(log).unwrap();
        assert!(content.contains("OPENAI_API_KEY"));
        assert!(!content.contains("sk-"));
    }

    #[cfg(unix)]
    #[test]
    fn audit_log_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let log = dir.path().join("access.log");
        let cfg = Config::from_env_overrides(None, None, Some(log.clone()));
        log_access(
            &cfg,
            &AuditRecord::new(
                Path::new("/db.kdbx"),
                vec!["x".into()],
                vec!["K".into()],
                None,
            ),
        )
        .unwrap();
        let mode = std::fs::metadata(&log).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn record_contains_db_id_not_path() {
        let dir = tempdir().unwrap();
        let log = dir.path().join("access.log");
        let db = dir.path().join("secrets.kdbx");
        let cfg = Config::from_env_overrides(None, None, Some(log.clone()));
        log_access(
            &cfg,
            &AuditRecord::new(
                &db,
                vec!["openai".into()],
                vec!["OPENAI_API_KEY".into()],
                None,
            ),
        )
        .unwrap();
        let content = std::fs::read_to_string(log).unwrap();
        let record: serde_json::Value =
            serde_json::from_str(content.lines().next().unwrap()).unwrap();
        let db_id = record["db_id"].as_str().unwrap();
        assert_eq!(db_id.len(), 16);
        assert!(db_id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(db_id, crate::unlock::vault_id(&db));
        assert!(record.get("db").is_none());
        // No component of the real filesystem path (and thus no OS username)
        // may appear anywhere in the line.
        let db_str = db.to_string_lossy();
        assert!(!content.contains(&*db_str));
    }

    #[test]
    fn same_path_yields_same_db_id() {
        let p = std::path::Path::new("/db.kdbx");
        let a = AuditRecord::new(p, vec![], vec![], None);
        let b = AuditRecord::new(p, vec![], vec![], None);
        assert_eq!(a.db_id, b.db_id);
    }
}
