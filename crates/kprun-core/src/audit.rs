use std::io::Write;
use std::path::PathBuf;

use chrono::Local;
use serde::Serialize;

use crate::config::Config;
use crate::Result;

#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    pub ts: String,
    pub pid: u32,
    pub db: PathBuf,
    pub entries: Vec<String>,
    pub injected_keys: Vec<String>,
    pub command: Option<String>,
}

impl AuditRecord {
    pub fn new(
        db: PathBuf,
        entries: Vec<String>,
        injected_keys: Vec<String>,
        command: Option<String>,
    ) -> Self {
        Self {
            ts: Local::now().format("%Y-%m-%dT%H:%M:%S%z").to_string(),
            pid: std::process::id(),
            db,
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
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn appends_json_line_without_values() {
        let dir = tempdir().unwrap();
        let log = dir.path().join("access.log");
        let cfg = Config::from_env_overrides(None, None, Some(log.clone()));
        log_access(
            &cfg,
            &AuditRecord::new(
                PathBuf::from("/db.kdbx"),
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
                PathBuf::from("/db.kdbx"),
                vec!["x".into()],
                vec!["K".into()],
                None,
            ),
        )
        .unwrap();
        let mode = std::fs::metadata(&log).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
