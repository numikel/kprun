use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub db_path: PathBuf,
    pub keyfile: Option<PathBuf>,
    pub log_path: PathBuf,
}

impl Config {
    pub fn from_env() -> Self {
        Self::from_env_overrides(
            std::env::var_os("KPRUN_DB").map(PathBuf::from),
            std::env::var_os("KPRUN_KEYFILE").map(PathBuf::from),
            std::env::var_os("KPRUN_LOG").map(PathBuf::from),
        )
    }

    pub fn from_env_overrides(
        db: Option<PathBuf>,
        keyfile: Option<PathBuf>,
        log: Option<PathBuf>,
    ) -> Self {
        let home = home_dir();
        let default_dir = home.join(".kprun");
        Self {
            db_path: db.unwrap_or_else(|| default_dir.join("secrets.kdbx")),
            keyfile,
            log_path: log.unwrap_or_else(|| default_dir.join("access.log")),
        }
    }
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

impl Config {
    pub fn ensure_parent_dirs(&self, path: &Path) -> crate::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use std::path::PathBuf;

    #[test]
    fn default_db_under_home_kprun() {
        let cfg = Config::from_env_overrides(None, None, None);
        assert_eq!(cfg.db_path, dirs_home().join(".kprun").join("secrets.kdbx"));
        assert_eq!(cfg.log_path, dirs_home().join(".kprun").join("access.log"));
    }

    fn dirs_home() -> PathBuf {
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"))
    }
}
