use std::io;
use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, KprunError>;

#[derive(Debug, thiserror::Error)]
pub enum KprunError {
    #[error("database not found at {0}; run `kprun init`")]
    DatabaseNotFound(PathBuf),
    #[error("entry '{0}' not found")]
    EntryNotFound(String),
    #[error("failed to unlock vault")]
    UnlockFailed,
    #[error("database is locked; close KeePassXC or retry")]
    DatabaseLocked,
    #[error("invalid KEY=val: {0}")]
    InvalidKeyVal(String),
    #[error("empty key in KEY=val: {0}")]
    EmptyKey(String),
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Keepass(#[from] keepass::error::DatabaseOpenError),
    #[error("{0}")]
    Keyring(#[from] keyring::v1::Error),
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}
