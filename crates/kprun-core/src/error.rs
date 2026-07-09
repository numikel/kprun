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
    #[error("invalid KEY=VALUE pair: missing '='")]
    InvalidKeyVal,
    #[error("invalid KEY=VALUE pair: empty key")]
    EmptyKey,
    #[error("multiple entries share the title '{0}'; titles must be unique")]
    DuplicateEntry(String),
    #[error("master password too short: minimum {0} characters required")]
    WeakPassword(usize),
    #[error("template references unknown field '{0}' (not present on the vault entry)")]
    UnknownTemplateField(String),
    #[error("malformed template: {0}")]
    MalformedTemplate(String),
    #[error("cannot unlock vault non-interactively; store the master password with `kprun init` or set KPRUN_KEYFILE for a keyfile-only vault")]
    NonInteractiveUnlock,
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("failed to open vault: {0}")]
    VaultOpen(String),
    #[error("{0}")]
    Keyring(#[from] keyring::v1::Error),
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}
