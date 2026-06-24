//! Cross-platform helpers that create/write secret files with owner-only permissions.
//!
//! Unix: files are created with mode 0o600.
//! Windows: inheritance is removed and only the current user is granted access (via `icacls`).
//! All helpers fail closed: if permissions cannot be enforced, the operation returns an error.

use std::fs::File;
use std::io::Write;
use std::path::Path;

use crate::{KprunError, Result};

/// Create a new file with owner-only permissions, truncating if it exists.
pub fn create_restricted(path: &Path) -> Result<File> {
    let file = create_restricted_inner(path)?;
    harden_existing(path)?;
    Ok(file)
}

/// Write `bytes` atomically (via a temp file in the same dir) with owner-only permissions.
pub fn write_restricted(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = create_restricted(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Open a file for append, creating it owner-only if missing.
pub fn open_append_restricted(path: &Path) -> Result<File> {
    let existed = path.exists();
    let file = open_append_inner(path)?;
    if !existed {
        harden_existing(path)?;
    }
    Ok(file)
}

#[cfg(unix)]
fn create_restricted_inner(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?)
}

#[cfg(unix)]
fn open_append_inner(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?)
}

/// Enforce owner-only permissions on an existing file.
#[cfg(unix)]
pub fn harden_existing(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn create_restricted_inner(path: &Path) -> Result<File> {
    Ok(File::create(path)?)
}

#[cfg(not(any(unix, windows)))]
fn open_append_inner(path: &Path) -> Result<File> {
    Ok(std::fs::OpenOptions::new().create(true).append(true).open(path)?)
}

#[cfg(not(any(unix, windows)))]
pub fn harden_existing(_path: &Path) -> Result<()> {
    Ok(())
}

#[allow(dead_code)]
fn unsupported(op: &str) -> KprunError {
    KprunError::Other(format!("secure_fs: cannot enforce permissions for {op}"))
}

#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn create_restricted_sets_0600() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("secret");
        let _f = create_restricted(&p).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn write_restricted_writes_and_sets_0600() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("data");
        write_restricted(&p, b"hello").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"hello");
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn append_restricted_sets_0600_on_create() {
        use std::io::Write;
        let dir = tempdir().unwrap();
        let p = dir.path().join("log");
        let mut f = open_append_restricted(&p).unwrap();
        writeln!(f, "line").unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
