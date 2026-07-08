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

#[cfg(unix)]
pub fn harden_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn create_restricted_inner(path: &Path) -> Result<File> {
    Ok(File::create(path)?)
}

#[cfg(not(any(unix, windows)))]
fn open_append_inner(path: &Path) -> Result<File> {
    Ok(std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?)
}

#[cfg(not(any(unix, windows)))]
pub fn harden_existing(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub fn harden_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn create_restricted_inner(path: &Path) -> Result<File> {
    // Create normally; permissions are tightened by harden_existing via icacls.
    Ok(std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?)
}

#[cfg(windows)]
fn open_append_inner(path: &Path) -> Result<File> {
    Ok(std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?)
}

/// Resolve the current user's SID from the process token (`whoami /user`),
/// not from the caller-controllable USERNAME environment variable.
#[cfg(windows)]
fn current_user_sid() -> Result<String> {
    use std::process::Command;
    let output = Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .map_err(|e| KprunError::Other(format!("secure_fs: failed to run whoami: {e}")))?;
    if !output.status.success() {
        return Err(KprunError::Other("secure_fs: whoami /user failed".into()));
    }
    // /fo csv /nh prints one line: "DOMAIN\user","S-1-5-21-…"
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .rsplit(',')
        .next()
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| s.starts_with("S-1-"))
        .ok_or_else(|| KprunError::Other("secure_fs: could not parse SID from whoami".into()))
}

#[cfg(windows)]
fn run_icacls(path: &Path, grant: &str) -> Result<()> {
    use std::process::Command;
    let output = Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(grant)
        .output()
        .map_err(|e| KprunError::Other(format!("secure_fs: failed to run icacls: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(KprunError::Other(format!(
            "secure_fs: icacls failed to restrict permissions: {}",
            stderr.trim()
        )));
    }
    Ok(())
}

/// Enforce owner-only access on Windows by removing inheritance and granting
/// full control only to the process token's SID.
#[cfg(windows)]
pub fn harden_existing(path: &Path) -> Result<()> {
    let sid = current_user_sid()?;
    run_icacls(path, &format!("*{sid}:F"))
}

/// Enforce owner-only permissions on a directory. On Windows the (OI)(CI)
/// inheritance flags make new children start owner-only from creation,
/// closing the create-then-harden ACL window for files inside.
#[cfg(windows)]
pub fn harden_dir(path: &Path) -> Result<()> {
    let sid = current_user_sid()?;
    run_icacls(path, &format!("*{sid}:(OI)(CI)F"))
}

/// Persist a NamedTempFile to `dst` and enforce owner-only permissions on the result.
pub fn persist_restricted(tmp: tempfile::NamedTempFile, dst: &Path) -> Result<()> {
    let file = tmp.persist(dst).map_err(|e| KprunError::Io(e.error))?;
    drop(file);
    harden_existing(dst)?;
    Ok(())
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

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::process::Command;
    use tempfile::tempdir;

    fn icacls_dump(path: &std::path::Path) -> String {
        let out = Command::new("icacls").arg(path).output().unwrap();
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    #[test]
    fn create_restricted_removes_inheritance() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("secret");
        let _f = create_restricted(&p).unwrap();
        let acl = icacls_dump(&p);
        // After /inheritance:r only explicit (current-user) entries remain;
        // built-in BUILTIN\Users group should not be present.
        assert!(!acl.contains("BUILTIN\\Users"));
        assert!(!acl.contains("Everyone"));
    }

    #[test]
    fn harden_dir_removes_inheritance() {
        let dir = tempdir().unwrap();
        let sub = dir.path().join("kprun-home");
        std::fs::create_dir(&sub).unwrap();
        harden_dir(&sub).unwrap();
        let acl = icacls_dump(&sub);
        assert!(!acl.contains("BUILTIN\\Users"));
        assert!(!acl.contains("Everyone"));
    }
}
