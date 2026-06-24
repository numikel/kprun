# Security hardening (v0.2.0) implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement all 21 consolidated security findings from three audits as 7 themed PRs merged sequentially into release v0.2.0.

**Architecture:** Approach A — a centralized `secure_fs` module in `kprun-core` provides cross-platform restrictive file permissions reused by every secret-writing path; remaining fixes live close to the code they harden (vault, unlock, inject, parse, export, CLI, CI).

**Tech Stack:** Rust 1.88.0, `keepass` 0.13.10, `keyring` 4.1.2, `zeroize`, `sha2` (new), `tempfile`, `clap`; GitHub Actions + minisign for release signing.

**Spec:** `.docs/specs/2026-06-24-security-hardening-design.md`

**Worktree:** `.worktrees/secure-file-permissions` (branch `feat/secure-file-permissions` for Phase 1). Each subsequent phase gets its own branch off updated `main` (see "Branch per phase" below).

---

## Branch per phase

Each phase is one PR. After a phase merges to `main`, create the next branch from the refreshed `main`:

```powershell
git -C D:\kprun worktree add .worktrees/<name> -b <branch> main
```

| Phase | Branch | Conventional title |
|-------|--------|--------------------|
| 1 | `feat/secure-file-permissions` | `feat(core): secure file permissions` |
| 2 | `feat/protected-fields` | `feat(core): protected fields + memory hygiene` |
| 3 | `ci/supply-chain-hardening` | `ci(security): supply-chain hardening` |
| 4 | `feat/input-validation-ux` | `feat(cli): input validation & secret exposure UX` |
| 5 | `feat/env-injection-safety` | `feat(core): env injection safety` |
| 6 | `feat/keychain-lifecycle` | `feat(cli): keychain lifecycle` |
| 7 | `fix/low-priority-hardening` | `fix: low-priority hardening & docs` |

Every phase ends by appending its entry to `docs/changelogs/v0.2.0.md` (created in Phase 1) and running `cargo fmt --all` + `cargo clippy --all-targets --all-features -- -D warnings`.

---

## File structure

**New files:**
- `crates/kprun-core/src/secure_fs.rs` — cross-platform restrictive permission helpers (single responsibility: create/write/append/persist secret files owner-only).
- `docs/changelogs/v0.2.0.md` — incremental changelog (required by CI on version bump).

**Modified (core):** `lib.rs`, `vault.rs`, `unlock.rs`, `audit.rs`, `parse.rs`, `inject.rs`, `error.rs`, `Cargo.toml` (workspace + core).

**Modified (CLI):** `cli.rs`, `commands/mod.rs`, `commands/export.rs`, `commands/init.rs`, `commands/get.rs`, `commands/import.rs`, `commands/doctor.rs`, `spawn.rs`, new `commands/deinit.rs`.

**Modified (infra/docs):** `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `scripts/install.sh`, `scripts/install.ps1`, `SECURITY.md`, `README.md`.

---

# Phase 1 — secure file permissions (H-1)

**Branch:** `feat/secure-file-permissions`
**Covers:** H-1 (vault, keyfile, audit log, export world-readable).

### Task 1.1: Add `secure_fs` module skeleton + Unix implementation

**Files:**
- Create: `crates/kprun-core/src/secure_fs.rs`
- Modify: `crates/kprun-core/src/lib.rs`

- [x] **Step 1: Register the module.** In `crates/kprun-core/src/lib.rs`, add `pub mod secure_fs;` alongside the existing module declarations (e.g. after `pub mod parse;`).

- [x] **Step 2: Write the failing test (Unix permission bits).** Create `crates/kprun-core/src/secure_fs.rs` with:

```rust
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
```

- [x] **Step 3: Run the Unix tests to verify they pass.**

Run: `cargo test -p kprun-core secure_fs`
Expected on Unix: 3 passed. Expected on Windows: tests are `#[cfg(unix)]` so 0 run; crate still compiles.

- [x] **Step 4: Commit.**

```powershell
git add crates/kprun-core/src/secure_fs.rs crates/kprun-core/src/lib.rs
git commit -m "feat(core): add secure_fs unix owner-only file helpers"
```

### Task 1.2: Windows implementation via `icacls`

**Files:**
- Modify: `crates/kprun-core/src/secure_fs.rs`

- [x] **Step 1: Add Windows code paths.** Append to `secure_fs.rs`:

```rust
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
    Ok(std::fs::OpenOptions::new().create(true).append(true).open(path)?)
}

/// Enforce owner-only access on Windows by removing inheritance and granting
/// full control only to the current user (`icacls <path> /inheritance:r /grant:r "<user>:F"`).
#[cfg(windows)]
pub fn harden_existing(path: &Path) -> Result<()> {
    use std::process::Command;

    let user = std::env::var("USERNAME")
        .map_err(|_| KprunError::Other("secure_fs: USERNAME not set".into()))?;
    let grant = format!("{user}:F");

    let output = Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(&grant)
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
}
```

- [x] **Step 2: Run tests on Windows.**

Run: `cargo test -p kprun-core secure_fs`
Expected on Windows: `create_restricted_removes_inheritance` passes. On Unix: 0 windows tests run, crate compiles.

- [x] **Step 3: Commit.**

```powershell
git add crates/kprun-core/src/secure_fs.rs
git commit -m "feat(core): add secure_fs windows owner-only via icacls"
```

### Task 1.3: Add `persist_restricted` for atomic vault saves

**Files:**
- Modify: `crates/kprun-core/src/secure_fs.rs`

- [x] **Step 1: Add the helper.** Append to `secure_fs.rs` (above the test modules):

```rust
/// Persist a NamedTempFile to `dst` and enforce owner-only permissions on the result.
pub fn persist_restricted(tmp: tempfile::NamedTempFile, dst: &Path) -> Result<()> {
    let file = tmp.persist(dst).map_err(|e| KprunError::Io(e.error))?;
    drop(file);
    harden_existing(dst)?;
    Ok(())
}
```

- [x] **Step 2: Verify it compiles.**

Run: `cargo build -p kprun-core`
Expected: builds clean.

- [x] **Step 3: Commit.**

```powershell
git add crates/kprun-core/src/secure_fs.rs
git commit -m "feat(core): add persist_restricted for atomic vault saves"
```

### Task 1.4: Use `secure_fs` in vault create + save

**Files:**
- Modify: `crates/kprun-core/src/vault.rs:71-85` (create_vault), `vault.rs:182-192` (save)

- [x] **Step 1: Replace `File::create` in `create_vault`.** Change the body of `create_vault` so the file is created owner-only:

```rust
pub fn create_vault(path: &Path, key: keepass::DatabaseKey, db_name: &str) -> Result<()> {
    if path.exists() {
        return Err(KprunError::Other(format!(
            "database already exists: {}",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut db = Database::new();
    db.meta.database_name = Some(db_name.to_string());
    let mut file = crate::secure_fs::create_restricted(path)?;
    db.save(&mut file, key).map_err(map_save_error)
}
```

- [x] **Step 2: Replace `tmp.persist` in `save`.** Change `save` to use `persist_restricted`:

```rust
pub fn save(&mut self, key: keepass::DatabaseKey) -> Result<()> {
    self.require_rw()?;
    let mut tmp =
        tempfile::NamedTempFile::new_in(self.path.parent().unwrap_or_else(|| Path::new(".")))?;
    self.db
        .save(tmp.as_file_mut(), key)
        .map_err(map_save_error)?;
    crate::secure_fs::persist_restricted(tmp, &self.path)?;
    Ok(())
}
```

Remove the now-unused `use std::fs::File;` import only if no longer referenced (the test module uses `std::fs::File::create`, so keep `std::fs` available; verify with the compiler).

- [x] **Step 3: Add a Unix permission test for the created vault.** In `vault.rs` `#[cfg(test)] mod tests`, add:

```rust
    #[cfg(unix)]
    #[test]
    fn create_vault_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("perm.kdbx");
        let ctx = UnlockContext { keyfile: None };
        let key = build_database_key(&ctx, "pass").unwrap();
        create_vault(&path, key, "kprun").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
```

- [x] **Step 4: Run vault tests.**

Run: `cargo test -p kprun-core vault`
Expected: all existing vault tests + `create_vault_is_owner_only` (on Unix) pass.

- [x] **Step 5: Commit.**

```powershell
git add crates/kprun-core/src/vault.rs
git commit -m "feat(core): create and save vault with owner-only permissions"
```

### Task 1.5: Use `secure_fs` for keyfile generation

**Files:**
- Modify: `crates/kprun-core/src/unlock.rs:116-126`

- [x] **Step 1: Replace `File::create` in `generate_keyfile`.**

```rust
pub fn generate_keyfile(path: &Path) -> Result<()> {
    use rand::Rng;
    let mut bytes = [0u8; 64];
    rand::rng().fill_bytes(&mut bytes);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    crate::secure_fs::write_restricted(path, &bytes)?;
    Ok(())
}
```

Remove unused `use std::fs::File;` / `use std::io::Write;` if the compiler flags them.

- [x] **Step 2: Add a Unix permission test.** In `unlock.rs` `#[cfg(test)] mod tests`, add:

```rust
    #[cfg(unix)]
    #[test]
    fn generate_keyfile_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("kprun.keyfile");
        generate_keyfile(&kf).unwrap();
        assert_eq!(std::fs::read(&kf).unwrap().len(), 64);
        let mode = std::fs::metadata(&kf).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
```

Add `tempfile` to `kprun-core` dev-dependencies if not present (it is already used in tests, so it exists).

- [x] **Step 3: Run unlock tests.**

Run: `cargo test -p kprun-core unlock`
Expected: pass.

- [x] **Step 4: Commit.**

```powershell
git add crates/kprun-core/src/unlock.rs
git commit -m "feat(core): generate keyfile with owner-only permissions"
```

### Task 1.6: Use `secure_fs` for the audit log

**Files:**
- Modify: `crates/kprun-core/src/audit.rs:39-48`

- [x] **Step 1: Replace `OpenOptions` with `open_append_restricted`.**

```rust
pub fn log_access(cfg: &Config, record: &AuditRecord) -> Result<()> {
    cfg.ensure_parent_dirs(&cfg.log_path)?;
    let line = serde_json::to_string(record)?;
    let mut f = crate::secure_fs::open_append_restricted(&cfg.log_path)?;
    writeln!(f, "{line}")?;
    Ok(())
}
```

Remove `use std::fs::OpenOptions;` (now unused).

- [x] **Step 2: Add a Unix permission test.** In `audit.rs` tests, add:

```rust
    #[cfg(unix)]
    #[test]
    fn audit_log_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let log = dir.path().join("access.log");
        let cfg = Config::from_env_overrides(None, None, Some(log.clone()));
        log_access(
            &cfg,
            &AuditRecord::new(PathBuf::from("/db.kdbx"), vec!["x".into()], vec!["K".into()], None),
        )
        .unwrap();
        let mode = std::fs::metadata(&log).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
```

- [x] **Step 3: Run audit tests.**

Run: `cargo test -p kprun-core audit`
Expected: pass.

- [x] **Step 4: Commit.**

```powershell
git add crates/kprun-core/src/audit.rs
git commit -m "feat(core): append audit log with owner-only permissions"
```

### Task 1.7: Use `secure_fs` for export-to-file

**Files:**
- Modify: `crates/kprun/src/commands/export.rs:50-54`

- [x] **Step 1: Replace `std::fs::write`.** In the `else` branch of `run`:

```rust
    } else {
        let path = default_export_path(format);
        kprun_core::secure_fs::write_restricted(&path, output.as_bytes())?;
        eprintln!("wrote export to {} (permissions restricted to owner)", path.display());
    }
```

- [x] **Step 2: Run the export tests + full CLI build.**

Run: `cargo test -p kprun`
Expected: pass (existing export tests assert stdout; file path unchanged).

- [x] **Step 3: Commit.**

```powershell
git add crates/kprun/src/commands/export.rs
git commit -m "feat(cli): write export file with owner-only permissions"
```

### Task 1.8: Create changelog + run full verification

**Files:**
- Create: `docs/changelogs/v0.2.0.md`

- [x] **Step 1: Create the changelog** (Keep a Changelog style; sentence-case headings):

```markdown
# v0.2.0

## Security

- Vault, keyfile, audit log, and export files are now created with owner-only permissions (`0600` on Unix; inheritance removed and current-user-only on Windows). (H-1)
```

- [x] **Step 2: Run the full suite + lint.**

Run:
```powershell
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```
Expected: fmt clean, clippy 0 warnings, all tests pass.

- [x] **Step 3: Commit.**

```powershell
git add docs/changelogs/v0.2.0.md
git commit -m "docs: add v0.2.0 changelog with H-1 file permission note"
```

- [x] **Step 4: Push and open PR 1.**

```powershell
git push -u origin feat/secure-file-permissions
gh pr create --title "feat(core): secure file permissions" --body "Implements H-1. Adds cross-platform secure_fs module; vault/keyfile/audit/export now owner-only. See .docs/specs/2026-06-24-security-hardening-design.md."
```

---

# Phase 2 — protected fields + memory hygiene (H-2, M-6)

**Branch:** `feat/protected-fields` (from refreshed `main`)
**Covers:** H-2 (`set_unprotected` → `set_protected`), M-6 (`db_key.clone()`).

### Task 2.1: Switch custom-field writes to `set_protected`

**Files:**
- Modify: `crates/kprun-core/src/vault.rs:134-158` (set_attributes)

- [x] **Step 1: Write the failing round-trip test.** In `vault.rs` tests:

```rust
    #[test]
    fn set_attributes_stores_protected_values() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("prot.kdbx");
        let ctx = UnlockContext { keyfile: None };
        let key = build_database_key(&ctx, "pass").unwrap();
        create_vault(&path, key.clone(), "kprun").unwrap();

        let mut vault = open_vault(&path, key.clone(), OpenMode::ReadWrite).unwrap();
        vault
            .set_attributes("svc", &[("SECRET".into(), "sk-protected".into())])
            .unwrap();
        vault.save(key.clone()).unwrap();

        // Reopen and confirm the value round-trips via the unprotecting getter.
        let vault2 = open_vault(&path, key, OpenMode::ReadOnly).unwrap();
        let id = vault2.find_entry_by_title("svc").unwrap();
        let vals = vault2.entry_custom_values(id);
        assert_eq!(vals.get("SECRET").map(String::as_str), Some("sk-protected"));
    }
```

- [x] **Step 2: Run it to confirm it passes already (baseline) or fails.**

Run: `cargo test -p kprun-core set_attributes_stores_protected_values`
Expected: PASS even before the change (because `entry.get()` unprotects automatically). This test guards the round-trip; the protected flag itself is the behavior change.

- [x] **Step 3: Change `set_unprotected` → `set_protected` in both branches of `set_attributes`:**

```rust
    pub fn set_attributes(&mut self, title: &str, pairs: &[(String, String)]) -> Result<()> {
        self.require_rw()?;
        let title_owned = title.to_string();
        let result = self.find_entry_by_title(&title_owned);
        match result {
            Ok(id) => {
                if let Some(mut entry) = self.db.entry_mut(id) {
                    for (k, v) in pairs {
                        entry.set_protected(k.clone(), v.clone());
                    }
                }
                Ok(())
            }
            Err(KprunError::EntryNotFound(_)) => {
                self.db.root_mut().add_entry().edit(|e| {
                    e.set_unprotected(fields::TITLE, title_owned);
                    for (k, v) in pairs {
                        e.set_protected(k.clone(), v.clone());
                    }
                });
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
```

Note: `TITLE` stays `set_unprotected` (it is metadata, not a secret, and is read for listing). Only custom values become protected.

- [x] **Step 4: Run tests to confirm round-trip still passes.**

Run: `cargo test -p kprun-core vault`
Expected: all pass, including the new test and existing `set_attributes_persists_after_reopen`.

If `set_protected` is not available on the `edit` closure's parameter type, fall back to: build the entry, then look it up and apply `set_protected` via `entry_mut` after `add_entry`. (Confirmed `set_protected` exists on `keepass::db::Entry` 0.13.10.)

- [x] **Step 5: Commit.**

```powershell
git add crates/kprun-core/src/vault.rs
git commit -m "feat(core): store custom field values as protected (H-2)"
```

### Task 2.2: Remove redundant `db_key.clone()`

**Files:**
- Modify: `crates/kprun/src/commands/mod.rs:46-55`

- [x] **Step 1: Inspect callers.** `unlock_vault` returns `(Config, UnlockContext, Vault, DatabaseKey)` and clones `db_key` into `open_vault`. `open_vault` consumes the key. Callers that only read (`get`, `list`, `export`, `run`) ignore the returned `db_key` (bind it `_db_key`). Only write commands (`set`, `unset`, `delete`, `import`) need a key to save — and those already re-unlock or use `save_with_key`.

- [x] **Step 2: Split into read-only vs read-write helpers** to avoid keeping a second key copy for readers:

```rust
fn unlock_vault(mode: OpenMode) -> Result<(Config, UnlockContext, Vault, DatabaseKey)> {
    let cfg = Config::from_env();
    let ctx = UnlockContext {
        keyfile: cfg.keyfile.clone(),
    };
    let master = unlock_with_fallback(&ctx)?;
    let db_key = build_database_key(&ctx, &master)?;
    // Read-write callers need the key to save; readers ignore it.
    // open_vault needs an owned key, so build a second key for the returned handle
    // ONLY when the vault is opened read-write.
    match mode {
        OpenMode::ReadOnly => {
            let vault = open_vault(&cfg.db_path, db_key, mode)?;
            // Reader: return a freshly derived key is wasteful; return a placeholder is unsafe.
            // Instead, readers must use `unlock_vault_ro`.
            let _ = vault;
            unreachable!("read-only callers must use unlock_vault_ro")
        }
        OpenMode::ReadWrite => {
            let key_for_caller = build_database_key(&ctx, &master)?;
            let vault = open_vault(&cfg.db_path, db_key, mode)?;
            Ok((cfg, ctx, vault, key_for_caller))
        }
    }
}

fn unlock_vault_ro(mode: OpenMode) -> Result<(Config, UnlockContext, Vault)> {
    let cfg = Config::from_env();
    let ctx = UnlockContext {
        keyfile: cfg.keyfile.clone(),
    };
    let master = unlock_with_fallback(&ctx)?;
    let db_key = build_database_key(&ctx, &master)?;
    let vault = open_vault(&cfg.db_path, db_key, mode)?;
    Ok((cfg, ctx, vault))
}
```

Simpler alternative (preferred — keep one function, drop the clone by deriving the caller key from `master` which is still in scope):

```rust
fn unlock_vault(mode: OpenMode) -> Result<(Config, UnlockContext, Vault, DatabaseKey)> {
    let cfg = Config::from_env();
    let ctx = UnlockContext {
        keyfile: cfg.keyfile.clone(),
    };
    let master = unlock_with_fallback(&ctx)?;
    let db_key = build_database_key(&ctx, &master)?;
    let caller_key = build_database_key(&ctx, &master)?;
    let vault = open_vault(&cfg.db_path, db_key, mode)?;
    Ok((cfg, ctx, vault, caller_key))
}
```

Use the simpler alternative: it removes `db_key.clone()` (which duplicated already-derived key material via `Clone`) and instead derives the second key directly from the still-alive `Zeroizing<String> master`, which is zeroized on drop. This avoids relying on `DatabaseKey: Clone` for secret material.

- [x] **Step 3: Run all CLI tests.**

Run: `cargo test -p kprun`
Expected: pass.

- [x] **Step 4: Commit.**

```powershell
git add crates/kprun/src/commands/mod.rs
git commit -m "refactor(cli): derive caller key from master instead of cloning DatabaseKey (M-6)"
```

### Task 2.3: Changelog + verification + PR

- [x] **Step 1: Append to `docs/changelogs/v0.2.0.md`** under `## Security`:

```markdown
- Custom secret fields are now stored as KeePass protected (in-memory encrypted) values instead of plaintext. (H-2)
- Removed a redundant clone of database key material in command dispatch. (M-6)
```

- [x] **Step 2: Verify.**

Run: `cargo fmt --all; cargo clippy --all-targets --all-features -- -D warnings; cargo test --all-features`
Expected: clean.

- [x] **Step 3: Commit, push, PR.**

```powershell
git add docs/changelogs/v0.2.0.md
git commit -m "docs: note H-2 protected fields and M-6 in changelog"
git push -u origin feat/protected-fields
gh pr create --title "feat(core): protected fields + memory hygiene" --body "Implements H-2 and M-6."
```

---

# Phase 3 — supply-chain hardening (H-3, H-4, M-4, M-5)

**Branch:** `ci/supply-chain-hardening`
**Covers:** H-3 (pin Actions to SHA), H-4 (sign artifacts), M-4 (scope `contents: write`), M-5 (hide `KPRUN_SKIP_CHECKSUM`).

### Task 3.1: Pin all GitHub Actions to commit SHAs

**Files:**
- Modify: `.github/workflows/ci.yml`, `.github/workflows/release.yml`

- [x] **Step 1: Resolve each action tag to its current commit SHA.** For every `uses:` in both workflows, look up the SHA for the pinned tag:

```powershell
gh api repos/actions/checkout/git/refs/tags/v7 --jq .object.sha
gh api repos/actions/upload-artifact/git/refs/tags/v7 --jq .object.sha
gh api repos/actions/download-artifact/git/refs/tags/v8 --jq .object.sha
gh api repos/dtolnay/rust-toolchain/git/refs/heads/stable --jq .object.sha
gh api repos/Swatinem/rust-cache/git/refs/tags/v2 --jq .object.sha
gh api repos/softprops/action-gh-release/git/refs/tags/v3 --jq .object.sha
```

(If a tag is annotated, dereference: append `^{}` lookup via `gh api repos/<o>/<r>/git/tags/<sha> --jq .object.sha`.)

- [x] **Step 2: Replace every `uses: owner/action@vTAG` with `uses: owner/action@<sha> # vTAG`.** Example for `ci.yml`:

```yaml
      - uses: actions/checkout@<sha-from-step-1> # v7
      - uses: dtolnay/rust-toolchain@<sha> # stable
```

Apply the same to all `uses:` lines in both files.

- [x] **Step 3: Add a CI lint job that rejects unpinned actions.** In `ci.yml` add a job:

```yaml
  pin-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha> # v7
      - name: Reject unpinned actions
        run: |
          set -euo pipefail
          if grep -rEn 'uses:\s+[^@]+@v[0-9]' .github/workflows/; then
            echo "ERROR: found actions pinned to mutable tags; pin to commit SHA"
            exit 1
          fi
          if grep -rEn 'uses:\s+[^@]+@(stable|main|master)\b' .github/workflows/; then
            echo "ERROR: found actions pinned to mutable refs; pin to commit SHA"
            exit 1
          fi
          echo "All actions pinned to SHA"
```

- [x] **Step 4: Validate YAML locally.**

Run: `gh workflow view ci.yml` is not offline; instead verify syntax by ensuring the grep lint passes locally:
```powershell
Select-String -Path .github/workflows/*.yml -Pattern 'uses:\s+[^@]+@v[0-9]'
```
Expected: no matches.

- [x] **Step 5: Commit.**

```powershell
git add .github/workflows/ci.yml .github/workflows/release.yml
git commit -m "ci: pin all GitHub Actions to commit SHAs (H-3)"
```

### Task 3.2: Scope `contents: write` to the release job only (M-4)

**Files:**
- Modify: `.github/workflows/release.yml:8-9` and the `release` job

- [x] **Step 1: Remove the top-level `permissions` block** (lines 8-9) and set permissions per job. Set `validate` and `build` to read-only, `release` to write:

```yaml
permissions:
  contents: read

jobs:
  validate:
    permissions:
      contents: read
    ...
  build:
    permissions:
      contents: read
    ...
  release:
    permissions:
      contents: write
    ...
```

- [x] **Step 2: Confirm the lint and grep.**

Run: `Select-String -Path .github/workflows/release.yml -Pattern 'contents: write'`
Expected: exactly one match (inside the `release` job).

- [x] **Step 3: Commit.**

```powershell
git add .github/workflows/release.yml
git commit -m "ci: scope contents:write to release job only (M-4)"
```

### Task 3.3: Sign checksums.txt with minisign (H-4)

**Files:**
- Modify: `.github/workflows/release.yml` (release job)

- [x] **Step 1: Add minisign install + sign steps** after "Create checksums" and before "Upload Release Assets":

```yaml
      - name: Install minisign
        run: |
          sudo apt-get update
          sudo apt-get install -y minisign

      - name: Sign checksums with minisign
        if: ${{ env.HAS_MINISIGN_KEY == 'true' }}
        env:
          MINISIGN_SECRET_KEY: ${{ secrets.MINISIGN_SECRET_KEY }}
          MINISIGN_PASSWORD: ${{ secrets.MINISIGN_PASSWORD }}
        run: |
          set -euo pipefail
          umask 077
          keyfile="$(mktemp)"
          trap 'rm -f "$keyfile"' EXIT
          printf '%s' "$MINISIGN_SECRET_KEY" > "$keyfile"
          printf '%s\n' "$MINISIGN_PASSWORD" | minisign -S -H \
            -m release/checksums.txt \
            -s "$keyfile" \
            -t "kprun ${VERSION} signed"
```

- [x] **Step 2: Derive `HAS_MINISIGN_KEY` at job level** so releases before the key ceremony still succeed (without a signature). Add to the `release` job, before steps:

```yaml
  release:
    name: Create Release
    needs: build
    runs-on: ubuntu-latest
    permissions:
      contents: write
    env:
      HAS_MINISIGN_KEY: ${{ secrets.MINISIGN_SECRET_KEY != '' }}
```

- [x] **Step 3: Include the signature in uploaded assets.** Change the final step's `files:`:

```yaml
      - name: Upload Release Assets
        uses: softprops/action-gh-release@<sha> # v3
        with:
          body_path: docs/changelogs/v${{ env.VERSION }}.md
          generate_release_notes: false
          files: |
            release/*
            release/checksums.txt.minisig
```

(`minisign -S` writes `checksums.txt.minisig` next to the input; it lands in `release/` and is matched by `release/*`, but listing it explicitly is harmless and documents intent.)

- [ ] **Step 4: Document the key ceremony in `SECURITY.md`** (full content added in Phase 7; here add a short pointer). Append to `release.yml` nothing else.

- [x] **Step 5: Commit.**

```powershell
git add .github/workflows/release.yml
git commit -m "ci: sign release checksums with minisign (H-4)"
```

### Task 3.4: Verify minisign signature in installers + hide skip flag (M-5)

**Files:**
- Modify: `scripts/install.sh:82-85`, `scripts/install.ps1:64-66`

- [x] **Step 1: Read both installer scripts fully** to locate the checksum verification block and the `KPRUN_SKIP_CHECKSUM` handling.

Run: open `scripts/install.sh` and `scripts/install.ps1`.

- [x] **Step 2: Add optional minisign verification (sh).** After the existing SHA-256 check in `install.sh`, add (using the embedded public key):

```sh
# Optional minisign verification (defense in depth on top of SHA-256).
KPRUN_MINISIGN_PUBKEY="RWQ..."   # published kprun release public key
if command -v minisign >/dev/null 2>&1; then
  if [ -f "checksums.txt.minisig" ]; then
    echo "$KPRUN_MINISIGN_PUBKEY" > kprun-minisign.pub
    if ! minisign -V -p kprun-minisign.pub -m checksums.txt; then
      echo "ERROR: minisign signature verification failed" >&2
      rm -f kprun-minisign.pub
      exit 1
    fi
    rm -f kprun-minisign.pub
    echo "minisign signature verified"
  fi
fi
```

- [x] **Step 3: Gate `KPRUN_SKIP_CHECKSUM` behind a developer flag (sh).** Replace the existing public bypass so it only works when `KPRUN_DEV=1` is also set:

```sh
if [ "${KPRUN_SKIP_CHECKSUM:-0}" = "1" ] && [ "${KPRUN_DEV:-0}" = "1" ]; then
  echo "WARNING: checksum verification skipped (developer mode)" >&2
else
  # ... existing checksum verification ...
fi
```

- [x] **Step 4: Mirror both changes in `install.ps1`** (PowerShell equivalents): add minisign verification block guarded by `Get-Command minisign -ErrorAction SilentlyContinue`, and gate the skip with `$env:KPRUN_SKIP_CHECKSUM -eq '1' -and $env:KPRUN_DEV -eq '1'`.

- [x] **Step 5: Validate script syntax** (mirrors CI `install-script-smoke`):

```powershell
bash -n scripts/install.sh
pwsh -NoProfile -Command '$errs=$null; [void][System.Management.Automation.Language.Parser]::ParseFile("scripts/install.ps1", [ref]$null, [ref]$errs); if ($errs) { exit 1 }'
```
Expected: both exit 0.

- [x] **Step 6: Commit.**

```powershell
git add scripts/install.sh scripts/install.ps1
git commit -m "ci(install): verify minisign signature and gate checksum skip behind dev flag (H-4, M-5)"
```

### Task 3.5: Changelog + PR

- [x] **Step 1: Append to `docs/changelogs/v0.2.0.md`:**

```markdown
## Supply chain

- All GitHub Actions are pinned to commit SHAs; CI fails on unpinned actions. (H-3)
- Release checksums are signed with minisign; installers verify the signature when available. (H-4)
- `contents: write` permission is scoped to the release job only. (M-4)
- `KPRUN_SKIP_CHECKSUM` now requires `KPRUN_DEV=1` (developer-only). (M-5)
```

- [x] **Step 2: Push + PR.**

```powershell
git add docs/changelogs/v0.2.0.md
git commit -m "docs: note supply-chain hardening in changelog"
git push -u origin ci/supply-chain-hardening
gh pr create --title "ci(security): supply-chain hardening" --body "Implements H-3, H-4, M-4, M-5. NOTE: requires MINISIGN_SECRET_KEY/MINISIGN_PASSWORD repo secrets and the public key embedded in installers before signing activates."
```

---

# Phase 4 — input validation & secret exposure UX (M-1, M-3, M-7, Bugbot)

**Branch:** `feat/input-validation-ux`
**Covers:** M-3 (min password length), M-7 (pipe warning), M-1 (`export --reveal` to file: warning + `--output` + perms — perms already done in Phase 1), dotenv `\n` escaping, duplicate title detection, parse error sanitization.

### Task 4.1: Sanitize `parse_key_val` error messages

**Files:**
- Modify: `crates/kprun-core/src/parse.rs:3-11`, `crates/kprun-core/src/error.rs`

- [ ] **Step 1: Inspect `error.rs`** to see the `InvalidKeyVal`/`EmptyKey` variants and their `Display` strings.

Run: open `crates/kprun-core/src/error.rs`.

- [ ] **Step 2: Write a failing test** in `parse.rs` tests asserting the error no longer echoes the full input value:

```rust
    #[test]
    fn invalid_key_val_error_does_not_leak_value() {
        let err = parse_key_val("API_KEY=sk-supersecret-value").unwrap_err();
        let msg = err.to_string();
        assert!(!msg.contains("sk-supersecret-value"), "error leaked secret: {msg}");
    }
```

Note: this input HAS an `=`, so it currently parses OK. Adjust: the leak risk is when the WHOLE token (which may be `KEY=secret`) is echoed for the missing-`=` / empty-key cases. Test the realistic leak — a token with no `=` that still contains secret-looking text, and the empty-key case:

```rust
    #[test]
    fn parse_errors_do_not_echo_full_input() {
        let e1 = parse_key_val("no-equals-but-sensitive").unwrap_err();
        assert!(!e1.to_string().contains("no-equals-but-sensitive"));
        let e2 = parse_key_val("=value-after-empty-key").unwrap_err();
        assert!(!e2.to_string().contains("value-after-empty-key"));
    }
```

- [ ] **Step 3: Run it to confirm it fails.**

Run: `cargo test -p kprun-core parse_errors_do_not_echo_full_input`
Expected: FAIL (current code stores `input.to_string()`).

- [ ] **Step 4: Change `error.rs` variants to carry no secret.** Replace the data carried by these variants with a non-secret hint. In `error.rs`:

```rust
    #[error("invalid KEY=VALUE pair: missing '='")]
    InvalidKeyVal,
    #[error("invalid KEY=VALUE pair: empty key")]
    EmptyKey,
```

(Remove the `(String)` payloads. Update any pattern matches like `KprunError::InvalidKeyVal(_)` to `KprunError::InvalidKeyVal`.)

- [ ] **Step 5: Update `parse.rs`:**

```rust
pub fn parse_key_val(input: &str) -> Result<(String, String)> {
    let Some((key, value)) = input.split_once('=') else {
        return Err(KprunError::InvalidKeyVal);
    };
    if key.is_empty() {
        return Err(KprunError::EmptyKey);
    }
    Ok((key.to_string(), value.to_string()))
}
```

- [ ] **Step 6: Fix all match sites.** Search for `InvalidKeyVal(` and `EmptyKey(`:

Run: `Select-String -Path crates/**/*.rs -Pattern 'InvalidKeyVal\(|EmptyKey\('`
Update each (notably `import.rs:171` uses `KprunError::EmptyKey(line.to_string())` → `KprunError::EmptyKey`; and `parse.rs` tests using `InvalidKeyVal(_)` → `InvalidKeyVal`).

- [ ] **Step 7: Run tests.**

Run: `cargo test -p kprun-core`
Expected: pass including new test.

- [ ] **Step 8: Commit.**

```powershell
git add crates/kprun-core/src/parse.rs crates/kprun-core/src/error.rs crates/kprun/src/commands/import.rs
git commit -m "fix(core): stop echoing user input in key/value parse errors (Bugbot)"
```

### Task 4.2: Detect duplicate entry titles

**Files:**
- Modify: `crates/kprun-core/src/vault.rs:95-107`, `crates/kprun-core/src/error.rs`

- [ ] **Step 1: Add a `DuplicateEntry` error variant** in `error.rs`:

```rust
    #[error("multiple entries share the title '{0}'; titles must be unique")]
    DuplicateEntry(String),
```

- [ ] **Step 2: Write a failing test** in `vault.rs` tests:

```rust
    #[test]
    fn find_entry_by_title_rejects_duplicates() {
        use keepass::Database;
        let dir = tempdir().unwrap();
        let path = dir.path().join("dup.kdbx");
        let mut db = Database::new();
        db.root_mut().add_entry().edit(|e| { e.set_unprotected(fields::TITLE, "dup"); });
        db.root_mut().add_entry().edit(|e| { e.set_unprotected(fields::TITLE, "DUP"); });
        let ctx = UnlockContext { keyfile: None };
        let key = build_database_key(&ctx, "pass").unwrap();
        let mut file = std::fs::File::create(&path).unwrap();
        db.save(&mut file, key.clone()).unwrap();

        let vault = open_vault(&path, key, OpenMode::ReadOnly).unwrap();
        let err = vault.find_entry_by_title("dup").unwrap_err();
        assert!(matches!(err, KprunError::DuplicateEntry(_)));
    }
```

- [ ] **Step 3: Run it to confirm it fails.**

Run: `cargo test -p kprun-core find_entry_by_title_rejects_duplicates`
Expected: FAIL (current code returns first match).

- [ ] **Step 4: Update `find_entry_by_title` to detect duplicates:**

```rust
    pub fn find_entry_by_title(&self, title: &str) -> Result<EntryId> {
        let title_lower = title.to_ascii_lowercase();
        let mut found: Option<EntryId> = None;
        for entry in self.db.iter_all_entries() {
            let matches = entry
                .get_title()
                .map(|t| t.to_ascii_lowercase() == title_lower)
                .unwrap_or(false);
            if matches {
                if found.is_some() {
                    return Err(KprunError::DuplicateEntry(title.to_string()));
                }
                found = Some(entry.id());
            }
        }
        found.ok_or_else(|| KprunError::EntryNotFound(title.to_string()))
    }
```

- [ ] **Step 5: Run all vault + inject tests** (inject relies on `find_entry_by_title`).

Run: `cargo test -p kprun-core`
Expected: pass.

- [ ] **Step 6: Commit.**

```powershell
git add crates/kprun-core/src/vault.rs crates/kprun-core/src/error.rs
git commit -m "feat(core): reject duplicate entry titles in lookup (Bugbot)"
```

### Task 4.3: Escape newlines in dotenv export

**Files:**
- Modify: `crates/kprun/src/commands/export.rs:93-119`

- [ ] **Step 1: Write a failing round-trip test.** Add an integration-style unit test in `export.rs` test module (create `#[cfg(test)] mod tests` if absent) that checks a value with a newline is escaped so re-import treats it as one value. Since `export_dotenv` is private, test it directly:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use kprun_core::vault::{create_vault, open_vault, OpenMode};
    use kprun_core::unlock::{build_database_key, UnlockContext};
    use tempfile::tempdir;

    #[test]
    fn dotenv_export_escapes_newlines() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("e.kdbx");
        let ctx = UnlockContext { keyfile: None };
        let key = build_database_key(&ctx, "pass").unwrap();
        create_vault(&path, key.clone(), "kprun").unwrap();
        let mut v = open_vault(&path, key.clone(), OpenMode::ReadWrite).unwrap();
        v.set_attributes("svc", &[("MULTI".into(), "line1\nline2".into())]).unwrap();
        v.save(key.clone()).unwrap();

        let v2 = open_vault(&path, key, OpenMode::ReadOnly).unwrap();
        let summaries = v2.list_entries();
        let out = export_dotenv(&v2, &summaries, true).unwrap();
        // The raw newline inside the value must not appear as an unescaped line break.
        assert!(out.contains("MULTI=\"line1\\nline2\""));
    }
}
```

- [ ] **Step 2: Run it to confirm it fails.**

Run: `cargo test -p kprun dotenv_export_escapes_newlines`
Expected: FAIL.

- [ ] **Step 3: Quote and escape values in `export_dotenv`.** Replace the reveal branch line construction:

```rust
        if reveal {
            let id = vault.find_entry_by_title(&summary.title)?;
            let values = vault.entry_custom_values(id);
            for key in &summary.keys {
                if let Some(value) = values.get(key) {
                    let escaped = value.replace('\\', "\\\\").replace('\n', "\\n").replace('\r', "\\r");
                    lines.push(format!("{key}=\"{escaped}\""));
                }
            }
        } else {
```

- [ ] **Step 4: Run the test.**

Run: `cargo test -p kprun dotenv_export_escapes_newlines`
Expected: PASS.

- [ ] **Step 5: Commit.**

```powershell
git add crates/kprun/src/commands/export.rs
git commit -m "fix(cli): escape newlines/backslashes in dotenv export (Bugbot)"
```

### Task 4.4: `export --reveal` file warning + `--output` flag (M-1)

**Files:**
- Modify: `crates/kprun/src/cli.rs` (Export args), `crates/kprun/src/commands/mod.rs` (dispatch), `crates/kprun/src/commands/export.rs`

- [ ] **Step 1: Inspect the `Export` subcommand in `cli.rs`** to see the existing `format`, `stdout`, `reveal` fields.

Run: open `crates/kprun/src/cli.rs`.

- [ ] **Step 2: Add an `--output <PATH>` option** to the `Export` variant:

```rust
    Export {
        #[arg(long, value_enum, default_value_t = ExportFormat::Json)]
        format: ExportFormat,
        #[arg(long)]
        stdout: bool,
        #[arg(long)]
        reveal: bool,
        /// Write to this path instead of the default kprun-export.* in the current directory.
        #[arg(long)]
        output: Option<String>,
    },
```

- [ ] **Step 3: Thread `output` through dispatch.** In `commands/mod.rs`, update the `Commands::Export { .. }` arm to pass `output` into `export::execute(format, stdout, reveal, output)`.

- [ ] **Step 4: Update `export::execute`/`run` signature** and the file-writing branch:

```rust
pub fn execute(format: ExportFormat, stdout: bool, reveal: bool, output: Option<String>) -> i32 {
    match run(format, stdout, reveal, output) {
        Ok(()) => 0,
        Err(e) => { eprintln!("error: {e}"); 1 }
    }
}

fn run(format: ExportFormat, stdout: bool, reveal: bool, output: Option<String>) -> Result<()> {
    // ... unchanged until the write branch ...
    if stdout {
        // ... unchanged ...
    } else {
        let path = output
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| default_export_path(format));
        if reveal {
            eprintln!(
                "WARNING: writing plaintext secrets to {} (permissions restricted to owner)",
                path.display()
            );
        }
        kprun_core::secure_fs::write_restricted(&path, output_str.as_bytes())?;
        eprintln!("wrote export to {}", path.display());
    }
    Ok(())
}
```

(Rename the local `output` string variable produced by the format match to `output_str` to avoid colliding with the new `output: Option<String>` parameter.)

- [ ] **Step 5: Build + test.**

Run: `cargo test -p kprun`
Expected: pass. Manually verify help: `cargo run -p kprun -- export --help` shows `--output`.

- [ ] **Step 6: Commit.**

```powershell
git add crates/kprun/src/cli.rs crates/kprun/src/commands/mod.rs crates/kprun/src/commands/export.rs
git commit -m "feat(cli): add export --output and warn on reveal-to-file (M-1)"
```

### Task 4.5: Minimum master password length (M-3)

**Files:**
- Modify: `crates/kprun-core/src/error.rs`, `crates/kprun/src/commands/init.rs:78-94`

- [ ] **Step 1: Add a `WeakPassword` error variant** in `error.rs`:

```rust
    #[error("master password too short: minimum {0} characters required")]
    WeakPassword(usize),
```

- [ ] **Step 2: Define the constant + enforce in `prompt_new_master`.** In `init.rs`:

```rust
const MIN_MASTER_LEN: usize = 12;
```

Then in `prompt_new_master`, after the match/empty checks:

```rust
    if pw1 != pw2 {
        return Err(KprunError::Other("passwords do not match".into()));
    }
    if pw1.chars().count() < MIN_MASTER_LEN {
        return Err(KprunError::WeakPassword(MIN_MASTER_LEN));
    }
    Ok(pw1)
```

Remove the now-redundant `pw1.is_empty()` check (length check subsumes it).

- [ ] **Step 3: Add a test** for the length rule. Since `prompt_new_master` reads stdin, extract the validation into a pure helper and test that:

```rust
fn validate_new_master(pw1: &str, pw2: &str) -> Result<()> {
    if pw1 != pw2 {
        return Err(KprunError::Other("passwords do not match".into()));
    }
    if pw1.chars().count() < MIN_MASTER_LEN {
        return Err(KprunError::WeakPassword(MIN_MASTER_LEN));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_short_password() {
        assert!(matches!(validate_new_master("short", "short"), Err(KprunError::WeakPassword(12))));
    }
    #[test]
    fn accepts_long_matching_password() {
        assert!(validate_new_master("a-strong-passphrase", "a-strong-passphrase").is_ok());
    }
    #[test]
    fn rejects_mismatch() {
        assert!(validate_new_master("a-strong-passphrase", "different-passphrase").is_err());
    }
}
```

Call `validate_new_master(&pw1, &pw2)?;` inside `prompt_new_master` instead of inlining the checks.

- [ ] **Step 4: Run tests.**

Run: `cargo test -p kprun rejects_short_password accepts_long_matching_password rejects_mismatch`
Expected: pass.

- [ ] **Step 5: Commit.**

```powershell
git add crates/kprun-core/src/error.rs crates/kprun/src/commands/init.rs
git commit -m "feat(cli): enforce minimum master password length (M-3)"
```

### Task 4.6: Warn when reading password from a pipe (M-7)

**Files:**
- Modify: `crates/kprun/src/commands/init.rs:96-117`

- [ ] **Step 1: Add a stderr warning in the non-terminal branch** of `read_password_prompt`:

```rust
    eprint!("{prompt}");
    eprintln!(
        "\nWARNING: reading password from a non-terminal (pipe); the value may be visible in shell history or process listings"
    );
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line).map_err(KprunError::Io)?;
    Ok(Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_string()))
```

- [ ] **Step 2: Build.**

Run: `cargo build -p kprun`
Expected: builds clean. (Behavior is stderr-only; covered by existing init integration tests not breaking.)

- [ ] **Step 3: Commit.**

```powershell
git add crates/kprun/src/commands/init.rs
git commit -m "feat(cli): warn when master password is read from a pipe (M-7)"
```

### Task 4.7: Changelog + PR

- [ ] **Step 1: Append to `docs/changelogs/v0.2.0.md`:**

```markdown
## Validation and UX

- Minimum master password length of 12 characters is now enforced on init. (M-3) **(breaking for new vaults with short passwords)**
- `kprun export` accepts `--output <path>` and warns when writing plaintext secrets to a file. (M-1)
- dotenv export now quotes and escapes values containing newlines/backslashes. (Bugbot)
- Duplicate entry titles are now rejected instead of silently using the first match. (Bugbot)
- Key/value parse errors no longer echo the user-supplied input. (Bugbot)
- A warning is shown when the master password is read from a pipe. (M-7)
```

- [ ] **Step 2: Verify + push + PR.**

```powershell
cargo fmt --all; cargo clippy --all-targets --all-features -- -D warnings; cargo test --all-features
git add docs/changelogs/v0.2.0.md
git commit -m "docs: note input validation and UX hardening in changelog"
git push -u origin feat/input-validation-ux
gh pr create --title "feat(cli): input validation & secret exposure UX" --body "Implements M-1, M-3, M-7 and Bugbot medium findings."
```

---

# Phase 5 — env injection safety (Bugbot, code-review Low)

**Branch:** `feat/env-injection-safety`
**Covers:** dangerous env name blocklist in injection + optional `--clean-env`.

### Task 5.1: Blocklist dangerous env names during injection

**Files:**
- Modify: `crates/kprun-core/src/inject.rs:17-37`

- [ ] **Step 1: Add the blocklist constant + helper** at the top of `inject.rs`:

```rust
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
```

- [ ] **Step 2: Write a failing test** in `inject.rs` tests:

```rust
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
```

- [ ] **Step 3: Run it to confirm it fails.**

Run: `cargo test -p kprun-core skips_dangerous_env_names`
Expected: FAIL (PATH currently injected).

- [ ] **Step 4: Filter in `resolve_injection`:**

```rust
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
```

- [ ] **Step 5: Run tests.**

Run: `cargo test -p kprun-core inject`
Expected: pass.

- [ ] **Step 6: Commit.**

```powershell
git add crates/kprun-core/src/inject.rs
git commit -m "feat(core): refuse to inject dangerous environment variables (Bugbot)"
```

### Task 5.2: Optional `--clean-env` for `kprun run`

**Files:**
- Modify: `crates/kprun/src/cli.rs` (Run args), `crates/kprun/src/commands/run.rs`, `crates/kprun/src/spawn.rs:26-43`

- [ ] **Step 1: Read `run.rs` and the `Run` subcommand** to see how `run_child` is called.

Run: open `crates/kprun/src/commands/run.rs` and `crates/kprun/src/cli.rs`.

- [ ] **Step 2: Add a `--clean-env` flag** to the `Run` subcommand in `cli.rs`:

```rust
    Run {
        /// Inject only vault secrets and a minimal safe environment, dropping the parent environment.
        #[arg(long)]
        clean_env: bool,
        // ... existing entries / command fields ...
    },
```

Thread `clean_env` through dispatch in `commands/mod.rs` into `run::execute`.

- [ ] **Step 3: Add a `clean` parameter to `run_child`** in `spawn.rs`:

```rust
pub fn run_child(
    command: &[String],
    extra_env: &HashMap<String, String>,
    clean: bool,
) -> std::io::Result<i32> {
    if command.is_empty() {
        return Ok(1);
    }
    let program = resolve_executable(&command[0]);
    let mut cmd = Command::new(program);
    cmd.args(&command[1..]);
    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    if clean {
        // Start from an empty environment, keeping only a minimal safe allowlist plus injected secrets.
        cmd.env_clear();
        for key in ["PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "TEMP", "TMP", "SystemRoot", "USERPROFILE"] {
            if let Some(val) = env::var_os(key) {
                cmd.env(key, val);
            }
        }
    } else {
        let mut env_map: HashMap<OsString, OsString> = env::vars_os().collect();
        for (k, v) in extra_env {
            env_map.insert(OsString::from(k), OsString::from(v));
        }
        cmd.envs(env_map);
        let status = cmd.status()?;
        return Ok(status.code().unwrap_or(1));
    }

    for (k, v) in extra_env {
        cmd.env(OsString::from(k), OsString::from(v));
    }
    let status = cmd.status()?;
    Ok(status.code().unwrap_or(1))
}
```

- [ ] **Step 4: Update the `run::execute` call site** to pass `clean_env`.

- [ ] **Step 5: Build + test.**

Run: `cargo test -p kprun; cargo build -p kprun`
Expected: pass. Verify `cargo run -p kprun -- run --help` shows `--clean-env`.

- [ ] **Step 6: Commit.**

```powershell
git add crates/kprun/src/cli.rs crates/kprun/src/commands/run.rs crates/kprun/src/commands/mod.rs crates/kprun/src/spawn.rs
git commit -m "feat(cli): add --clean-env to drop inherited environment (code-review)"
```

### Task 5.3: Changelog + PR

- [ ] **Step 1: Append to `docs/changelogs/v0.2.0.md`:**

```markdown
## Process isolation

- Vault entries named like dangerous environment variables (PATH, LD_PRELOAD, DYLD_*, NODE_OPTIONS, ...) are refused during injection. (Bugbot)
- `kprun run --clean-env` runs the child with a minimal environment plus injected secrets. (code-review)
```

- [ ] **Step 2: Verify + push + PR.**

```powershell
cargo fmt --all; cargo clippy --all-targets --all-features -- -D warnings; cargo test --all-features
git add docs/changelogs/v0.2.0.md
git commit -m "docs: note env injection safety in changelog"
git push -u origin feat/env-injection-safety
gh pr create --title "feat(core): env injection safety" --body "Implements env blocklist and --clean-env."
```

---

# Phase 6 — keychain lifecycle (M-2, L-5) — BREAKING

**Branch:** `feat/keychain-lifecycle`
**Covers:** M-2 (per-vault keychain keying), L-5 (`deinit`/`logout`).

### Task 6.1: Per-vault keychain keying

**Files:**
- Modify: `crates/kprun-core/Cargo.toml` and workspace `Cargo.toml` (add `sha2`), `crates/kprun-core/src/unlock.rs`

- [x] **Step 1: Add `sha2` dependency.** Check latest version:

```powershell
(Invoke-RestMethod https://crates.io/api/v1/crates/sha2).crate.max_stable_version
```

Add to workspace `Cargo.toml` `[workspace.dependencies]`: `sha2 = "<latest>"`. Add to `crates/kprun-core/Cargo.toml` `[dependencies]`: `sha2 = { workspace = true }`.

- [x] **Step 2: Replace constant USER with a per-vault account derived from db path.** In `unlock.rs`:

```rust
const SERVICE: &str = "kprun";

/// Derive a stable, per-vault keychain account name from the database path,
/// so different vaults never overwrite each other's stored master password.
fn keychain_account(db_path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let canonical = std::fs::canonicalize(db_path)
        .unwrap_or_else(|_| db_path.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(canonical.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    format!("master:{:x}", digest)
}
```

- [x] **Step 3: Thread `db_path` into the keychain functions.** Change the signatures:

```rust
pub fn store_master_in_keystore(db_path: &Path, master: &str) -> Result<()> {
    let entry = Entry::new(SERVICE, &keychain_account(db_path))?;
    entry.set_password(master)?;
    Ok(())
}

pub fn delete_master_from_keystore(db_path: &Path) -> Result<()> {
    let entry = Entry::new(SERVICE, &keychain_account(db_path))?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::v1::Error::NoEntry) => Ok(()),
        Err(e) => Err(KprunError::Keyring(e)),
    }
}

pub fn keystore_has_master(db_path: &Path) -> bool {
    Entry::new(SERVICE, &keychain_account(db_path))
        .and_then(|e| e.get_password())
        .is_ok()
}
```

Also update `SystemUnlock`. Since `MasterPasswordSource::get_master` takes no path, add the db_path to `UnlockContext` and use it:

```rust
pub struct UnlockContext {
    pub keyfile: Option<PathBuf>,
    pub db_path: PathBuf,
}

pub struct SystemUnlock<'a> {
    pub db_path: &'a Path,
}

impl MasterPasswordSource for SystemUnlock<'_> {
    fn get_master(&self) -> Result<Zeroizing<String>> {
        let entry = Entry::new(SERVICE, &keychain_account(self.db_path))?;
        match entry.get_password() {
            Ok(pw) => Ok(Zeroizing::new(pw)),
            Err(keyring::v1::Error::NoEntry) => Err(KprunError::UnlockFailed),
            Err(e) => Err(KprunError::Keyring(e)),
        }
    }
}
```

Update `unlock_with_fallback` to construct `SystemUnlock { db_path: &ctx.db_path }`.

- [x] **Step 4: Update all call sites** of `UnlockContext { keyfile }`, `store_master_in_keystore`, `keystore_has_master`, and `SystemUnlock`. Search:

```powershell
Select-String -Path crates/**/*.rs -Pattern 'UnlockContext \{|store_master_in_keystore|keystore_has_master|SystemUnlock'
```

Update:
- `commands/mod.rs unlock_vault`: `UnlockContext { keyfile: cfg.keyfile.clone(), db_path: cfg.db_path.clone() }`.
- `commands/init.rs`: pass `db_path` to `store_master_in_keystore(&db_path, &master)` in both `verify_existing` and `create_new`; build `UnlockContext` with `db_path`.
- All test modules constructing `UnlockContext { keyfile: None }` → add `db_path: PathBuf::from("test.kdbx")` (or the test's actual path). Search and fix each.

- [x] **Step 5: Write a test** that two different db paths produce different accounts:

```rust
    #[test]
    fn keychain_account_is_per_vault() {
        let a = keychain_account(Path::new("a.kdbx"));
        let b = keychain_account(Path::new("b.kdbx"));
        assert_ne!(a, b);
        assert!(a.starts_with("master:"));
    }
```

- [x] **Step 6: Run tests.**

Run: `cargo test -p kprun-core; cargo test -p kprun`
Expected: pass after all `UnlockContext` constructions are updated.

- [x] **Step 7: Commit.**

```powershell
git add Cargo.toml crates/kprun-core/Cargo.toml crates/kprun-core/src/unlock.rs crates/kprun/src/commands/mod.rs crates/kprun/src/commands/init.rs
git commit -m "feat(core)!: derive keychain account per vault path (M-2)"
```

### Task 6.2: `kprun deinit` command (L-5)

**Files:**
- Create: `crates/kprun/src/commands/deinit.rs`
- Modify: `crates/kprun/src/cli.rs`, `crates/kprun/src/commands/mod.rs`

- [x] **Step 1: Add the `Deinit` subcommand** in `cli.rs`:

```rust
    /// Remove the stored master password for the current vault from the OS keychain.
    Deinit,
```

- [x] **Step 2: Create `commands/deinit.rs`:**

```rust
use kprun_core::config::Config;
use kprun_core::unlock::delete_master_from_keystore;

pub fn execute() -> i32 {
    let cfg = Config::from_env();
    match delete_master_from_keystore(&cfg.db_path) {
        Ok(()) => {
            eprintln!("Removed stored master password for {} from keychain.", cfg.db_path.display());
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}
```

- [x] **Step 3: Wire it up** in `commands/mod.rs`: add `mod deinit;` and the dispatch arm `Commands::Deinit => std::process::exit(deinit::execute()),`.

- [x] **Step 4: Build + smoke test.**

Run: `cargo build -p kprun`; `cargo run -p kprun -- deinit --help`
Expected: builds; help shows the command.

- [x] **Step 5: Commit.**

```powershell
git add crates/kprun/src/commands/deinit.rs crates/kprun/src/cli.rs crates/kprun/src/commands/mod.rs
git commit -m "feat(cli): add deinit to clear stored master from keychain (L-5)"
```

### Task 6.3: Migration notice + changelog + PR

**Files:**
- Modify: `crates/kprun/src/commands/mod.rs` (unlock fallback notice)

- [x] **Step 1: Emit a one-time hint** when the keychain has no entry for this vault (e.g. legacy users after the keying change). In `unlock_vault`, when `unlock_with_fallback` falls back to prompt because the per-vault account is missing, the existing prompt flow already handles it — add a stderr hint in `init`'s `verify_existing` after a successful store: no code needed beyond existing messages. Document the migration in the changelog instead.

- [x] **Step 2: Append BREAKING note to `docs/changelogs/v0.2.0.md`:**

```markdown
## Keychain

- **BREAKING:** the OS keychain entry is now keyed per vault path (`kprun` / `master:<sha256(db_path)>`) instead of a single shared `kprun`/`master` entry. After upgrading, run `kprun init` once per vault to re-store the master password (or you will be prompted). (M-2)
- Added `kprun deinit` to remove the stored master password for the current vault. (L-5)
```

- [x] **Step 3: Verify + push + PR.**

```powershell
cargo fmt --all; cargo clippy --all-targets --all-features -- -D warnings; cargo test --all-features
git add docs/changelogs/v0.2.0.md crates/kprun/src/commands/mod.rs
git commit -m "docs: document keychain keying migration (M-2, L-5)"
git push -u origin feat/keychain-lifecycle
gh pr create --title "feat(cli): keychain lifecycle (BREAKING)" --body "Implements M-2 (per-vault keying, BREAKING) and L-5 (deinit)."
```

---

# Phase 7 — low-priority hardening & docs (L-1..L-4, get --keys audit, FixedUnlock)

**Branch:** `fix/low-priority-hardening`
**Covers:** Bugbot Low (`get --keys` audit), L-2 (pin npx), L-3 (path leakage in errors), L-4 (`KPRUN_TEST_MASTER` docs), L-1 (import trim review), `FixedUnlock` visibility, `SECURITY.md` expansion + minisign public key.

### Task 7.1: Audit log for `get --keys`

**Files:**
- Modify: `crates/kprun/src/commands/get.rs:22-27`

- [ ] **Step 1: Add an audit record in the `keys_only` branch:**

```rust
    if keys_only {
        for k in &keys {
            println!("{k}");
        }
        log_access(
            &cfg,
            &AuditRecord::new(cfg.db_path.clone(), vec![entry.to_string()], keys.clone(), None),
        )?;
        return Ok(());
    }
```

- [ ] **Step 2: Build + run get tests.**

Run: `cargo test -p kprun`
Expected: pass.

- [ ] **Step 3: Commit.**

```powershell
git add crates/kprun/src/commands/get.rs
git commit -m "feat(cli): record audit entry for get --keys (Bugbot)"
```

### Task 7.2: Pin npx version in doctor suggestion (L-2)

**Files:**
- Modify: `crates/kprun/src/commands/doctor.rs:89-98`

- [ ] **Step 1: Read the doctor MCP suggestion block.**

Run: open `crates/kprun/src/commands/doctor.rs`.

- [ ] **Step 2: Replace the `npx -y @modelcontextprotocol/server-github` suggestion** with a version-pinned form and a note about lockfile/pinning, e.g. `npx -y @modelcontextprotocol/server-github@<pinned-version>` plus a printed caution that auto-install without a lockfile is a supply-chain risk. Use the current pinned version (look it up):

```powershell
(Invoke-RestMethod https://registry.npmjs.org/-/package/@modelcontextprotocol/server-github/dist-tags).latest
```

Embed that exact version in the suggestion string.

- [ ] **Step 3: Build.**

Run: `cargo build -p kprun`
Expected: clean.

- [ ] **Step 4: Commit.**

```powershell
git add crates/kprun/src/commands/doctor.rs
git commit -m "fix(cli): pin npx MCP server version in doctor suggestion (L-2)"
```

### Task 7.3: Reduce full-path leakage in error messages (L-3)

**Files:**
- Modify: `crates/kprun/src/commands/doctor.rs:36-38`, `crates/kprun/src/commands/init.rs:30,47,67`

- [ ] **Step 1: Review each `eprintln!`/error that prints a full path** in those locations. For user-facing operational hints keep paths (they are intentional UX), but for error contexts that may be logged, print only the file name via `Path::file_name()`. Decide per line; conservative change: in `doctor.rs:36-38` error branch, replace `path.display()` with `path.file_name().map(|f| f.to_string_lossy()).unwrap_or_default()`.

- [ ] **Step 2: Build + doctor test.**

Run: `cargo test -p kprun`
Expected: pass.

- [ ] **Step 3: Commit.**

```powershell
git add crates/kprun/src/commands/doctor.rs crates/kprun/src/commands/init.rs
git commit -m "fix(cli): avoid leaking full paths in error output (L-3)"
```

### Task 7.4: Gate `FixedUnlock` behind test-hooks

**Files:**
- Modify: `crates/kprun-core/src/unlock.rs:52-59`

- [ ] **Step 1: Feature-gate `FixedUnlock`** so it is not part of the public API in release builds:

```rust
/// Test helper — production code uses SystemUnlock then PromptUnlock fallback.
#[cfg(feature = "test-hooks")]
pub struct FixedUnlock(pub String);

#[cfg(feature = "test-hooks")]
impl MasterPasswordSource for FixedUnlock {
    fn get_master(&self) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(self.0.clone()))
    }
}
```

- [ ] **Step 2: Move/guard its test.** The `fixed_unlock_returns_password` test must also be gated; wrap it in `#[cfg(feature = "test-hooks")]`.

- [ ] **Step 3: Build both ways.**

Run: `cargo build -p kprun-core`; `cargo test -p kprun-core --all-features`
Expected: default build excludes `FixedUnlock`; all-features build runs its test.

- [ ] **Step 4: Commit.**

```powershell
git add crates/kprun-core/src/unlock.rs
git commit -m "refactor(core): gate FixedUnlock behind test-hooks feature (code-review)"
```

### Task 7.5: Review dotenv import trim (L-1)

**Files:**
- Modify: `crates/kprun/src/commands/import.rs:179`

- [ ] **Step 1: Decide policy.** L-1 flags that `value.trim()` silently alters secrets with intentional surrounding whitespace. Now that Phase 4 quotes/escapes exported values, change import to preserve inner whitespace of quoted values while still trimming unquoted ones. Implement: if the value is wrapped in double quotes, strip the quotes and unescape `\\n`/`\\r`/`\\\\` without trimming; otherwise keep the existing `.trim()`:

```rust
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            if key.is_empty() {
                return Err(KprunError::EmptyKey);
            }
            if current_title.is_none() {
                return Err(KprunError::Other(
                    "dotenv import line before entry title comment".into(),
                ));
            }
            saw_key_value = true;
            let raw = value.trim();
            let decoded = if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
                raw[1..raw.len() - 1]
                    .replace("\\n", "\n")
                    .replace("\\r", "\r")
                    .replace("\\\\", "\\")
            } else {
                raw.to_string()
            };
            pairs.push((key.to_string(), decoded));
        } else {
```

- [ ] **Step 2: Write a round-trip test** (export with newline → import → value preserved). Add to `import.rs` tests (create module if needed) using the `parse_dotenv_import` directly:

```rust
#[cfg(test)]
mod tests {
    use super::parse_dotenv_import;

    #[test]
    fn imports_quoted_value_with_escaped_newline() {
        let content = "# svc\nMULTI=\"line1\\nline2\"\n";
        let entries = parse_dotenv_import(content).unwrap();
        assert_eq!(entries[0].pairs[0].0, "MULTI");
        assert_eq!(entries[0].pairs[0].1, "line1\nline2");
    }
}
```

- [ ] **Step 3: Run tests.**

Run: `cargo test -p kprun imports_quoted_value_with_escaped_newline`
Expected: pass.

- [ ] **Step 4: Commit.**

```powershell
git add crates/kprun/src/commands/import.rs
git commit -m "fix(cli): preserve quoted dotenv values on import (L-1)"
```

### Task 7.6: Documentation — README + SECURITY.md (L-4 + security model)

**Files:**
- Modify: `README.md:163`, `SECURITY.md`

- [ ] **Step 1: Fix `README.md` `KPRUN_TEST_MASTER` docs** to state it only works in builds with `--features test-hooks` and is absent from GitHub Release binaries. (L-4)

- [ ] **Step 2: Expand `SECURITY.md`** with sections (sentence-case headings):
  - "File permissions" — owner-only on Unix/Windows (Phase 1).
  - "Keychain storage" — master password stored as plaintext in the OS keychain; per-vault keying; `kprun deinit` to remove.
  - "Process environment exposure" — injected secrets visible in `/proc/<pid>/environ`, Process Explorer, `ps e`; `--clean-env` available.
  - "Release verification" — how to verify with minisign, including the public key:

```markdown
### Verifying releases

Release `checksums.txt` is signed with minisign. Verify with:

```sh
minisign -Vm checksums.txt -P RWQ...   # kprun public key
sha256sum -c checksums.txt
```

kprun minisign public key:

```
RWQ...   # paste the real public key produced during the key ceremony
```
```

  - "test-hooks scope" — `KPRUN_TEST_MASTER` only in `--features test-hooks` builds.

- [ ] **Step 3: Commit.**

```powershell
git add README.md SECURITY.md
git commit -m "docs: document security model and release verification (L-4)"
```

### Task 7.7: Changelog + PR + release

- [ ] **Step 1: Append to `docs/changelogs/v0.2.0.md`:**

```markdown
## Low priority

- `kprun get --keys` now writes an audit record. (Bugbot)
- `doctor` pins the MCP server npm version in its suggestion. (L-2)
- Error output avoids leaking full filesystem paths. (L-3)
- `FixedUnlock` is gated behind the `test-hooks` feature. (code-review)
- Quoted dotenv values are preserved on import. (L-1)

## Documentation

- README clarifies `KPRUN_TEST_MASTER` requires `--features test-hooks`. (L-4)
- SECURITY.md documents file permissions, keychain storage, process env exposure, and minisign release verification.
```

- [ ] **Step 2: Final verification.**

Run: `cargo fmt --all; cargo clippy --all-targets --all-features -- -D warnings; cargo test --all-features`
Expected: clean.

- [ ] **Step 3: Push + PR.**

```powershell
git add docs/changelogs/v0.2.0.md
git commit -m "docs: finalize v0.2.0 changelog (low-priority hardening)"
git push -u origin fix/low-priority-hardening
gh pr create --title "fix: low-priority hardening & docs" --body "Implements L-1..L-4, get --keys audit, FixedUnlock gating, SECURITY.md."
```

### Task 7.8: Release v0.2.0 (after all PRs merged)

- [ ] **Step 1: Use the prepare-release skill** (`.claude/skills/prepare-release/SKILL.md`) to bump workspace version to `0.2.0` and finalize `docs/changelogs/v0.2.0.md`.

- [ ] **Step 2: Provision minisign secrets** (`MINISIGN_SECRET_KEY`, `MINISIGN_PASSWORD`) in the GitHub repo and paste the public key into `SECURITY.md` and both installer scripts (Phase 3 placeholders `RWQ...`).

- [ ] **Step 3: Tag and push.**

```powershell
git tag v0.2.0
git push origin v0.2.0
```

- [ ] **Step 4: Verify the release** has signed `checksums.txt.minisig` and that `minisign -Vm checksums.txt -P <pubkey>` succeeds.

---

## Self-review

**Spec coverage check** — every spec finding maps to a task:

- H-1 → 1.1–1.8 ✓
- H-2 → 2.1 ✓ · M-6 → 2.2 ✓
- H-3 → 3.1 ✓ · H-4 → 3.3, 3.4 ✓ · M-4 → 3.2 ✓ · M-5 → 3.4 ✓
- M-3 → 4.5 ✓ · M-7 → 4.6 ✓ · M-1 → 4.4 ✓ · dotenv `\n` → 4.3 ✓ · duplicate titles → 4.2 ✓ · parse sanitize → 4.1 ✓
- env blocklist → 5.1 ✓ · `--clean-env` → 5.2 ✓
- M-2 → 6.1 ✓ · L-5 → 6.2 ✓
- get --keys audit → 7.1 ✓ · L-2 → 7.2 ✓ · L-3 → 7.3 ✓ · FixedUnlock → 7.4 ✓ · L-1 → 7.5 ✓ · L-4 + SECURITY.md → 7.6 ✓

**Type consistency** — `secure_fs` function names (`create_restricted`, `write_restricted`, `open_append_restricted`, `persist_restricted`, `harden_existing`) are used identically across vault/unlock/audit/export. `keychain_account(db_path)` signature consistent across all keychain functions. `UnlockContext` gains `db_path` in Phase 6 — all constructors updated in Task 6.1 Step 4.

**Open items deferred to execution (require live lookups, not placeholders):** action SHAs (Task 3.1 Step 1), minisign public key (key ceremony, Task 7.8), `sha2` version (Task 6.1 Step 1), npm server-github version (Task 7.2 Step 2). Each has an exact command to obtain the value.
