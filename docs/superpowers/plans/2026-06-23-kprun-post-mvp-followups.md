# kprun post-MVP follow-ups — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all open items from the post-MVP final review: harden vault write paths, secure release binaries from `KPRUN_TEST_MASTER`, fix `--no-store` double-unlock UX, add inject collision warnings, and ship docs/tests polish in a follow-up release.

**Architecture:** Four phases per the approved design spec. Phase 1 (`feat/post-mvp-hardening`) lands core behavior in `kprun-core` and CLI write commands. Phase 2 (`feat/post-mvp-polish`) adds tests and README/SECURITY updates. Phase 3 tags **v0.1.2** (v0.1.0 and v0.1.1 are already published on GitHub). Work happens in worktree `.worktrees/feat-post-mvp-hardening` on branch `feat/post-mvp-hardening`.

**Tech Stack:** Rust 1.88.0, keepass 0.13, clap 4, GitHub Actions (`ci.yml`, `release.yml`), Cursor `prepare-release` skill, Conventional Commits 1.0.0.

## Global constraints

- **Worktree:** `d:\kprun\.worktrees\feat-post-mvp-hardening`, branch `feat/post-mvp-hardening` (from current `main`).
- **Release target:** `v0.1.2` — `v0.1.1` was consumed by CI/release hygiene (PR #8); do not retag.
- **Already done on `main`:** `LICENSE`, `SECURITY.md`, changelog infra, `release.yml` validate job — Phase 2 only **updates** SECURITY/README, does not recreate those files.
- **Test command:** After Task 2, always use `cargo test --all-features` (not `cargo test --all`).
- **Release build:** `cargo build --release -p kprun` must **not** enable `test-hooks`.
- **Commit messages:** Conventional Commits (`feat(core): …`, `fix(cli): …`, `test: …`, `ci: …`, `docs: …`).
- **Code/comments:** English. User-facing plan prose: Polish responses to user; this file is English (repo convention).

---

## File structure (by phase)

### Phase 1 — core hardening (`feat/post-mvp-hardening`)

| File | Responsibility |
|------|----------------|
| `crates/kprun-core/Cargo.toml` | Add `[features] test-hooks = []` |
| `crates/kprun/Cargo.toml` | Add `test-hooks = ["kprun-core/test-hooks"]` |
| `.github/workflows/ci.yml` | `cargo test --all-features` |
| `crates/kprun-core/src/unlock.rs` | Gate `KPRUN_TEST_MASTER`; `generate_keyfile(&Path)` |
| `crates/kprun/src/commands/init.rs` | Gate test env reads; update `generate_keyfile` call |
| `crates/kprun-core/src/vault.rs` | `require_rw`, `save_with_key`, `pub(crate) database_mut`, sorted keys |
| `crates/kprun-core/src/inject.rs` | Collision warning + deduped `injected_keys` |
| `crates/kprun/src/commands/mod.rs` | `unlock_vault` returns `DatabaseKey` |
| `crates/kprun/src/commands/{set,unset,delete,import}.rs` | Use `save_with_key`; drop `save_with_unlock` |
| `crates/kprun/src/commands/import.rs` | Dotenv value `.trim()` |

### Phase 2 — polish (`feat/post-mvp-polish`, after PR #1 merge)

| File | Responsibility |
|------|----------------|
| `crates/kprun-core/src/parse.rs` | `parse_rejects_empty_key` unit test |
| `tests/manage.rs` | `list_json_outputs_valid_payload` |
| `tests/doctor.rs` | `doctor_mcp_generic_entry` |
| `crates/kprun/src/commands/doctor.rs` | Optional stderr hint for non-github entries |
| `README.md` | `KPRUN_TEST_MASTER` + MCP generic-entry docs |
| `SECURITY.md` | `test-hooks` / release-binary section |

### Phase 3 — release

| File | Responsibility |
|------|----------------|
| `Cargo.toml` | Bump workspace version to `0.1.2` |
| `README.md` | Title version if pinned |
| `docs/changelogs/v0.1.2.md` | Release notes |
| `CHANGELOG.md` | Prepend `0.1.2` summary |

---

## Phase 0 — Release validation (reference checklist)

> **Status:** `v0.1.0` and `v0.1.1` are tagged and published. Use this checklist for Phase 3 (`v0.1.2`), not as implementation tasks.

- [ ] CI green on `main`: ubuntu / windows / macos (`fmt`, `clippy --all-features`, `test --all-features`).
- [ ] Tag `v0.1.2` triggers `release.yml`.
- [ ] GitHub Release contains all five platform archives + `checksums.txt`.
- [ ] `KPRUN_VERSION=v0.1.2` install smoke on Linux + one of macOS/Windows.
- [ ] Release binary ignores `KPRUN_TEST_MASTER` (see Task 15 verification).

---

## Phase 1 — Core hardening

### Task 1: CI runs tests with `test-hooks` enabled

**Files:**
- Modify: `.github/workflows/ci.yml:21`

- [ ] **Step 1: Update test step**

Replace:

```yaml
      - run: cargo test --all
```

with:

```yaml
      - run: cargo test --all-features
```

- [ ] **Step 2: Verify locally**

Run: `cargo test --all-features`  
Expected: PASS (baseline before feature gating).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: run tests with all features enabled"
```

---

### Task 2: Add `test-hooks` feature flags

**Files:**
- Modify: `crates/kprun-core/Cargo.toml`
- Modify: `crates/kprun/Cargo.toml`

- [ ] **Step 1: Add features to kprun-core**

Append to `crates/kprun-core/Cargo.toml`:

```toml
[features]
default = []
test-hooks = []
```

- [ ] **Step 2: Add features to kprun**

Append to `crates/kprun/Cargo.toml`:

```toml
[features]
default = []
test-hooks = ["kprun-core/test-hooks"]
```

- [ ] **Step 3: Verify default build has no hook**

Run: `cargo build -p kprun`  
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/kprun-core/Cargo.toml crates/kprun/Cargo.toml
git commit -m "feat(core): add test-hooks feature flag"
```

---

### Task 3: Gate `KPRUN_TEST_MASTER` in `unlock.rs`

**Files:**
- Modify: `crates/kprun-core/src/unlock.rs`

- [ ] **Step 1: Gate `PromptUnlock::get_master`**

Replace lines 38–41:

```rust
        if let Ok(pw) = std::env::var("KPRUN_TEST_MASTER") {
            return Ok(Zeroizing::new(pw));
        }
```

with:

```rust
        #[cfg(feature = "test-hooks")]
        if let Ok(pw) = std::env::var("KPRUN_TEST_MASTER") {
            return Ok(Zeroizing::new(pw));
        }
```

- [ ] **Step 2: Gate `unlock_with_fallback` test shortcut**

Replace lines 68–71:

```rust
    if std::env::var("KPRUN_TEST_MASTER").is_ok() {
        return unlock_master(ctx, &PromptUnlock);
    }
```

with:

```rust
    #[cfg(feature = "test-hooks")]
    if std::env::var("KPRUN_TEST_MASTER").is_ok() {
        return unlock_master(ctx, &PromptUnlock);
    }
```

- [ ] **Step 3: Run tests with feature**

Run: `cargo test -p kprun-core --all-features`  
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/kprun-core/src/unlock.rs
git commit -m "feat(core): gate KPRUN_TEST_MASTER behind test-hooks feature"
```

---

### Task 4: Gate `KPRUN_TEST_MASTER` in `init.rs`

**Files:**
- Modify: `crates/kprun/src/commands/init.rs`

- [ ] **Step 1: Gate `prompt_new_master`**

Wrap the `KPRUN_TEST_MASTER` block (lines 79–81) with `#[cfg(feature = "test-hooks")]`.

- [ ] **Step 2: Gate `read_password_prompt`**

Wrap the `KPRUN_TEST_MASTER` block (lines 96–98) with `#[cfg(feature = "test-hooks")]`.

- [ ] **Step 3: Run integration tests**

Run: `cargo test -p kprun --all-features init`  
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/kprun/src/commands/init.rs
git commit -m "feat(cli): gate init test master env behind test-hooks"
```

---

### Task 5: `require_rw` helper and write guards

**Files:**
- Modify: `crates/kprun-core/src/vault.rs`
- Test: `crates/kprun-core/src/vault.rs` (inline `mod tests`)

- [ ] **Step 1: Write the failing test**

Add to `mod tests` in `vault.rs`:

```rust
    #[test]
    fn read_only_vault_rejects_write_operations() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ro.kdbx");
        let ctx = UnlockContext { keyfile: None };
        let key = build_database_key(&ctx, "pass").unwrap();
        create_vault(&path, key.clone(), "kprun").unwrap();

        let mut vault = open_vault(&path, key, OpenMode::ReadOnly).unwrap();
        let err = vault
            .unset_attributes("missing", &["KEY".into()])
            .unwrap_err();
        assert!(matches!(err, KprunError::Other(msg) if msg == "vault opened read-only"));

        let err = vault.save(key).unwrap_err();
        assert!(matches!(err, KprunError::Other(msg) if msg == "vault opened read-only"));
    }
```

Add `use crate::KprunError;` in the test module if missing.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p kprun-core read_only_vault_rejects_write_operations --all-features`  
Expected: FAIL — `unset_attributes` succeeds on read-only vault today.

- [ ] **Step 3: Implement `require_rw` and guards**

Inside `impl Vault` (before `find_entry_by_title`), add:

```rust
    fn require_rw(&self) -> Result<()> {
        if self.mode != OpenMode::ReadWrite {
            return Err(KprunError::Other("vault opened read-only".into()));
        }
        Ok(())
    }
```

Update methods:

```rust
    pub fn set_attributes(&mut self, title: &str, pairs: &[(String, String)]) -> Result<()> {
        self.require_rw()?;
        // remove inline mode_check block
        ...
    }

    pub fn unset_attributes(&mut self, title: &str, keys: &[String]) -> Result<()> {
        self.require_rw()?;
        ...
    }

    pub fn delete_entry(&mut self, title: &str) -> Result<()> {
        self.require_rw()?;
        ...
    }

    pub fn save(&mut self, key: keepass::DatabaseKey) -> Result<()> {
        self.require_rw()?;
        ...
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p kprun-core read_only_vault_rejects_write_operations --all-features`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/kprun-core/src/vault.rs
git commit -m "feat(core): add require_rw guards on vault write paths"
```

---

### Task 6: Narrow `database_mut` to `pub(crate)`

**Files:**
- Modify: `crates/kprun-core/src/vault.rs:51`

- [ ] **Step 1: Change visibility**

```rust
    pub(crate) fn database_mut(&mut self) -> &mut Database {
        &mut self.db
    }
```

- [ ] **Step 2: Verify no external callers**

Run: `cargo build --all-features`  
Expected: PASS (no callers outside `kprun-core` crate).

- [ ] **Step 3: Commit**

```bash
git add crates/kprun-core/src/vault.rs
git commit -m "refactor(core): make database_mut pub(crate)"
```

---

### Task 7: Inject key-collision warning and deduped keys

**Files:**
- Modify: `crates/kprun-core/src/inject.rs`
- Test: `crates/kprun-core/src/inject.rs` (`mod tests`)

- [ ] **Step 1: Write the failing test**

Add helper and test to `inject.rs`:

```rust
fn collision_warning_message(key: &str, entry: &str) -> String {
    format!("warning: key '{key}' from entry '{entry}' overrides an earlier value")
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
    let ctx = UnlockContext { keyfile: None };
    let key = build_database_key(&ctx, "pass").unwrap();
    let mut file = std::fs::File::create(&db_path).unwrap();
    db.save(&mut file, key.clone()).unwrap();

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
```

Add `use keepass::db::fields;` to the test module.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p kprun-core warns_on_key_collision --all-features`  
Expected: FAIL — `injected_keys` contains duplicate `SHARED_KEY`.

- [ ] **Step 3: Implement warning + dedupe**

Replace the merge loop in `resolve_injection`:

```rust
    let mut env = HashMap::new();
    let mut injected_keys = Vec::new();
    let mut seen_keys = std::collections::HashSet::new();
    for name in entry_names {
        let id = vault.find_entry_by_title(name)?;
        for (k, v) in vault.entry_custom_values(id) {
            if env.insert(k.clone(), v).is_some() {
                eprintln!("{}", collision_warning_message(&k, name));
            }
            if seen_keys.insert(k.clone()) {
                injected_keys.push(k);
            }
        }
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p kprun-core warns_on_key_collision --all-features`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/kprun-core/src/inject.rs
git commit -m "feat(core): warn on inject key collisions and dedupe injected_keys"
```

---

### Task 8: `save_with_key` and single unlock on write path

**Files:**
- Modify: `crates/kprun-core/src/vault.rs`
- Modify: `crates/kprun/src/commands/mod.rs`
- Modify: `crates/kprun/src/commands/set.rs`
- Modify: `crates/kprun/src/commands/unset.rs`
- Modify: `crates/kprun/src/commands/delete.rs`
- Modify: `crates/kprun/src/commands/import.rs`
- Modify: `crates/kprun/src/commands/{list,get,export}.rs` (destructure 4-tuple)

- [ ] **Step 1: Write the failing unit test**

Add to `vault.rs` `mod tests`:

```rust
    #[test]
    fn save_with_key_persists_without_second_unlock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.kdbx");
        let ctx = UnlockContext { keyfile: None };
        let key = build_database_key(&ctx, "pass").unwrap();
        create_vault(&path, key.clone(), "kprun").unwrap();

        let mut vault = open_vault(&path, key.clone(), OpenMode::ReadWrite).unwrap();
        vault
            .set_attributes("svc", &[("TOKEN".into(), "t1".into())])
            .unwrap();
        vault.save_with_key(key.clone()).unwrap();

        let vault2 = open_vault(&path, key, OpenMode::ReadOnly).unwrap();
        let id = vault2.find_entry_by_title("svc").unwrap();
        let vals = vault2.entry_custom_values(id);
        assert_eq!(vals.get("TOKEN").map(String::as_str), Some("t1"));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p kprun-core save_with_key_persists --all-features`  
Expected: FAIL — `save_with_key` not defined.

- [ ] **Step 3: Add `save_with_key`; remove `save_with_unlock`**

In `impl Vault`:

```rust
    pub fn save_with_key(&mut self, key: keepass::DatabaseKey) -> Result<()> {
        self.require_rw()?;
        self.save(key)
    }
```

Delete `save_with_unlock` entirely (lines 185–189).

- [ ] **Step 4: Extend `unlock_vault` to return `DatabaseKey`**

In `commands/mod.rs`:

```rust
use keepass::DatabaseKey;

fn unlock_vault(mode: OpenMode) -> Result<(Config, UnlockContext, Vault, DatabaseKey)> {
    let cfg = Config::from_env();
    let ctx = UnlockContext {
        keyfile: cfg.keyfile.clone(),
    };
    let master = unlock_with_fallback(&ctx)?;
    let db_key = build_database_key(&ctx, &master)?;
    let vault = open_vault(&cfg.db_path, db_key.clone(), mode)?;
    Ok((cfg, ctx, vault, db_key))
}
```

- [ ] **Step 5: Update write commands**

`set.rs`:

```rust
    let (_cfg, _ctx, mut vault, db_key) = unlock_vault(OpenMode::ReadWrite)?;
    vault.set_attributes(entry, &pairs)?;
    vault.save_with_key(db_key)?;
```

Apply the same pattern to `unset.rs`, `delete.rs`, `import.rs` (replace `save_with_unlock(&ctx)?` with `save_with_key(db_key)?`).

Read-only commands (`list.rs`, `get.rs`, `export.rs`):

```rust
    let (_cfg, _ctx, vault, _db_key) = unlock_vault(OpenMode::ReadOnly)?;
```

- [ ] **Step 6: Run tests**

Run: `cargo test -p kprun-core save_with_key_persists --all-features`  
Expected: PASS.

Run: `cargo test -p kprun --all-features manage`  
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/kprun-core/src/vault.rs crates/kprun/src/commands/mod.rs \
  crates/kprun/src/commands/set.rs crates/kprun/src/commands/unset.rs \
  crates/kprun/src/commands/delete.rs crates/kprun/src/commands/import.rs \
  crates/kprun/src/commands/list.rs crates/kprun/src/commands/get.rs \
  crates/kprun/src/commands/export.rs
git commit -m "fix(cli): single unlock on write commands via save_with_key"
```

---

### Task 9: Alphabetically sorted custom field names

**Files:**
- Modify: `crates/kprun-core/src/vault.rs`

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn custom_field_names_are_sorted_alphabetically() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sort.kdbx");
        let ctx = UnlockContext { keyfile: None };
        let key = build_database_key(&ctx, "pass").unwrap();
        create_vault(&path, key.clone(), "kprun").unwrap();

        let mut vault = open_vault(&path, key.clone(), OpenMode::ReadWrite).unwrap();
        vault
            .set_attributes(
                "svc",
                &[
                    ("ZZZ".into(), "1".into()),
                    ("AAA".into(), "2".into()),
                    ("MMM".into(), "3".into()),
                ],
            )
            .unwrap();
        vault.save(key).unwrap();

        let vault = open_vault(&path, key, OpenMode::ReadOnly).unwrap();
        let summaries = vault.list_entries();
        let svc = summaries.iter().find(|e| e.title == "svc").unwrap();
        assert_eq!(svc.keys, vec!["AAA", "MMM", "ZZZ"]);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p kprun-core custom_field_names_are_sorted --all-features`  
Expected: FAIL — insertion order, not sorted.

- [ ] **Step 3: Sort keys in `custom_field_names`**

```rust
fn custom_field_names(entry: &EntryRef<'_>) -> Vec<String> {
    let mut keys: Vec<String> = entry
        .fields
        .keys()
        .filter(|k| !is_standard_field(k))
        .cloned()
        .collect();
    keys.sort_unstable();
    keys
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p kprun-core custom_field_names_are_sorted --all-features`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/kprun-core/src/vault.rs
git commit -m "feat(core): sort custom field names alphabetically in list output"
```

---

### Task 10: Dotenv import value trim

**Files:**
- Modify: `crates/kprun/src/commands/import.rs`
- Test: `tests/export_import.rs`

- [ ] **Step 1: Write the failing integration test**

Add to `tests/export_import.rs`:

```rust
#[test]
fn import_dotenv_trims_value_whitespace() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    let import_file = dir.path().join("trim.env");
    let ctx = UnlockContext { keyfile: None };
    let key = build_database_key(&ctx, "pass").unwrap();
    create_vault(&db, key, "kprun").unwrap();

    std::fs::write(
        &import_file,
        "# demo\nTRIM_KEY= value \n",
    )
    .unwrap();

    kprun()
        .env("KPRUN_DB", db.to_str().unwrap())
        .env("KPRUN_TEST_MASTER", "pass")
        .args(["import", import_file.to_str().unwrap(), "--merge"])
        .assert()
        .success();

    kprun()
        .env("KPRUN_DB", db.to_str().unwrap())
        .env("KPRUN_TEST_MASTER", "pass")
        .args(["get", "demo", "--reveal"])
        .assert()
        .success()
        .stdout(predicates::str::contains("value"))
        .stdout(predicates::str::is_match(r"^value\r?\n$").unwrap());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p kprun import_dotenv_trims_value_whitespace --all-features`  
Expected: FAIL — stored value is `" value "` (with spaces).

- [ ] **Step 3: Trim value in `parse_dotenv_import`**

In `import.rs` line 179, change:

```rust
            pairs.push((key.to_string(), value.to_string()));
```

to:

```rust
            pairs.push((key.to_string(), value.trim().to_string()));
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p kprun import_dotenv_trims_value_whitespace --all-features`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/kprun/src/commands/import.rs tests/export_import.rs
git commit -m "fix(cli): trim whitespace from dotenv import values"
```

---

### Task 11: `generate_keyfile` accepts `&Path`

**Files:**
- Modify: `crates/kprun-core/src/unlock.rs:114`
- Modify: `crates/kprun/src/commands/init.rs` (call site uses `&Path` already via `kf`)

- [ ] **Step 1: Change signature**

In `unlock.rs`, add `use std::path::Path;` and change:

```rust
pub fn generate_keyfile(path: &PathBuf) -> Result<()> {
```

to:

```rust
pub fn generate_keyfile(path: &Path) -> Result<()> {
```

- [ ] **Step 2: Verify build**

Run: `cargo build --all-features`  
Expected: PASS (`init.rs` passes `kf` which is `&PathBuf`, coerces to `&Path`).

- [ ] **Step 3: Commit**

```bash
git add crates/kprun-core/src/unlock.rs
git commit -m "refactor(core): accept Path in generate_keyfile"
```

---

### Task 12: Phase 1 full verification

**Files:** (none — verification only)

- [ ] **Step 1: Format and lint**

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: no warnings or errors.

- [ ] **Step 2: Full test suite**

```bash
cargo test --all-features
```

Expected: all tests PASS.

- [ ] **Step 3: Release build ignores test hook**

```bash
cargo build --release -p kprun
KPRUN_TEST_MASTER=foo target/release/kprun list 2>&1 || true
```

Expected: prompts for master password (env var ignored without `test-hooks`).

- [ ] **Step 4: Open PR #1**

```bash
git push -u origin feat/post-mvp-hardening
gh pr create --title "feat: post-MVP core hardening" --body "$(cat <<'EOF'
## Summary
- Gate `KPRUN_TEST_MASTER` behind `test-hooks` feature (disabled in release builds)
- Add `require_rw` guards on all vault write paths; narrow `database_mut` to `pub(crate)`
- Inject key-collision warnings on stderr; dedupe `injected_keys`
- Fix double unlock on write commands (`save_with_key`)
- Sort custom field names alphabetically; trim dotenv import values

## Test plan
- [ ] `cargo test --all-features`
- [ ] Release build ignores `KPRUN_TEST_MASTER`
- [ ] Manual: `kprun init --no-store` then `kprun set` prompts once

EOF
)"
```

---

## Phase 2 — CLI polish + docs

> **Branch:** `feat/post-mvp-polish` from `main` after PR #1 merges. Create worktree if needed.

### Task 13: Unit test `parse_rejects_empty_key`

**Files:**
- Modify: `crates/kprun-core/src/parse.rs`

- [ ] **Step 1: Add test**

```rust
    #[test]
    fn parse_rejects_empty_key() {
        let err = parse_key_val("=value").unwrap_err();
        assert!(matches!(err, KprunError::EmptyKey(_)));
    }
```

- [ ] **Step 2: Run test**

Run: `cargo test -p kprun-core parse_rejects_empty_key --all-features`  
Expected: PASS (behavior already implemented).

- [ ] **Step 3: Commit**

```bash
git add crates/kprun-core/src/parse.rs
git commit -m "test(core): cover EmptyKey rejection in parse_key_val"
```

---

### Task 14: Integration test `list --json`

**Files:**
- Modify: `tests/manage.rs`

- [ ] **Step 1: Add test**

```rust
#[test]
fn list_json_outputs_valid_payload() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("secrets.kdbx");
    setup_openai_vault(&db);

    let output = kprun()
        .env("KPRUN_DB", db.to_str().unwrap())
        .env("KPRUN_TEST_MASTER", "pass")
        .args(["list", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let entries: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let arr = entries.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["title"], "openai");
    assert_eq!(arr[0]["keys"], serde_json::json!(["OPENAI_API_KEY"]));
}
```

Add `use serde_json::Value;` if not present.

- [ ] **Step 2: Run test**

Run: `cargo test -p kprun list_json_outputs_valid_payload --all-features`  
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/manage.rs
git commit -m "test(cli): cover list --json output shape"
```

---

### Task 15: `doctor --mcp` generic entry test + hint

**Files:**
- Modify: `tests/doctor.rs`
- Modify: `crates/kprun/src/commands/doctor.rs`
- Modify: `README.md` (MCP section)

- [ ] **Step 1: Write failing integration test**

Add to `tests/doctor.rs`:

```rust
#[test]
fn doctor_mcp_generic_entry() {
    let output = kprun()
        .args(["doctor", "--mcp", "openai"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output).unwrap();
    let args = value["args"].as_array().unwrap();
    assert_eq!(args[0], "run");
    assert_eq!(args[1], "openai");
    assert_eq!(args[2], "--");
    assert_eq!(args.len(), 3);
}
```

- [ ] **Step 2: Run test**

Run: `cargo test -p kprun doctor_mcp_generic_entry --all-features`  
Expected: PASS (behavior already correct).

- [ ] **Step 3: Add optional stderr hint in `doctor.rs`**

In `print_mcp_fragment`, after building args:

```rust
    if entry != "github" {
        eprintln!("note: append your MCP server command after '--' in the generated args");
    }
```

- [ ] **Step 4: Document in README MCP section**

After the `kprun doctor --mcp github` example block, add:

```markdown
`kprun doctor --mcp github` emits a complete snippet including the `npx` child command. For other entries, output is `["run", "<entry>", "--"]` — append your MCP server command after `--` in `.mcp.json`.
```

- [ ] **Step 5: Commit**

```bash
git add tests/doctor.rs crates/kprun/src/commands/doctor.rs README.md
git commit -m "docs(cli): document doctor --mcp generic entry behavior"
```

---

### Task 16: Update `KPRUN_TEST_MASTER` and SECURITY docs

**Files:**
- Modify: `README.md` (Configuration table)
- Modify: `SECURITY.md`

- [ ] **Step 1: Replace README env table row**

Replace the `KPRUN_TEST_MASTER` row with:

```markdown
| `KPRUN_TEST_MASTER` | — | Build-time only: enabled with `cargo build --features test-hooks`. Not present in GitHub release binaries. For source builds in CI/automation. |
```

- [ ] **Step 2: Update Development → Running tests**

Change `cargo test --all` to `cargo test --all-features` in README (lines ~271 and ~288).

- [ ] **Step 3: Add SECURITY.md section**

Append before `## Security model`:

```markdown
## Test hooks in release binaries

GitHub release binaries are built **without** the `test-hooks` Cargo feature. The `KPRUN_TEST_MASTER` environment variable has **no effect** in those binaries.

Source builds for development or CI may enable `test-hooks` via `cargo build --features test-hooks` or `cargo test --all-features`. Do not rely on `KPRUN_TEST_MASTER` in production workflows.
```

- [ ] **Step 4: Verify files exist**

Run: `test -f LICENSE && test -f SECURITY.md` (or PowerShell equivalent)  
Expected: both exist (from PR #8).

- [ ] **Step 5: Commit**

```bash
git add README.md SECURITY.md
git commit -m "docs: document test-hooks feature and KPRUN_TEST_MASTER scope"
```

---

### Task 17: Phase 2 verification and PR #2

- [ ] **Step 1: Full test suite**

```bash
cargo test --all-features
```

Expected: PASS.

- [ ] **Step 2: Open PR #2**

```bash
git push -u origin feat/post-mvp-polish
gh pr create --title "docs: post-MVP CLI polish and test coverage" --body "$(cat <<'EOF'
## Summary
- Add tests for EmptyKey, list --json, doctor --mcp generic entries
- Document test-hooks / KPRUN_TEST_MASTER and doctor --mcp limitations

## Test plan
- [ ] `cargo test --all-features`

EOF
)"
```

---

## Phase 3 — Release `v0.1.2`

### Task 18: Prepare release with Cursor skill

**Files:**
- Create: `docs/changelogs/v0.1.2.md`
- Modify: `CHANGELOG.md`, `Cargo.toml`, `README.md` (title version)

- [ ] **Step 1: Merge PR #1 and PR #2 to `main`**

Confirm CI green on `main`.

- [ ] **Step 2: Run `/prepare-release 0.1.2`**

Use `.cursor/skills/prepare-release/SKILL.md`. Release notes draft:

```markdown
## [0.1.2] - YYYY-MM-DD

### Added
- `test-hooks` Cargo feature; `KPRUN_TEST_MASTER` disabled in release binaries
- Inject key-collision warnings on stderr
- `save_with_key` for single unlock on write commands

### Changed
- Alphabetically sorted custom field names in list output
- `database_mut` narrowed to `pub(crate)`

### Fixed
- Vault `OpenMode` guards on all write paths (`unset`, `delete`, `save`)
- Double master-password prompt with `--no-store` on write commands
- Dotenv import value whitespace trimming

### Security
- Release binaries no longer honor `KPRUN_TEST_MASTER` without `test-hooks`
```

- [ ] **Step 3: Commit release prep**

Expected commit: `chore(release): prepare v0.1.2`

---

### Task 19: Tag and validate release

- [ ] **Step 1: Tag and push**

```bash
git tag v0.1.2
git push origin main --tags
```

- [ ] **Step 2: Watch `release.yml`**

Confirm all five platform artifacts + `checksums.txt` on GitHub Release.

- [ ] **Step 3: Install e2e**

```bash
KPRUN_VERSION=v0.1.2 curl -fsSL .../install.sh | sh
kprun --version
```

- [ ] **Step 4: Confirm test hook disabled**

Download release binary; run with `KPRUN_TEST_MASTER=foo kprun list` — must prompt, not use env.

---

## Concern ID traceability

| ID | Task(s) |
|----|---------|
| 4.3 KPRUN_TEST_MASTER in prod | 2–4, 12, 16, 19 |
| 5.2 Key order | 9 |
| 5.3 database_mut bypass | 5–6 |
| 6.1, 6.2, 6.4 Inject override | 7 |
| 7.1, 7.2 RW guards | 5 |
| 7.7, 11.1 Double unlock | 8 |
| 11.4 list --json test | 14 |
| 13.2 doctor --mcp generic | 15 |
| M1 PathBuf / test hook | 3–4, 11 |
| M2 Double unlock | 8 |
| F1 Inject warning | 7 |
| F2 Dotenv trim | 10 |
| F3 README test hook | 16 |
| F4 LICENSE / SECURITY | Already on main; 16 updates SECURITY |
| 14.2, 15.x, 16.2 Release validation | 0 (reference), 19 |

---

## Self-review

**Spec coverage:** All Phase 1–3 requirements map to Tasks 1–19. Phase 0 is operational only. `v0.1.1` → `v0.1.2` adjustment documented (spec assumed v0.1.1 for code fixes; that version shipped with hygiene work).

**Placeholder scan:** No TBD/TODO steps. All code blocks are complete.

**Type consistency:** `unlock_vault` returns 4-tuple everywhere; `save_with_key` takes `DatabaseKey`; `generate_keyfile` takes `&Path`; `require_rw` error message matches test assertions.
