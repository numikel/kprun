# kprun post-MVP follow-ups — design spec

**Date:** 2026-06-23  
**Status:** Approved (brainstorming)  
**Source:** `.superpowers/sdd/task-18-final-review.md` (branch `feat/kprun-mvp`, verdict: approved with minor follow-ups)  
**Base:** `main` after MVP merge (PR #2)

## Summary

MVP is merged and **v0.1.0 release is in progress**. This spec covers all open follow-ups from the final branch review, delivered in four phases:

| Phase | When | Deliverable |
|-------|------|-------------|
| 0 | Now (parallel) | Validate `v0.1.0` release (CI, artifacts, install e2e) |
| 1 | After v0.1.0 | PR: core hardening |
| 2 | After phase 1 | PR: CLI polish + docs |
| 3 | After phase 2 | Tag `v0.1.1`, validate release |

**Decisions (brainstorming):**

- **Scope:** Full multi-phase plan (code + docs + release ops).
- **Release timing:** `v0.1.0` ships now; code fixes land in `v0.1.1`.
- **`KPRUN_TEST_MASTER`:** Feature flag `test-hooks` — disabled in release binaries (option B).

## Goals

| Goal | How |
|------|-----|
| Close review backlog | Map every open concern ID to a phase and acceptance criterion |
| Harden core API | `OpenMode` guards on all write paths; inject collision warnings |
| Fix `--no-store` UX | Single unlock on write commands (no double prompt) |
| Secure release binaries | `test-hooks` feature off by default in `release.yml` builds |
| Repo hygiene | Add `LICENSE`, `SECURITY.md`; document `doctor --mcp` limits |

## Non-goals

- Deterministic KeePass **entry** iteration order (KeePass API limitation; only key sorting within entries)
- Generic MCP child-command heuristics for every entry in `doctor --mcp` (document instead)
- Windows Arm64 release target (informational 16.3 — future work)
- Breaking API changes beyond narrowing `database_mut` to `pub(crate)`

---

## Phase 0 — Release validation (`v0.1.0`)

**Purpose:** Close operational items 14.2, 15.1–15.3, 16.2, 15.4 without product code changes.

### Steps

1. **Remote CI (14.2)** — Confirm green matrix on `main`: `ubuntu-latest`, `windows-latest`, `macos-latest` (`fmt`, `clippy --all-features`, `test`).
2. **Tag** — Push `v0.1.0`; `release.yml` triggers on `v*` tags.
3. **Artifact validation (15.1–15.3)** — Verify GitHub Release contains:
   - `kprun-x86_64-unknown-linux-gnu.tar.gz`
   - `kprun-aarch64-unknown-linux-gnu.tar.gz`
   - `kprun-x86_64-apple-darwin.tar.gz`
   - `kprun-aarch64-apple-darwin.tar.gz`
   - `kprun-x86_64-pc-windows-msvc.zip`
   - `checksums.txt`
   - Watch `aarch64-unknown-linux-gnu` cross-build logs (linker `aarch64-linux-gnu-gcc`).
   - Watch `x86_64-apple-darwin` on ARM macOS runner; add `MACOSX_DEPLOYMENT_TARGET` in follow-up only if build fails.
4. **Install e2e (16.2, 15.4)** — From a clean environment:
   - `KPRUN_VERSION=v0.1.0` + `install.sh` / `install.ps1` against GitHub Releases.
   - Verify SHA-256 checksum step passes.
   - Run `kprun --version`.
   - Windows: confirm `kprun.exe` at zip archive root.

### Acceptance criteria

- [ ] All five platform artifacts downloadable with matching checksums.
- [ ] Install scripts succeed on at least Linux and one of macOS/Windows manually.
- [ ] No code changes required unless release workflow fails (fix in hotfix branch, retag if needed).

---

## Phase 1 — Core hardening (PR #1)

**Branch:** `feat/post-mvp-hardening` from `main`  
**Closes:** 4.3, 5.2, 5.3, 6.1, 6.2, 6.4, 7.1, 7.2, 7.7, 11.1, M1, M2, F1, F2

### 1.1 Feature flag `test-hooks`

**Files:** `crates/kprun-core/Cargo.toml`, `crates/kprun/Cargo.toml`, `crates/kprun-core/src/unlock.rs`, `crates/kprun/src/commands/init.rs`

```toml
# kprun-core/Cargo.toml
[features]
default = []
test-hooks = []

# kprun/Cargo.toml
[features]
default = []
test-hooks = ["kprun-core/test-hooks"]
```

**Behavior:**

- All `std::env::var("KPRUN_TEST_MASTER")` reads wrapped in `#[cfg(feature = "test-hooks")]`.
- Release build (`cargo build --release -p kprun` in `release.yml`) — no feature — env var has no effect.
- CI runs `cargo clippy --all-targets --all-features`; **update** `ci.yml` test step from `cargo test --all` to `cargo test --all-features` so integration tests that set `KPRUN_TEST_MASTER` compile and run with the gated hook enabled.

**Locations to gate:**

- `PromptUnlock::get_master` in `unlock.rs`
- `prompt_new_master`, `read_password_prompt` in `init.rs`

Integration tests continue using `KPRUN_TEST_MASTER` via dev builds with `test-hooks` enabled in CI.

### 1.2 Vault `OpenMode` guards (5.3, 7.1, 7.2)

**File:** `crates/kprun-core/src/vault.rs`

Add private helper:

```rust
fn require_rw(&self) -> Result<()> {
    if self.mode != OpenMode::ReadWrite {
        return Err(KprunError::Other("vault opened read-only".into()));
    }
    Ok(())
}
```

| Method | Change |
|--------|--------|
| `set_attributes` | Replace inline check with `require_rw()?` |
| `unset_attributes` | Add `require_rw()?` at start |
| `delete_entry` | Add `require_rw()?` at start |
| `save` | Add `require_rw()?` at start |
| `database_mut` | Change to `pub(crate)` — remove from public crate API |

**Tests:** Add `read_only_vault_rejects_write_operations` — open `ReadOnly`, assert `unset_attributes`, `save` return error.

### 1.3 Inject key-collision warning (F1, 6.1, 6.2)

**File:** `crates/kprun-core/src/inject.rs`

When `env.insert(k.clone(), v).is_some()` during multi-entry merge:

```rust
eprintln!(
    "warning: key '{k}' from entry '{name}' overrides an earlier value"
);
```

- Warning on **stderr** only (MCP-safe; `run` stdout stays empty).
- **Deduplicate `injected_keys`:** after merge loop, retain unique keys in last-wins order (or build set while iterating — final list has no duplicates).

**Test:** `warns_on_key_collision` — two entries with same custom key; assert stderr contains warning; assert `env` has last entry's value; `injected_keys` has single key.

### 1.4 Single unlock on write path (M2, 7.7, 11.1)

**Problem:** `unlock_vault()` obtains master password; `save_with_unlock()` calls `unlock_with_fallback()` again → second prompt with `--no-store`.

**Solution:**

```rust
// commands/mod.rs
fn unlock_vault(mode: OpenMode) -> Result<(Config, UnlockContext, Vault, DatabaseKey)> {
    // ... existing logic ...
    Ok((cfg, ctx, vault, db_key))
}

// vault.rs
pub fn save_with_key(&mut self, key: DatabaseKey) -> Result<()> {
    self.require_rw()?;
    self.save(key)
}
```

- Remove `save_with_unlock` (or make it call `save_with_key` after unlock — prefer removal to avoid regression).
- Update RW commands: `set`, `unset`, `delete`, `import` — destructure `db_key`, call `vault.save_with_key(db_key)`.

**Test:** Optional integration test with `--no-store` vault — single password prompt count is hard to assert; unit-level test that `save_with_key` does not call unlock is sufficient. Manual smoke: `kprun init --no-store`, then `kprun set` prompts once.

### 1.5 Sorted custom keys (5.2, 11.3)

**File:** `crates/kprun-core/src/vault.rs` — `custom_field_names()`:

```rust
let mut keys: Vec<String> = /* existing filter */;
keys.sort_unstable();
keys
```

Entry **title** order remains KeePass iteration order (non-deterministic). Keys within each entry are alphabetically stable.

### 1.6 Dotenv import value trim (F2)

**File:** `crates/kprun/src/commands/import.rs` — in `parse_dotenv_import`:

```rust
pairs.push((key.to_string(), value.trim().to_string()));
```

**Test:** Import `KEY= value ` → stored value `"value"`.

### 1.7 Minor API cleanup (M1)

**File:** `crates/kprun-core/src/unlock.rs`

- `generate_keyfile(path: &PathBuf)` → `generate_keyfile(path: &Path)`
- Update call sites in `init.rs`.

### Phase 1 acceptance criteria

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release -p kprun   # no test-hooks
# Verify: KPRUN_TEST_MASTER=foo kprun list → still prompts (env ignored)
```

---

## Phase 2 — CLI polish + docs (PR #2)

**Branch:** `feat/post-mvp-polish` from `main` (after PR #1 merge)  
**Closes:** 2.1, 11.4, 13.2, F3, F4

### 2.1 Test `EmptyKey` (2.1)

**File:** `crates/kprun-core/src/parse.rs`

```rust
#[test]
fn parse_rejects_empty_key() {
    let err = parse_key_val("=value").unwrap_err();
    assert!(matches!(err, KprunError::EmptyKey(_)));
}
```

### 2.2 Test `list --json` (11.4)

**File:** `tests/manage.rs`

Test `list_json_outputs_valid_payload`:

- Setup vault with `openai` / `OPENAI_API_KEY`.
- Run `kprun list --json` with `KPRUN_TEST_MASTER=pass` (CI: `--all-features`).
- Parse JSON array; assert structure `[{ "title": "openai", "keys": ["OPENAI_API_KEY"] }]`.

### 2.3 `doctor --mcp` documentation (13.2)

**Decision:** Document limitation; do not add MCP server registry.

**README** (MCP section):

> `kprun doctor --mcp github` emits a complete snippet including the `npx` child command. For other entries, output is `["run", "<entry>", "--"]` — append your MCP server command after `--` in `.mcp.json`.

**Optional stderr hint** in `doctor.rs` when `entry != "github"`:

```rust
eprintln!("note: append your MCP server command after '--' in the generated args");
```

**Test:** `doctor_mcp_generic_entry` — `doctor --mcp openai` → args `["run", "openai", "--"]`.

### 2.4 `KPRUN_TEST_MASTER` documentation (F3)

**README** env table — replace brief row with:

| `KPRUN_TEST_MASTER` | — | Build-time only: enabled with `cargo build --features test-hooks`. Not present in GitHub release binaries. For source builds in CI/automation. |

### 2.5 Repository files (F4)

| File | Content |
|------|---------|
| `LICENSE` | MIT license text; copyright holder per repo owner; year 2026 |
| `SECURITY.md` | Reporting via GitHub Issues; scope (local CLI, no remote API); test-hooks section |

Existing README badge `[![License: MIT](...)](LICENSE)` becomes valid.

### Phase 2 acceptance criteria

```bash
cargo test --all-features
test -f LICENSE && test -f SECURITY.md
# README LICENSE link resolves
```

---

## Phase 3 — Release `v0.1.1`

1. Bump `version = "0.1.1"` in workspace `Cargo.toml` (and README if version pinned in title).
2. Merge PR #1 and PR #2 to `main`; confirm CI green.
3. Tag `v0.1.1`, push, validate artifacts (same checklist as phase 0).
4. Confirm release binary ignores `KPRUN_TEST_MASTER`.
5. Install e2e with `KPRUN_VERSION=v0.1.1`.

**Release notes draft:**

```
## v0.1.1
- Vault OpenMode guards on all write paths
- Inject key-collision warnings on stderr
- Single unlock on write commands (--no-store UX)
- test-hooks feature flag (removed from release binaries)
- LICENSE and SECURITY.md
- Alphabetically sorted keys in list output
- Dotenv import value trimming
```

---

## Concern ID traceability

| ID | Phase | Resolution |
|----|-------|------------|
| 2.1 EmptyKey test | 2 | Unit test in `parse.rs` |
| 4.3 KPRUN_TEST_MASTER in prod | 1 | `test-hooks` feature |
| 5.2 Key order | 1 | Sort in `custom_field_names` |
| 5.3 `database_mut` bypass | 1 | `pub(crate)` + guards |
| 6.1 Inject override silent | 1 | stderr warning |
| 6.2 Duplicate injected_keys | 1 | Dedupe list |
| 6.4 Override test | 1 | `warns_on_key_collision` |
| 7.1 RW guards | 1 | `require_rw` on all writes |
| 7.2 save guard | 1 | Same |
| 7.7 Double unlock | 1 | `save_with_key` |
| 11.1 Double unlock | 1 | Same |
| 11.4 list --json test | 2 | Integration test |
| 13.2 doctor --mcp generic | 2 | README + optional hint + test |
| 14.2 Remote CI | 0, 3 | Validate on main |
| 15.1–15.3 Release matrix | 0, 3 | First tag validation |
| 16.2 Install e2e | 0, 3 | Post-release smoke |
| M1 PathBuf / test hook | 1 | Path + feature flag |
| M2 Double unlock | 1 | `save_with_key` |
| F1 Inject warning | 1 | stderr |
| F2 Dotenv trim | 1 | `value.trim()` |
| F3 README test hook | 2 | Env table + SECURITY.md |
| F4 LICENSE / SECURITY | 2 | New files |

**Informational items (no action):** 1.2, 1.3, 3.x, 4.2, 4.4, 6.3, 6.5, 7.3–7.6, 8.x, 9.2–9.6, 10.2–10.4, 11.2–11.3, 11.5–11.6, 13.1, 13.3–13.4, 14.1, 15.4, 16.3.

---

## CI / release impact

| Workflow | Change |
|----------|--------|
| `ci.yml` | Change `cargo test --all` → `cargo test --all-features` so integration tests using `KPRUN_TEST_MASTER` pass after feature gating |
| `release.yml` | No change — release build stays without features |

---

## Risk register

| Risk | Mitigation |
|------|------------|
| `aarch64-linux` cross-build fails on first tag | Fix linker in workflow; patch release or retag |
| Integration tests break without `test-hooks` | CI always tests with `--all-features` |
| `pub(crate) database_mut` breaks external consumers | MVP has no published crate consumers; document in CHANGELOG if crate published later |
| v0.1.0 already tagged before LICENSE added | Accept for v0.1.0; LICENSE in v0.1.1 (user chose v0.1.0 in progress) |

---

## Verification commands (full suite)

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release -p kprun
bash -n scripts/install.sh
pwsh -NoProfile -Command '... install.ps1 parser smoke ...'
```

---

## Next step

After spec approval: invoke **writing-plans** skill → `docs/superpowers/plans/2026-06-23-kprun-post-mvp-followups.md` with bite-sized TDD tasks per phase.
