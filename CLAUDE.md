# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Superpowers workflow

The user invokes all superpowers workflow skills (brainstorming → writing-plans → executing-plans etc.) **manually**. After finishing one stage (e.g. saving an approved design spec), STOP — do not ask whether to proceed and do not auto-invoke the next skill in the chain.

### Model tier mapping

When any Superpowers skill (especially `subagent-driven-development`,
"Model Selection" section) refers to a "cheap/mechanical model", "standard
model", or "most capable model" when dispatching a subagent, do NOT leave
this underspecified or silently inherit the session's default model.
Substitute the values below directly into the `model:` field (and
`effort:`, if that field exists in the dispatch template).

| Skill tier                | Model                      | Effort |
|----------------------------|------------------------------|--------|
| cheap / mechanical         | claude-haiku-4-5             | —      |
| standard / execution       | claude-sonnet-5               | medium |
| most capable / review      | claude-opus-4-8               | xhigh  |

#### Escalation on BLOCKED or repeated failure
claude-haiku-4-5 → claude-sonnet-5 (effort: high) → claude-opus-4-8 (effort: xhigh).
Never redispatch the same task on the same model without changing
approach — escalate the tier instead of repeating the attempt.

#### Exceptions to the default step mapping (always "most capable",
regardless of which step they appear in)
- systematic-debugging (root-cause on a hard bug)
- final whole-branch code reviewer (superpowers:requesting-code-review)
- brainstorming and writing-plans

#### Exceptions that are always "cheap", regardless of the general step mapping
- using-git-worktrees
- finishing-a-development-branch
- /prepare-release — deterministic checklist; escalate to
  claude-sonnet-5 (effort: medium) ONLY if the skill's §6 self-check
  (cargo fmt / cargo test / version consistency) fails on the first pass

#### verification-before-completion
Always claude-sonnet-5, effort: high — never downgrade to cheap,
regardless of how simple the task looks. The cost of a false "it works"
is asymmetrically higher than the token savings.

#### Verification
After each dispatch inside subagent-driven-development, if the
narration/log doesn't explicitly show which model was selected, ask
briefly whether the mapping was applied — don't silently assume
inheritance worked correctly.

## Build and development

```bash
# Development build
cargo build -p kprun

# Release build
cargo build --release -p kprun

# Install into Cargo bin dir
cargo install --path crates/kprun
```

## Code quality (must all pass — matches CI)

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## Running tests

```bash
# All tests
cargo test --all-features

# Single test by name (substring match)
cargo test run_injects_env_var

# Integration tests that unlock the vault require the test-hooks feature.
cargo test --test init_set_run --features test-hooks

# KeePassXC compatibility test (needs a local fixture file; gitignored)
KPRUN_KEEPASSXC_FIXTURE=1 KPRUN_TEST_MASTER='your-pass' \
  cargo test reads_keepassxc_fixture -- --ignored
```

Integration tests that spawn `kprun` with `common::test_env()` require `--features test-hooks` (declared via `required-features` on `[[test]]` targets). `KPRUN_TEST_MASTER=pass` is honored only when that feature is enabled.

## Architecture

Two-crate Cargo workspace:

**`crates/kprun-core`** — pure library, no Clap dependency:
- `vault.rs` — `Vault` struct wrapping `keepass::Database`; `open_vault` / `create_vault`; all entry CRUD; `OpenMode` (ReadOnly / ReadWrite); custom fields = env vars (standard KeePass fields like Title/Password/UserName are excluded)
- `unlock.rs` — `MasterPasswordSource` trait; unlock priority: `KPRUN_KEYFILE` → OS keyring (SHA-256 of canonical db path as account name) → stderr prompt; `build_database_key` composes password + optional keyfile; `test-hooks` feature enables `KPRUN_TEST_MASTER` env override; `unlock_noninteractive` (mcp mode: keyring/keyfile only, never prompts)
- `template.rs` — `{{FIELD}}` template resolution against vault entry custom fields, used to build headers and URLs for `kprun mcp`
- `inject.rs` — `resolve_injection` merges custom fields from multiple entries, blocks a hardcoded `DANGEROUS_ENV` list (PATH, LD_PRELOAD, etc.), warns on key collisions
- `audit.rs` — appends JSON-lines to `~/.kprun/access.log`; records entry names and injected key names, **never values**
- `config.rs` — reads `KPRUN_DB`, `KPRUN_KEYFILE`, `KPRUN_LOG` from environment; defaults to `~/.kprun/`
- `secure_fs.rs` — creates files/dirs with owner-only permissions (mode 600 on Unix)
- `import.rs` / `parse.rs` — structured JSON and kprun-dotenv import/export format

**`crates/kprun`** — CLI binary:
- `cli.rs` — Clap `Cli` / `Commands` enum; all subcommand argument definitions
- `commands/mod.rs` — `dispatch()` routes to per-command modules; shared helpers `unlock_vault`, `mutate_vault`, `run_command`
- `commands/run.rs` — opens vault read-only, resolves injection, writes audit log, spawns child
- `commands/mcp.rs` — non-interactive unlock, `{{FIELD}}` template resolution, audit (header names + URL host only), hands off to the bridge
- `mcp_bridge/` — stdio↔HTTP MCP bridge: `streamable.rs` (Streamable HTTP, `Mcp-Session-Id` lifecycle, 404 re-init), `legacy_sse.rs` (deprecated HTTP+SSE), `sse.rs` (shared SSE parser)
- `spawn.rs` — `run_child` builds `std::process::Command`; `--clean-env` drops parent env except safe vars (PATH, HOME, etc.); Windows-aware `resolve_executable` checks PATHEXT
- `ui.rs` — terminal output helpers

**`tests/`** — integration tests at workspace root, registered as `[[test]]` entries in `crates/kprun/Cargo.toml`. Each test file uses `mod common` from `tests/common/mod.rs` which provides `kprun_cmd()`, `test_env()`, and `create_vault_with_entries()`.

## Key invariants

- `kprun run` writes **nothing** to stdout (MCP-safe); all warnings go to stderr
- Vault saves go through atomic temp-file write via `secure_fs::persist_restricted`
- `Vault::save` normalizes legacy KDBX4.0 minor version to 4.1 before persisting
- Entry lookup is case-insensitive; duplicate titles return `KprunError::DuplicateEntry`
- `--features test-hooks` must NOT be present in release binaries (bypasses password prompt)
- `kprun mcp` stdout carries exclusively JSON-RPC frames; message bodies pass through byte-for-byte; 401/403 during transport detection never triggers legacy fallback

## Release process

Tag `vX.Y.Z` and push; CI validates that `docs/changelogs/vX.Y.Z.md` exists and the version matches `Cargo.toml`, then builds cross-platform binaries and publishes a GitHub Release.

Version is defined once in the workspace root `Cargo.toml` (`[workspace.package] version`).
