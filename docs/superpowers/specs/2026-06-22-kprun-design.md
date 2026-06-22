# kprun — design spec

**Date:** 2026-06-22  
**Status:** Approved (brainstorming)  
**Scope:** MVP v1 — CLI secret injector + management, Rust, cross-platform

## Summary

`kprun` is a local secrets tool for developers and AI agent workflows. It stores secrets in a KeePass `.kdbx` vault (compatible with KeePassXC), unlocks via OS keystore or interactive prompt, and injects secrets as environment variables into a **single child process** — scoped, not session-wide.

Primary use cases:

- Wrap commands: `kprun run openai -- python ingest.py`
- MCP servers without plaintext tokens in `.mcp.json`
- Task Scheduler / cron jobs with scoped secrets

Pattern matches `op run` and `infisical run`: config holds **references** (entry names), not secret values.

## Goals

| Goal | How |
|------|-----|
| Simple for users | One-line install (`install.ps1` / `install.sh`) puts binary on PATH; then `kprun init` for vault |
| Secure by default | Per-process scoping, audit log without values, optional keyfile |
| Cross-platform | Windows, Linux, macOS via GitHub Releases |
| KeePassXC compatible | Same entry model: title = service, custom attributes = env vars |
| Extensible | `kprun-core` library crate for future Python/Node SDK |

## Non-goals (v1)

- SDK for Python / Node (v1.1)
- Pluggable backends (Infisical, 1Password)
- Session daemon / vault cache
- TOML config file
- MSI/deb installers

## Architecture

### Repository layout

```
kprun/
├── crates/
│   ├── kprun-core/          # vault logic, unlock, inject, audit
│   │   └── src/
│   │       ├── vault.rs     # open/save .kdbx, CRUD entries
│   │       ├── unlock.rs    # keystore | prompt | keyfile
│   │       ├── inject.rs    # resolve entries → HashMap<env_key, value>
│   │       ├── audit.rs     # JSON access log
│   │       └── config.rs    # KPRUN_DB, KPRUN_KEYFILE, KPRUN_LOG
│   └── kprun/               # CLI binary (thin clap layer)
│       └── src/
│           ├── main.rs
│           └── commands/
├── scripts/
│   ├── install.ps1          # Windows: download + PATH (user scope)
│   └── install.sh           # Linux/macOS: download + PATH
├── .github/workflows/       # CI: test + release binaries
└── docs/
```

### Data flow

```
CLI (kprun) → kprun-core
  → unlock (OS keystore | keyfile | prompt)
  → vault (.kdbx read-only for run, read-write for set/delete)
  → inject (merge custom properties into env map)
  → subprocess (run only) OR CRUD result (manage commands)
  → audit log (run, get --reveal)
```

### Module boundaries

- `kprun-core` has no dependency on `clap` or `std::process::Command`.
- `kprun-core` returns `HashMap<String, String>` for injection; the binary spawns the child.
- `run` opens vault **read-only**; `set` / `unset` / `delete` / `import` open **read-write**.
- Never log secret values to stdout, stderr, or audit log.

### Technology stack

| Layer | Choice |
|-------|--------|
| Language | Rust (edition 2021) |
| `.kdbx` | `keepass` crate |
| OS keystore | `keyring` crate |
| CLI | `clap` (derive) |
| Serialization | `serde`, `serde_json` |
| CI / release | GitHub Actions, cross-compilation |

## KeePass data model

Full compatibility with KeePassXC entry structure from research docs.

| Element | Convention |
|---------|------------|
| Entry | Title = service name (`github`, `openai`) |
| Secrets | Custom properties (additional attributes): attribute name = env var name |
| Entry `password` field | Unused by kprun in v1 |
| Groups | Ignored in v1; flat title lookup via `find_entries(title=...)` |

Example entry `github`:

| Attribute | Value |
|-----------|-------|
| `GITHUB_TOKEN` | `ghp_...` |

`kprun set openai OPENAI_API_KEY=sk-xxx` creates or updates entry `openai` with attribute `OPENAI_API_KEY`.

## Unlock strategy

Priority in `kprun-core/unlock.rs`:

1. `KPRUN_KEYFILE` env — if set, use as second factor
2. OS keystore — service `kprun`, user `master` (via `keyring` crate)
3. Interactive prompt on stderr (hidden input) — fallback

### `kprun init` behaviour

| Flag | Behaviour |
|------|-----------|
| (default) | Create `~/.kprun/secrets.kdbx`, prompt for master password, store in OS keystore |
| `--no-store` | Create vault, do **not** store master — prompt on every use |
| `--keyfile PATH` | Generate or use keyfile, register as second factor on database |
| `--db PATH` | Target path for new vault, or attach to existing `.kdbx` (verify unlock only) |

`--db` on init with existing KeePassXC database: verify credentials, optionally store master in keystore; do not recreate database.

### Automation without interactive session

For Task Scheduler / cron when user is not logged in, OS keystore may fail. Use `KPRUN_KEYFILE` with restrictive file ACL (documented in README). Keyfile is a **cryptographic key file**, not a plaintext password file.

## CLI reference

### Commands

```
kprun init   [--db PATH] [--no-store] [--keyfile PATH]
kprun run    <entry> [entry2 ...] -- <command> [args...]
kprun list   [--json]
kprun get    <entry> [--keys] [--reveal]
kprun set    <entry> KEY=val [KEY2=val2 ...]
kprun unset  <entry> KEY [KEY2 ...]
kprun delete <entry>
kprun export [--format json|dotenv] [--stdout] [--reveal]
kprun import <file> [--merge]
kprun doctor [--mcp <entry>]
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KPRUN_DB` | `~/.kprun/secrets.kdbx` | Vault path |
| `KPRUN_KEYFILE` | — | Keyfile path |
| `KPRUN_LOG` | `~/.kprun/access.log` | Audit log path |

### `run` — subprocess wrapper

Critical for MCP compatibility:

- Inherit stdin, stdout, stderr to child process
- Propagate child exit code
- No output on stdout from kprun itself (audit/warnings on stderr or log file only)
- On Windows: resolve `npx.cmd` and similar via PATHEXT or documented workaround

Example:

```bash
kprun run openai -- python ingest.py
kprun run github -- npx -y @modelcontextprotocol/server-github
```

### `get` / `export` safety

- Default: show entry metadata and **key names only**, never values
- `--reveal`: show values (terminal) or export with values; print security warning on stderr

### `export` / `import`

- Formats: `json` (structured entries + attributes), `dotenv` (flat KEY=val per entry block)
- `import --merge`: update existing entries, add new; do not delete unmentioned entries
- Export without `--reveal`: structure only, safe for inspection

### `doctor`

Diagnostics:

- Vault exists and unlocks
- Keystore / keyfile status
- Resolved binary path (for `.mcp.json` on Windows)
- `--mcp <entry>`: print ready-to-paste MCP JSON fragment

## MCP integration

MCP clients spawn `command` + `args` and communicate via child stdin/stdout. `kprun run` must be a transparent wrapper.

**Linux / macOS** (kprun on PATH):

```json
{
  "mcpServers": {
    "github": {
      "command": "kprun",
      "args": ["run", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

**Windows** (prefer full path — MCP clients may not resolve PATH reliably):

```json
{
  "mcpServers": {
    "github": {
      "command": "C:\\Tools\\kprun\\kprun.exe",
      "args": ["run", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

After `claude mcp add` or similar tooling, verify `git diff` on config — some tools expand placeholders and write secrets back to disk.

## Audit log

Append one JSON line per `run` invocation (and `get --reveal`):

```json
{
  "ts": "2026-06-17T03:00:01+0200",
  "pid": 12044,
  "db": "C:\\Users\\you\\.kprun\\secrets.kdbx",
  "entries": ["openai"],
  "injected_keys": ["OPENAI_API_KEY", "OPENAI_ORG"],
  "command": "python"
}
```

- `injected_keys`: names only, never values
- `command`: argv[0] of child process

## Error handling

| Condition | Exit code | Message |
|-----------|-----------|---------|
| Database not found | 1 | Suggest `kprun init` |
| Entry not found | 1 | `entry '<name>' not found` |
| Unlock failed | 1 | Generic message, no crypto details |
| No keys injected | 0 | Warning on stderr, run proceeds |
| Child failed | child code | Propagated |
| Database locked (write) | 1 | Suggest close KeePassXC or retry |

CLI messages in English.

## Distribution and installation

Two separate steps — do not conflate them:

| Step | Command | What it does |
|------|---------|--------------|
| **1. Install program** | `install.ps1` / `install.sh` / manual zip | Puts `kprun` binary on disk and on PATH |
| **2. Initialize vault** | `kprun init` | Creates `~/.kprun/secrets.kdbx`, unlock setup (unchanged from design) |

`kprun init` is **not** part of the install scripts. After installing the binary,
the user runs `kprun init` explicitly when ready.

### Reference: RTK ([rtk-ai/rtk](https://github.com/rtk-ai/rtk))

RTK solves a different problem (CLI output compression), but its install UX is a
good model for `kprun`:

| RTK pattern | kprun adoption |
|-------------|----------------|
| `install.sh` via `curl \| sh` | Same — primary Linux/macOS path |
| Installs to `~/.local/bin` | Same default (`KPRUN_INSTALL_DIR` override) |
| `checksums.txt` + SHA-256 verify before install | Same — refuse install if mismatch |
| Latest version via `/releases/latest` redirect (no API rate limit) | Same; fallback to GitHub API |
| `RTK_VERSION` env to pin version | `KPRUN_VERSION` |
| `tar.gz` per target triple in releases | Same naming: `kprun-{target}.tar.gz` |
| Warn if binary not on PATH | kprun goes further: **auto-modify PATH** by default |
| Windows: manual zip extract only | kprun adds **`install.ps1`** (gap in RTK) |
| `rtk init -g` = app setup after install | `kprun init` = vault setup (different concern) |

### Recommended: install scripts (v1)

**Windows (PowerShell)** — RTK does not ship this; we do:

```powershell
irm https://raw.githubusercontent.com/<org>/kprun/master/scripts/install.ps1 | iex
```

**Linux / macOS** — same style as RTK:

```bash
curl -fsSL https://raw.githubusercontent.com/<org>/kprun/master/scripts/install.sh | sh
```

Environment overrides (RTK-style):

| Variable | Default | Description |
|----------|---------|-------------|
| `KPRUN_INSTALL_DIR` | `%LOCALAPPDATA%\kprun\bin` (Win) / `~/.local/bin` (Unix) | Install directory |
| `KPRUN_VERSION` | latest | Pin tag, e.g. `v0.1.0` |
| `KPRUN_SKIP_CHECKSUM` | `0` | Set `1` to skip verify (not recommended) |
| `KPRUN_NO_MODIFY_PATH` | `0` | Set `1` to skip PATH update |

### Install locations and PATH

| OS | Binary path | PATH update (default) |
|----|-------------|------------------------|
| Windows | `%LOCALAPPDATA%\kprun\bin\kprun.exe` | Append dir to **user** `Path` via `[Environment]::SetEnvironmentVariable` (idempotent) |
| Linux / macOS | `~/.local/bin/kprun` | If `kprun` not found after install: append `export PATH="$HOME/.local/bin:$PATH"` to `~/.bashrc`, `~/.zshrc`, or `~/.profile` (first existing, idempotent) |

After install, script prints: version, full binary path, reminder to **open a new
terminal**, then next step: `kprun init`.

`kprun doctor` verifies binary on PATH and prints full path for `.mcp.json` on
Windows (RTK has no equivalent; useful for MCP clients that ignore PATH).

### Install script behaviour (both platforms)

1. Detect OS and architecture (`x86_64`, `aarch64`).
2. Resolve latest tag via GitHub `/releases/latest` redirect; fallback API; or `KPRUN_VERSION`.
3. Download `kprun-{target}.tar.gz` (Unix) or `kprun-{target}.zip` (Windows).
4. Download `checksums.txt` from same release; verify SHA-256 (abort on mismatch).
5. Extract with path-traversal check (RTK: reject `..` and absolute paths in archive).
6. Move binary to `KPRUN_INSTALL_DIR`; `chmod +x` on Unix.
7. Update PATH unless `KPRUN_NO_MODIFY_PATH=1`.
8. Run `kprun --version` to verify.
9. Print success + hint: `kprun init` when ready.

Scripts live in repo `scripts/`; raw URLs point at `master` branch (RTK pattern).
Release CI also attaches `checksums.txt` and archives per target.

### Manual install (fallback, RTK-style)

For air-gapped, CI, or users who prefer no pipe-to-shell:

| OS | Steps |
|----|-------|
| Windows | Download `kprun-x86_64-pc-windows-msvc.zip` from Releases → extract `kprun.exe` → add folder to PATH (or run `install.ps1 -Dir ...` locally) |
| Linux / macOS | Download `kprun-{target}.tar.gz` → extract to `~/.local/bin` |

Plain `.exe` in Releases remains available for users who want a single file without zip.

### Other v1 channels

- **GitHub Releases** (primary artifact source for scripts and manual install)
- **cargo install kprun** (optional, Rust developers)

### User onboarding

```powershell
# 1. Install program (binary + PATH)
irm .../scripts/install.ps1 | iex
# 2. New terminal, then initialize vault
kprun init
kprun set github GITHUB_TOKEN=ghp_xxx
kprun run github -- npx -y @modelcontextprotocol/server-github
```

```bash
# 1. Install program
curl -fsSL .../scripts/install.sh | sh
# 2. New terminal, then initialize vault
kprun init
kprun set github GITHUB_TOKEN=ghp_xxx
kprun run github -- npx -y @modelcontextprotocol/server-github
```

## Testing strategy

### CI pipeline

- Every PR: `cargo test`, `clippy`, `fmt`
- Tag `v*`: build release artifacts, upload to GitHub Releases

### Test matrix

| Area | Tests |
|------|-------|
| `kprun-core` | Unit: KEY=val parsing, unlock mocks, CRUD on temp `.kdbx` |
| CLI integration | `init` → `set` → `run -- env` verifies injected vars |
| MCP-critical | stdio inheritance; kprun stdout empty during run |
| Windows job | `run` with `npx` or `cmd /C` |
| KeePassXC compat | Fixture DB created in KeePassXC, read via kprun |
| Install scripts | Smoke: dry-run or CI job verifies URL resolution, checksum, idempotent PATH |

Test fixture: minimal `.kdbx` in `tests/fixtures/` with known test-only credentials.

## Security model

### Threats addressed

| Risk | Mitigation |
|------|------------|
| Plaintext secrets in MCP config / `.env` | Reference + injector; config has entry names only |
| Agent reads entire session env | Per-process scoping; inject only needed entries |
| Prompt injection in MCP exfiltrates creds | One entry per service; minimal blast radius |
| Accidental commit of secrets | No secrets in config; pre-commit scanning recommended |
| Master password in plaintext on disk | OS keystore by default; keyfile as second factor |

### Accepted risks (documented)

- After injection, secret is in child process `environ` — code in that process can read it (same as `op run`).
- Malware running as same user can access OS keystore and process memory.
- Use dedicated **dev-secrets** vault, not personal password vault.

### Anti-patterns

- Do not use `setx` / `/etc/environment` for API keys (global, persistent plaintext).
- Do not pass more entries to `run` than the command needs.

## Roadmap

### v1 (MVP)

- Full CLI: `init`, `run`, `list`, `get`, `set`, `unset`, `delete`, `export`, `import`, `doctor`
- `kprun-core` + `kprun` workspace
- `install.ps1` + `install.sh` (download, PATH, checksums)
- GitHub Releases, README, MCP examples

### v1.1

- Python SDK (`kprun-core` via PyO3)
- Node SDK (`kprun-core` via napi-rs)
- Scoop / Homebrew formulae

### v1.2+

- Entry groups in `list` and `run`
- Optional Infisical backend (same `run` UX, different prefix)

## Decisions log

| Decision | Rationale |
|----------|-----------|
| Rust single binary | Minimal user dependencies, fast startup, cross-platform releases |
| Workspace (`kprun-core` + CLI) | SDK later without rewrite |
| KeePass `.kdbx` | Existing research, KeePassXC GUI, offline, no server |
| OS keystore default | Zero prompts for daily use; `--no-store` for paranoid mode |
| Explicit `run` subcommand | Clear semantics; avoids ambiguity with entry names |
| No daemon in v1 | Simpler security model; unlock per invocation |
| English CLI messages | Convention for CLI tools; Polish docs in README |
| `install.ps1` / `install.sh` as default | RTK-style for Unix; we add `install.ps1` where RTK only has manual zip on Windows |
| User-scope PATH by default | RTK only warns; kprun auto-updates PATH (opt out via `KPRUN_NO_MODIFY_PATH`) |
| `kprun init` separate from install | Install = binary; init = vault (like RTK separates `rtk init` from install) |

## References

- `.docs/research/README.md` — prototype usage and MCP examples
- `.docs/research/kprun.py` — Python prototype (behavioural reference)
- `.docs/research/runbook-sekrety-agenci-ai.html` — threat model and architecture runbook
