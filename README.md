# kprun v0.1.0

[![CI](https://github.com/numikel/kprun/actions/workflows/ci.yml/badge.svg)](https://github.com/numikel/kprun/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Rust](https://img.shields.io/badge/Rust-1.85.1-orange?logo=rust)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

**Local secrets injector for developers and AI agent workflows.** KeePass `.kdbx` vault (KeePassXC-compatible), OS keychain unlock, per-process env injection — not session-wide.

[Releases](https://github.com/numikel/kprun/releases) · [Install](#installation) · [Quick start](#quick-start) · [MCP integration](#mcp-integration) · [Security model](#security-model)

---

## About

kprun stores API keys and tokens in a KeePass database on your machine. It unlocks the vault via `KPRUN_KEYFILE`, the OS credential store, or an interactive prompt, then injects secrets as environment variables into **one child process** only. Nothing is exported to your shell profile, nothing lands in MCP stdout.

Typical uses:

- Run MCP servers (`npx …`) without pasting tokens into client config files
- Launch dev tools with scoped secrets (`kprun run openai -- python app.py`)
- Manage a dedicated **dev-secrets** vault separate from your personal password manager

## How it works

```mermaid
flowchart LR
    subgraph without ["Without kprun"]
        direction TB
        W1["shell exports GITHUB_TOKEN=…"]
        W1 -->|"secrets in every child"| W2["all processes inherit env"]
    end

    subgraph with ["With kprun"]
        direction TB
        K1["kprun run github -- npx @mcp/server-github"]
        K1 --> K2["unlock vault<br/>(keyfile → keyring → prompt)"]
        K2 --> K3["read entry \"github\" custom fields"]
        K3 --> K4["inject env into child only"]
        K4 --> K5["inherit stdio; audit log (key names only)"]
    end
```

Unlock priority: `KPRUN_KEYFILE` → OS keystore (`kprun` / `master`) → hidden stderr prompt.

## Features

- ✅ **KeePass / KeePassXC vault** — entry title = service name; custom string fields = env var names
- ✅ **Per-process injection** — `kprun run` opens the vault read-only and spawns one child with merged env
- ✅ **MCP-safe stdio** — `run` prints nothing on stdout; child owns stdin/stdout/stderr
- ✅ **Full secret lifecycle** — `init`, `set`, `get`, `unset`, `delete`, `export`, `import`, `doctor`
- ✅ **Audit log** — JSON lines with entry names and injected key names; **never values**
- ✅ **Cross-platform** — Linux, macOS, Windows (PATHEXT-aware spawn, keyring v1)
- ✅ **RTK-style install** — `install.sh` / `install.ps1` with SHA-256 checksum verify
- ✅ **CI matrix** — fmt, clippy, tests on ubuntu/windows/macos; release assets on tag `v*`

## Requirements

- **Rust**: 1.85.1+ (to build from source)
- **OS**: Linux, macOS, or Windows
- **Optional**: [KeePassXC](https://keepassxc.org/) to create or edit `.kdbx` files
- **MCP client**: Cursor, Claude Code, or any tool that spawns a subprocess over stdio

## Installation

### Quick install (Linux / macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/numikel/kprun/refs/heads/main/scripts/install.sh | sh
```

Installs to `~/.local/bin` by default. Override with `KPRUN_INSTALL_DIR`. Skip PATH changes with `KPRUN_NO_MODIFY_PATH=1`.

> Add to PATH manually if needed:
>
> ```bash
> echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc   # or ~/.zshrc
> ```

### Quick install (Windows)

```powershell
irm https://raw.githubusercontent.com/numikel/kprun/refs/heads/main/scripts/install.ps1 | iex
```

Default install dir: `%LOCALAPPDATA%\kprun\bin`. Adds user `Path` unless `KPRUN_NO_MODIFY_PATH=1`.

Open a **new terminal**, then verify:

```bash
kprun --version
```

### Pre-built binaries

Download from [GitHub Releases](https://github.com/numikel/kprun/releases) (after the first tag):

| Platform | Asset |
|----------|-------|
| Linux x86_64 | `kprun-x86_64-unknown-linux-gnu.tar.gz` |
| Linux arm64 | `kprun-aarch64-unknown-linux-gnu.tar.gz` |
| macOS Intel | `kprun-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `kprun-aarch64-apple-darwin.tar.gz` |
| Windows | `kprun-x86_64-pc-windows-msvc.zip` + standalone `kprun.exe` |

Verify with `checksums.txt` from the same release unless `KPRUN_SKIP_CHECKSUM=1`.

### Build from source

```bash
git clone https://github.com/numikel/kprun.git
cd kprun
cargo build --release -p kprun
# binary: target/release/kprun (or target/<triple>/release/kprun)
```

Or install into Cargo bin dir:

```bash
cargo install --path crates/kprun
```

## Quick start

```bash
# 1. Create vault (master password → OS keychain by default)
kprun init

# 2. Store secrets (entry title = service; fields = env vars)
kprun set github GITHUB_TOKEN=ghp_xxx

# 3. Inject into a child process
kprun run github -- npx -y @modelcontextprotocol/server-github
```

Windows (after `install.ps1`):

```powershell
kprun init
kprun set github GITHUB_TOKEN=ghp_xxx
kprun run github -- npx -y @modelcontextprotocol/server-github
```

### Attach an existing KeePassXC database

```bash
kprun init --db /path/to/existing.kdbx
```

Verifies unlock and optionally stores the master password in the OS keychain. Does **not** recreate the database.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `KPRUN_DB` | `~/.kprun/secrets.kdbx` | Path to the KeePass database |
| `KPRUN_KEYFILE` | — | Path to a cryptographic key file (second factor) |
| `KPRUN_LOG` | `~/.kprun/access.log` | Audit log path (JSON lines, key names only) |
| `KPRUN_INSTALL_DIR` | `~/.local/bin` / `%LOCALAPPDATA%\kprun\bin` | Install script target |
| `KPRUN_NO_MODIFY_PATH` | unset | Set to `1` to skip shell PATH updates |
| `KPRUN_SKIP_CHECKSUM` | unset | Set to `1` to skip install checksum verify |
| `KPRUN_VERSION` | latest release | Pin install script version |
| `KPRUN_TEST_MASTER` | — | Test hook: fixed master password (automation only) |

Install script env vars are documented in `scripts/install.sh` and `scripts/install.ps1`.

## CLI reference

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

Notes:

- `get` and `export` show key **names** by default; use `--reveal` only when you need values (stderr warning + audit).
- `run` inherits stdio to the child and writes **nothing** to stdout (MCP-safe).
- `import` without `--merge` replaces vault content; structure-only dotenv exports are rejected to prevent accidental wipes.
- Exit codes: `1` for DB not found, entry not found, unlock failed, DB locked; child exit code propagated; empty injection → `0` with stderr warning.

## MCP integration

MCP clients spawn a command and talk over the child's stdio. Use `kprun run` as a transparent wrapper.

**Linux / macOS** (with `kprun` on `PATH`):

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

**Windows** (prefer full path — some MCP clients do not resolve `PATH` reliably):

```json
{
  "mcpServers": {
    "github": {
      "command": "C:\\Users\\you\\AppData\\Local\\kprun\\bin\\kprun.exe",
      "args": ["run", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

Generate a ready-to-paste fragment:

```bash
kprun doctor --mcp github
```

After editing MCP config, check `git diff` — some tools may write secrets back to disk.

## Automation and cron

When no interactive session is available (cron, Task Scheduler), the OS keychain may be unavailable. Use a **keyfile**:

```bash
kprun init --keyfile ~/.kprun/master.key
export KPRUN_KEYFILE=~/.kprun/master.key
kprun run myservice -- /path/to/script.sh
```

The keyfile is generated by kprun (64 random bytes), not a plaintext password file. Restrict permissions (`chmod 600` on Unix; user-only ACL on Windows).

For scheduled jobs, set `KPRUN_DB` and `KPRUN_KEYFILE` in the job environment. Use `--no-store` at `init` if you do not want the master password in the keychain.

## Project structure

```
kprun/
├── crates/
│   ├── kprun-core/          # vault, unlock, inject, audit (no clap / Command)
│   └── kprun/               # CLI binary, spawn, commands
├── scripts/
│   ├── install.sh           # RTK-style installer (Unix)
│   └── install.ps1          # Windows installer
├── tests/                   # integration tests (run, init, manage, export, doctor, …)
├── .github/workflows/
│   ├── ci.yml               # fmt, clippy, test matrix
│   └── release.yml          # cross-build + checksums on tag v*
└── docs/superpowers/        # design spec and implementation plan
```

## Development

### Setup

```bash
git clone https://github.com/numikel/kprun.git
cd kprun
cargo build -p kprun
```

### Running tests

```bash
cargo test --all
```

KeePassXC compatibility test (optional, local fixture):

```bash
# Create tests/fixtures/keepassxc.kdbx in KeePassXC (gitignored)
# Entry title: fixture; custom attribute: FIXTURE_KEY
KPRUN_KEEPASSXC_FIXTURE=1 KPRUN_TEST_MASTER='your-pass' \
  cargo test reads_keepassxc_fixture -- --ignored
```

### Code quality (matches CI)

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

## Security model

- Use a dedicated **dev-secrets** vault, not your personal password manager.
- Secrets exist in the **child process environment** after injection (same model as other secret runners).
- Audit log records entry names and injected key names — **never values**.
- Do not use `setx` or global shell profiles for API keys.
- Pass only the entries a command needs: `kprun run openai -- python script.py`, not every secret at once.
- `export --reveal` and `get --reveal` print values to the terminal — use deliberately.

## Contributing

1. Fork the repository.
2. Create a feature branch (`git checkout -b feat/my-change`).
3. Commit using **Conventional Commits 1.0.0** (e.g. `feat(cli): add example command`, `fix(core): handle locked db`).
4. Add or update tests for behavior changes.
5. Run `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all`.
6. Open a pull request against `main`.

Use English for code, comments, and CLI messages.

## License

MIT License — see [LICENSE](LICENSE).

## Author

**@numikel**

---

**Security note:** kprun injects secrets into child process environments. Treat the vault file, keyfile, and audit log as sensitive. Do not commit `.kdbx` files or keyfiles to version control.