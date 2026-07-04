# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-07-02

See [docs/changelogs/v0.3.0.md](docs/changelogs/v0.3.0.md) for details.

### Added

- `kprun mcp` — stdio↔HTTP bridge for hosted MCP servers with vault-backed auth headers and Streamable HTTP (#25).
- `{{FIELD}}` template substitution and non-interactive vault unlock for automation.

### Changed

- README documents `kprun mcp` bridge and transport options.

### Fixed

- MCP GET stream session re-init, JSON-RPC duplicate error frames, SSE reader error logging.

## [0.2.4] - 2026-06-28

See [docs/changelogs/v0.2.4.md](docs/changelogs/v0.2.4.md) for details.

### Changed

- README scripts and automation documentation.

### Fixed

- Integration tests require `test-hooks` feature to avoid hang on `cargo test --all`.
- Duplicate `license-file` manifest warning removed.

## [0.2.3] - 2026-06-26

See [docs/changelogs/v0.2.3.md](docs/changelogs/v0.2.3.md) for details.

### Added

- README section on OpenRouter coding agents.

### Changed

- Code simplification across CLI and core: unified unlock paths, DRY command helpers, import refactor; no CLI behavior change.

### Fixed

- Legacy KDBX4.0 vaults normalized before save.

## [0.2.2] - 2026-06-24

See [docs/changelogs/v0.2.2.md](docs/changelogs/v0.2.2.md) for details.

### Added

- CLI option help text; `doctor --mcp` accepts child command after `--`; dotenv import docs; README demo GIF.

### Changed

- `.gitignore` tracks demo GIF and alternate Cargo target dirs.

## [0.2.1] - 2026-06-24

See [docs/changelogs/v0.2.1.md](docs/changelogs/v0.2.1.md) for details.

### Added

- CLI polish: ASCII banner, subcommand help text, success confirmations, guided `init`, empty `list` hint; minisign public key in installers.

### Changed

- Interactive stderr UX for vault management; banner suppressed for `run` and machine-readable modes.

## [0.2.0] - 2026-06-24

See [docs/changelogs/v0.2.0.md](docs/changelogs/v0.2.0.md) for details.

### Added

- Security hardening: owner-only file permissions, protected KeePass fields, `kprun deinit`, `kprun run --clean-env`, dangerous env injection blocklist, minisign-signed releases.

### Changed

- **BREAKING:** per-vault OS keychain keying and 12-character minimum master password on new vaults; supply-chain pinning and signed checksums.

### Fixed

- Parse error sanitization, pipe password warning, export reveal-to-file warning, dotenv round-trip quoting.

## [0.1.2] - 2026-06-23

See [docs/changelogs/v0.1.2.md](docs/changelogs/v0.1.2.md) for details.

### Added

- Post-MVP core hardening: `test-hooks` feature flag, `OpenMode` write guards, inject collision warnings, sorted `list` field names.

### Fixed

- Single unlock on `--no-store` write commands; whitespace trimming on dotenv import.

### Changed

- `database_mut` narrowed to `pub(crate)`; CI tests run with `--all-features`.

## [0.1.1] - 2026-06-23

See [docs/changelogs/v0.1.1.md](docs/changelogs/v0.1.1.md) for details.

### Added

- Release workflow (`/prepare-release` skill, changelog files, CI validate + publish), repo hygiene (LICENSE, SECURITY, Dependabot, templates), and `cargo audit` CI job.

### Fixed

- Integration test unlock determinism when OS keyring has a stored master password.

### Changed

- GitHub Actions dependency bumps (checkout, download-artifact, upload-artifact, action-gh-release).

## [0.1.0] - 2026-06-23

See [docs/changelogs/v0.1.0.md](docs/changelogs/v0.1.0.md) for details.

### Added

- Initial public release: KeePass-backed local secrets injector with per-process env injection, full vault management CLI, MCP-safe stdio, install scripts, and cross-platform CI/release assets.

### Fixed

- Dotenv import guard, keyring fallback, CI PowerShell escaping.

### Changed

- MSRV 1.88.0.
