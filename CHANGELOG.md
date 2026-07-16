# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-07-16

See [docs/changelogs/v0.6.0.md](docs/changelogs/v0.6.0.md) for details.

### Added

- `kprun migrate` — command to migrate vault entries from legacy password manager exports.
- Comprehensive manual testing guide for all features and workflows.
- Windows update troubleshooting section in the README.

### Changed

- Documentation improvements: clarified master password handling and added migration notes.

### Fixed

- `kprun init --quick` now improves credential visibility in terminal output.

## [0.5.0] - 2026-07-12

See [docs/changelogs/v0.5.0.md](docs/changelogs/v0.5.0.md) for details.

### Added

- `kprun init --quick` — non-interactive onboarding with master password generation and keychain storage.
- `kprun reveal-master` — retrieve stored master password from OS keychain.
- `kprun deinit --delete-vault` — remove vault file and keychain entry.
- `--db` flag on `reveal-master` and `deinit` for non-standard vault paths.

### Changed

- OS keychain account name now derived from lexical path (SHA-256) instead of `fs::canonicalize`.

### Fixed

- Atomic vault creation in `init --quick --force` prevents partial failures.
- Vault file deletion before keychain cleanup in `deinit --delete-vault`.
- Keychain error messages now actionable instead of raw backend strings.

### ⚠️ BREAKING CHANGES

- OS keychain account name changes for Windows vaults and macOS `/tmp` vaults; users must re-run `kprun init`.

## [0.4.3] - 2026-07-11

See [docs/changelogs/v0.4.3.md](docs/changelogs/v0.4.3.md) for details.

### Changed

- Deprecated HTTP+SSE transport now emits warning when used; migrate to Streamable HTTP.

### Fixed

- MCP bridge legacy SSE fallback narrowed to HTTP 404/405 errors only.
- Keyfile unlock error messages clarified for composite keyfile scenarios.

## [0.4.2] - 2026-07-11

See [docs/changelogs/v0.4.2.md](docs/changelogs/v0.4.2.md) for details.

### Changed

- MCP bridge transport abstraction via `McpTransportImpl` trait; SSE buffer optimization.
- Context7 header expectations and legacy POST body forwarding documented.

### Fixed

- MCP bridge shutdown timeout bounds and server-stream cleanup.
- Notifications/initialized message replay on session re-init; response body timeout exemptions.
- MCP-Protocol-Version header negotiation on transport initiation/shutdown.

## [0.4.1] - 2026-07-09

See [docs/changelogs/v0.4.1.md](docs/changelogs/v0.4.1.md) for details.

### Changed

- Core insulation from keepass types via owned newtypes; shared keyring helper extraction.

### Fixed

- DatabaseSaveError matching and VaultKey Debug redaction (password leak prevention).

### Security

- VaultKey Debug impl redacted to prevent master password leakage in logs.

## [0.4.0] - 2026-07-08

See [docs/changelogs/v0.4.0.md](docs/changelogs/v0.4.0.md) for details.

### Added

- Core `vault_id` utility for stable, non-identifying vault digest.

### Security

- Audit log replaces vault path with `db_id` (SHA-256 digest). Hardens MCP transport and Windows ACL enforcement.

## [0.3.1] - 2026-07-07

See [docs/changelogs/v0.3.1.md](docs/changelogs/v0.3.1.md) for details.

### Fixed

- **Security**: block dangerous env var families by prefix to prevent env injection (#49).
- **Security**: resolve CodeQL code scanning alerts (#48).
- `kprun init` now uses Argon2id with 64 MiB KDF parameters (#46).

### Changed

- Documentation clarified that Superpowers workflow skills are invoked manually (#47).

## [0.3.0] - 2026-07-04

See [docs/changelogs/v0.3.0.md](docs/changelogs/v0.3.0.md) for details.

### Added

- `kprun mcp` — stdio↔HTTP bridge for hosted MCP servers with vault-backed auth headers and Streamable HTTP (#25).
- `{{FIELD}}` template substitution and non-interactive vault unlock for automation.

### Changed

- README documents `kprun mcp` bridge and transport options.

### Fixed

- MCP GET stream session re-init, JSON-RPC duplicate error frames, SSE reader error logging.

### Security

- `keepass` bumped to 0.13.11, fixing `quick-xml` advisories RUSTSEC-2026-0194/0195.

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
