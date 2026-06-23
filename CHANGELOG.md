# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
