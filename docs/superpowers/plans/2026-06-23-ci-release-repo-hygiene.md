# CI/CD release, changelog, and repo hygiene — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a two-phase release workflow (Cursor `prepare-release` skill locally + tag-triggered CI validation/publish), bootstrap Keep a Changelog files for v0.1.0, and ship standard open-source repo hygiene (LICENSE, SECURITY, Dependabot, templates, `cargo audit`).

**Architecture:** Phase A is IDE-only: a `.cursor/skills/prepare-release` skill writes `docs/changelogs/vX.Y.Z.md`, prepends `CHANGELOG.md`, bumps Cargo manifests, and commits. Phase B is manual `git tag vX.Y.Z && git push --tags`. Phase C is existing `release.yml` extended with a `validate` gate (changelog file exists, version matches tag) and `body_path` for GitHub Release body. CI gains `audit` (RustSec) and optional `release-prep-check` on PRs.

**Tech Stack:** Rust 1.88.0, GitHub Actions (`dtolnay/rust-toolchain`, `softprops/action-gh-release@v2`, `Swatinem/rust-cache` optional), `cargo-audit`, Keep a Changelog 1.1.0, Conventional Commits 1.0.0, Contributor Covenant 2.1, MIT License.

## Global Constraints

- Release trigger: manual `git tag vX.Y.Z && git push --tags` (no LLM in GitHub Actions).
- Changelog generation: Cursor agent via `prepare-release` skill only (local IDE).
- Changelog locations: root `CHANGELOG.md` + `docs/changelogs/vX.Y.Z.md` (tracked in git).
- Release body source: `docs/changelogs/vX.Y.Z.md` via `body_path` in `softprops/action-gh-release`; `generate_release_notes: false`.
- Security contact: **contact@michalsk.pl** (SECURITY.md and CoC enforcement).
- Repo hygiene scope: LICENSE (MIT), SECURITY, Dependabot (Cargo + Actions weekly), issue/PR templates, CODEOWNERS (`* @numikel`), CoC (Contributor Covenant 2.1), `docs/github-setup.md`, `cargo audit` in CI.
- Rust toolchain in CI: **1.88.0** (matches existing workflows).
- Changelog language: **English** (matches code and README).
- Changelog date in skill: **UTC**.
- Root `.gitignore` currently ignores `docs/` — must un-ignore `docs/changelogs/**`, `docs/github-setup.md`, `docs/superpowers/**`.
- Non-goals: MSI/deb packaging changes, branch protection as code, automated semver from commits.
- Commit messages: Conventional Commits 1.0.0 (`chore(release): prepare vX.Y.Z` for release prep commits).

---

## File structure (target)

```
kprun/
├── .cursor/skills/prepare-release/SKILL.md   # NEW — release prep agent skill
├── .github/
│   ├── CODEOWNERS                            # NEW
│   ├── dependabot.yml                        # NEW
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.yml                    # NEW
│   │   ├── feature_request.yml               # NEW
│   │   └── config.yml                        # NEW
│   ├── pull_request_template.md              # NEW
│   └── workflows/
│       ├── ci.yml                            # MODIFY — audit + release-prep-check
│       └── release.yml                       # MODIFY — validate job + body_path
├── CHANGELOG.md                              # NEW — bootstrap v0.1.0
├── CODE_OF_CONDUCT.md                        # NEW
├── LICENSE                                   # NEW
├── SECURITY.md                               # NEW
├── docs/
│   ├── changelogs/
│   │   └── v0.1.0.md                         # NEW — first release notes
│   ├── github-setup.md                       # NEW — manual GitHub UI steps
│   └── superpowers/                          # already present locally; un-ignored
├── .gitignore                                # MODIFY — un-ignore tracked docs paths
└── README.md                                 # MODIFY — changelog, security, release workflow
```

---

### Task 1: Un-ignore tracked docs paths in `.gitignore`

**Files:**
- Modify: `.gitignore`

**Interfaces:**
- Produces: git tracks `docs/changelogs/**`, `docs/github-setup.md`, `docs/superpowers/**` while still ignoring other `docs/` content.

- [ ] **Step 1: Replace blanket `docs/` ignore with selective rules**

Replace the entire `.gitignore` with:

```gitignore
/target/
**/*.kdbx
**/*.keyfile
.DS_Store
docs/
!docs/changelogs/
!docs/changelogs/**
!docs/github-setup.md
!docs/superpowers/
!docs/superpowers/**
.docs/
.ai/
.worktrees/
```

- [ ] **Step 2: Verify paths are no longer ignored**

Run:

```powershell
cd d:\kprun\.worktrees\feat-ci-release-repo-hygiene
git check-ignore -v docs/changelogs/v0.1.0.md docs/github-setup.md docs/superpowers/specs/2026-06-23-ci-release-repo-design.md
```

Expected: exit code 1 (no output — paths are **not** ignored).

Run:

```powershell
git check-ignore -v docs/random-note.md
```

Expected: matches `docs/` rule (still ignored).

- [ ] **Step 3: Commit**

```bash
git add .gitignore
git commit -m "chore: un-ignore changelog and superpowers docs paths"
```

---

### Task 2: Bootstrap `CHANGELOG.md` and `docs/changelogs/v0.1.0.md`

**Files:**
- Create: `docs/changelogs/v0.1.0.md`
- Create: `CHANGELOG.md`

**Interfaces:**
- Produces: Keep a Changelog 1.1.0 files for v0.1.0 derived from existing git history (no prior tag).
- Consumed by: Task 7 (`release.yml` validate), Task 8 (`prepare-release` skill as reference pattern).

- [ ] **Step 1: Create `docs/changelogs/v0.1.0.md`**

```markdown
# Changelog v0.1.0

All notable changes to kprun are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-23

### Added

- Cross-platform Rust CLI (`kprun`) with KeePass `.kdbx` vault support (KeePassXC-compatible)
- Per-process secret injection via `kprun run` — env vars scoped to a single child process
- Vault lifecycle commands: `init`, `list`, `get`, `set`, `unset`, `delete`, `export`, `import`
- `doctor` diagnostics with MCP stdio configuration snippet output
- JSON audit log recording entry names and injected key names (never values)
- OS keychain unlock with keyfile and interactive prompt fallback
- RTK-style install scripts (`install.sh`, `install.ps1`) with SHA-256 checksum verification
- Cross-platform CI (fmt, clippy, tests on Linux/macOS/Windows) and tag-triggered release workflow with binary matrix (5 targets) and checksums
- MCP-safe stdio: `run` prints nothing on stdout; child owns stdin/stdout/stderr

### Fixed

- Reject structure-only dotenv import that would wipe the vault
- Escape PowerShell variables in CI install-script smoke test
- Fall back to prompt when OS keyring store is unavailable

### Changed

- MSRV bumped to Rust 1.88.0 for `keyring` 4.1.2 compatibility

---

<details>
<summary>Full commit list</summary>

- feat: scaffold kprun cargo workspace
- feat(core): add error types and KEY=val parser
- feat(core): add config path resolution from env
- feat(core): add unlock module with keystore and prompt fallback
- feat(core): add vault read operations and entry lookup
- feat(core): add inject resolver and audit logger
- feat(core): add vault write path with atomic save
- feat(cli): add clap command tree and child process spawner
- feat(cli): add kprun init command
- feat(cli): add kprun run with per-process env injection
- feat(cli): add list get set unset delete commands
- feat(cli): add export and import with merge support
- fix(cli): reject structure-only dotenv import that would wipe vault
- feat(cli): add doctor diagnostics and mcp snippet output
- ci: add cross-platform test clippy and fmt workflow
- ci: add release workflow with checksums
- feat(scripts): add install.sh and install.ps1 with checksum verify
- build: bump MSRV to 1.88.0 for keyring 4.1.2
- fix(unlock): fall back when keyring store is unavailable

</details>
```

- [ ] **Step 2: Create root `CHANGELOG.md`**

```markdown
# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-23

See [docs/changelogs/v0.1.0.md](docs/changelogs/v0.1.0.md) for details.

### Added

- Initial public release: KeePass-backed local secrets injector with per-process env injection, full vault management CLI, MCP-safe stdio, install scripts, and cross-platform CI/release assets.

### Fixed

- Dotenv import guard, keyring fallback, CI PowerShell escaping.

### Changed

- MSRV 1.88.0.
```

- [ ] **Step 3: Verify files are trackable**

Run:

```powershell
git add docs/changelogs/v0.1.0.md CHANGELOG.md
git status --short
```

Expected: both files staged (not ignored).

- [ ] **Step 4: Commit**

```bash
git add docs/changelogs/v0.1.0.md CHANGELOG.md
git commit -m "docs: bootstrap changelog for v0.1.0"
```

---

### Task 3: Add LICENSE, SECURITY.md, and CODE_OF_CONDUCT.md

**Files:**
- Create: `LICENSE`
- Create: `SECURITY.md`
- Create: `CODE_OF_CONDUCT.md`

**Interfaces:**
- Produces: MIT license, security policy (contact@michalsk.pl), Contributor Covenant 2.1.
- Consumed by: Task 4 (issue template config links SECURITY), Task 9 (README links).

- [ ] **Step 1: Create `LICENSE`**

```text
MIT License

Copyright (c) 2025-2026 Michał Sk

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 2: Create `SECURITY.md`**

```markdown
# Security policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| Latest release | ✅ |
| Older releases | ❌ |

## Reporting a vulnerability

**Do not** open a public GitHub issue for security vulnerabilities.

Report security issues to **contact@michalsk.pl**.

For this repository, you may also use [GitHub Private Security Advisories](https://github.com/numikel/kprun/security/advisories/new) on `numikel/kprun`.

We aim to acknowledge reports within **7 days** and will coordinate disclosure and fixes with the reporter.

## Out of scope

- Social engineering attacks
- Physical attacks against users or infrastructure
- Issues in third-party dependencies without a practical exploit path in kprun (report upstream; we track via Dependabot and `cargo audit`)

## Security model

kprun injects secrets into **child process environments**. Treat vault files (`.kdbx`), keyfiles, and audit logs as sensitive. Do not commit them to version control.
```

- [ ] **Step 3: Create `CODE_OF_CONDUCT.md`**

Use the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/) text. Create the file with this content (standard template with project-specific enforcement contact):

```markdown
# Contributor Covenant Code of Conduct

## Our pledge

We as members, contributors, and leaders pledge to make participation in our
community a harassment-free experience for everyone, regardless of age, body
size, visible or invisible disability, ethnicity, sex characteristics, gender
identity and expression, level of experience, education, socio-economic status,
nationality, personal appearance, race, caste, color, religion, or sexual
identity and orientation.

We pledge to act and interact in ways that contribute to an open, welcoming,
diverse, inclusive, and healthy community.

## Our standards

Examples of behavior that contributes to a positive environment for our
community include:

* Demonstrating empathy and kindness toward other people
* Being respectful of differing opinions, viewpoints, and experiences
* Giving and gracefully accepting constructive feedback
* Accepting responsibility and apologizing to those affected by our mistakes,
  and learning from the experience
* Focusing on what is best not just for us as individuals, but for the overall
  community

Examples of unacceptable behavior include:

* The use of sexualized language or imagery, and sexual attention or advances of
  any kind
* Trolling, insulting or derogatory comments, and personal or political attacks
* Public or private harassment
* Publishing others' private information, such as a physical or email address,
  without their explicit permission
* Other conduct which could reasonably be considered inappropriate in a
  professional setting

## Enforcement responsibilities

Community leaders are responsible for clarifying and enforcing our standards of
acceptable behavior and will take appropriate and fair corrective action in
response to any behavior that they deem inappropriate, threatening, offensive,
or harmful.

Community leaders have the right and responsibility to remove, edit, or reject
comments, commits, code, wiki edits, issues, and other contributions that are
not aligned to this Code of Conduct, and will communicate reasons for moderation
decisions when appropriate.

## Scope

This Code of Conduct applies within all community spaces, and also applies when
an individual is officially representing the community in public spaces.
Examples of representing our community include using an official email address,
posting via an official social media account, or acting as an appointed
representative at an online or offline event.

## Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be
reported to the community leaders responsible for enforcement at
**contact@michalsk.pl**.

All complaints will be reviewed and investigated promptly and fairly.

All community leaders are obligated to respect the privacy and security of the
reporter of any incident.

## Enforcement guidelines

Community leaders will follow these Community Impact Guidelines in determining
the consequences for any action they deem in violation of this Code of Conduct:

### 1. Correction

**Community impact:** Use of inappropriate language or other behavior deemed
unprofessional or unwelcome in the community.

**Consequence:** A private, written warning from community leaders, providing
clarity around the nature of the violation and an explanation of why the
behavior was inappropriate. A public apology may be requested.

### 2. Warning

**Community impact:** A violation through a single incident or series of actions.

**Consequence:** A warning with consequences for continued behavior. No
interaction with the people involved, including unsolicited interaction with
those enforcing the Code of Conduct, for a specified period of time. This
includes avoiding interactions in community spaces as well as external channels
like social media. Violating these terms may lead to a temporary or permanent
ban.

### 3. Temporary ban

**Community impact:** A serious violation of community standards, including
sustained inappropriate behavior.

**Consequence:** A temporary ban from any sort of interaction or public
communication with the community for a specified period of time. No public or
private interaction with people involved, including unsolicited interaction
with those enforcing the Code of Conduct, is allowed during this period.
Violating these terms may lead to a permanent ban.

### 4. Permanent ban

**Community impact:** Demonstrating a pattern of violation of community
standards, including sustained inappropriate behavior, harassment of an
individual, or aggression toward or disparagement of classes of individuals.

**Consequence:** A permanent ban from any sort of public interaction within the
community.

## Attribution

This Code of Conduct is adapted from the [Contributor Covenant][homepage],
version 2.1, available at
[https://www.contributor-covenant.org/version/2/1/code_of_conduct.html][v2.1].

[homepage]: https://www.contributor-covenant.org
[v2.1]: https://www.contributor-covenant.org/version/2/1/code_of_conduct.html
```

- [ ] **Step 4: Verify LICENSE is packaged**

Run:

```powershell
cargo package --list -p kprun 2>&1 | Select-String "LICENSE"
```

Expected: `LICENSE` appears in package file list (workspace `license = "MIT"` already set).

- [ ] **Step 5: Commit**

```bash
git add LICENSE SECURITY.md CODE_OF_CONDUCT.md
git commit -m "chore: add LICENSE, SECURITY policy, and code of conduct"
```

---

### Task 4: Add GitHub community health files

**Files:**
- Create: `.github/dependabot.yml`
- Create: `.github/CODEOWNERS`
- Create: `.github/ISSUE_TEMPLATE/bug_report.yml`
- Create: `.github/ISSUE_TEMPLATE/feature_request.yml`
- Create: `.github/ISSUE_TEMPLATE/config.yml`
- Create: `.github/pull_request_template.md`

**Interfaces:**
- Produces: Dependabot weekly updates (Cargo + Actions), default reviewer routing, structured issue/PR templates.

- [ ] **Step 1: Create `.github/dependabot.yml`**

```yaml
version: 2
updates:
  - package-ecosystem: cargo
    directory: /
    schedule:
      interval: weekly
    open-pull-requests-limit: 5
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
```

- [ ] **Step 2: Create `.github/CODEOWNERS`**

```
* @numikel
```

- [ ] **Step 3: Create `.github/ISSUE_TEMPLATE/bug_report.yml`**

```yaml
name: Bug report
description: Report a problem with kprun
title: "[bug]: "
labels: ["bug"]
body:
  - type: input
    id: version
    attributes:
      label: kprun version
      description: Output of `kprun --version`
      placeholder: "0.1.0"
    validations:
      required: true
  - type: dropdown
    id: os
    attributes:
      label: Operating system
      options:
        - Linux
        - macOS
        - Windows
    validations:
      required: true
  - type: textarea
    id: steps
    attributes:
      label: Steps to reproduce
      description: Commands and config (redact secrets)
      placeholder: |
        1. kprun init ...
        2. kprun run ...
    validations:
      required: true
  - type: textarea
    id: expected
    attributes:
      label: Expected behavior
    validations:
      required: true
  - type: textarea
    id: actual
    attributes:
      label: Actual behavior
    validations:
      required: true
  - type: textarea
    id: logs
    attributes:
      label: Logs / additional context
      description: stderr output, audit log excerpts (no secret values)
```

- [ ] **Step 4: Create `.github/ISSUE_TEMPLATE/feature_request.yml`**

```yaml
name: Feature request
description: Suggest an idea for kprun
title: "[feat]: "
labels: ["enhancement"]
body:
  - type: textarea
    id: problem
    attributes:
      label: Problem
      description: What problem does this solve?
    validations:
      required: true
  - type: textarea
    id: solution
    attributes:
      label: Proposed solution
    validations:
      required: true
  - type: textarea
    id: alternatives
    attributes:
      label: Alternatives considered
  - type: textarea
    id: context
    attributes:
      label: Additional context
```

- [ ] **Step 5: Create `.github/ISSUE_TEMPLATE/config.yml`**

```yaml
blank_issues_enabled: false
contact_links:
  - name: Security vulnerability
    url: https://github.com/numikel/kprun/security/advisories/new
    about: Report security issues privately (see SECURITY.md)
```

- [ ] **Step 6: Create `.github/pull_request_template.md`**

```markdown
## Summary

<!-- What changed and why? -->

## Checklist

- [ ] Tests added or updated if behavior changed
- [ ] `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all` pass locally
- [ ] Commit message follows [Conventional Commits 1.0.0](https://www.conventionalcommits.org/)
- [ ] User-facing changes will be noted in changelog at release time via `/prepare-release`
```

- [ ] **Step 7: Validate YAML syntax locally**

Run:

```powershell
Get-Content .github/dependabot.yml, .github/ISSUE_TEMPLATE/bug_report.yml, .github/ISSUE_TEMPLATE/feature_request.yml, .github/ISSUE_TEMPLATE/config.yml | Out-Null; Write-Host "YAML files readable"
```

Expected: no parse errors (GitHub validates on push; spot-check file contents).

- [ ] **Step 8: Commit**

```bash
git add .github/dependabot.yml .github/CODEOWNERS .github/ISSUE_TEMPLATE/ .github/pull_request_template.md
git commit -m "chore: add Dependabot, CODEOWNERS, and issue/PR templates"
```

---

### Task 5: Add `cargo audit` job to CI

**Files:**
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: Rust 1.88.0 toolchain (same as `test` job).
- Produces: `audit` job name for branch protection docs in Task 9.

- [ ] **Step 1: Install and run `cargo audit` locally (baseline)**

Run:

```powershell
cargo install cargo-audit --locked 2>$null; cargo audit
```

Expected: exits 0 (no vulnerabilities) or note advisories to fix before merging. If CVEs exist, update dependencies in a separate commit before enabling failing CI.

- [ ] **Step 2: Add `audit` job to `.github/workflows/ci.yml`**

Append after the `install-script-smoke` job (full file):

```yaml
name: CI
on:
  push:
    branches: [master, main]
  pull_request:

jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: 1.88.0
          components: rustfmt, clippy
      - run: cargo fmt --all -- --check
      - run: cargo clippy --all-targets --all-features -- -D warnings
      - run: cargo test --all

  install-script-smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: bash -n scripts/install.sh
      - run: pwsh -NoProfile -Command '$errs=$null; [void][System.Management.Automation.Language.Parser]::ParseFile("scripts/install.ps1", [ref]$null, [ref]$errs); if ($errs) { exit 1 }'

  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: 1.88.0
      - uses: Swatinem/rust-cache@v2
      - name: Install cargo-audit
        run: cargo install cargo-audit --locked
      - name: Run cargo audit
        run: cargo audit
```

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add cargo audit job for RustSec advisories"
```

---

### Task 6: Add `release-prep-check` job to CI

**Files:**
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: root `Cargo.toml` `[workspace.package].version`, `docs/changelogs/v*.md`.
- Produces: PR gate — version bump without matching changelog file fails CI.

- [ ] **Step 1: Add `release-prep-check` job**

Insert before the `audit` job in `.github/workflows/ci.yml`:

```yaml
  release-prep-check:
    if: github.event_name == 'pull_request' && github.base_ref == 'main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Require changelog when workspace version changes
        run: |
          set -euo pipefail
          base="${{ github.event.pull_request.base.sha }}"
          head="${{ github.event.pull_request.head.sha }}"
          if ! git diff "$base" "$head" -- Cargo.toml | grep -q '^[+-].*version'; then
            echo "Cargo.toml version unchanged — skip changelog check"
            exit 0
          fi
          new_version=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
          changelog="docs/changelogs/v${new_version}.md"
          if git diff --name-only "$base" "$head" | grep -Fxq "$changelog"; then
            echo "Found $changelog in PR"
            exit 0
          fi
          echo "ERROR: Cargo.toml version bumped to ${new_version} but ${changelog} not added in this PR"
          exit 1
```

- [ ] **Step 2: Test logic locally (simulated)**

Run on current branch (should skip — no version change in last commit vs parent):

```powershell
git diff HEAD~1 HEAD -- Cargo.toml
```

If no version line change, the script would print "version unchanged — skip" and exit 0.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: require per-version changelog when workspace version changes"
```

---

### Task 7: Extend `release.yml` with validate gate and `body_path`

**Files:**
- Modify: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: `docs/changelogs/v${VERSION}.md`, root `Cargo.toml` workspace version.
- Produces: GitHub Release with markdown body from per-version changelog file.

- [ ] **Step 1: Add `validate` job and wire dependencies**

Replace `.github/workflows/release.yml` with:

```yaml
name: Release

on:
  push:
    tags:
      - "v*"

permissions:
  contents: write

env:
  CARGO_TERM_COLOR: always

jobs:
  validate:
    name: Validate release metadata
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Parse version from tag
        run: echo "VERSION=${GITHUB_REF#refs/tags/v}" >> $GITHUB_ENV
      - name: Require per-version changelog
        run: test -f "docs/changelogs/v${VERSION}.md"
      - name: Require version match
        run: |
          set -euo pipefail
          cargo_version=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
          if [ "$cargo_version" != "$VERSION" ]; then
            echo "ERROR: Cargo.toml version ($cargo_version) != tag ($VERSION)"
            exit 1
          fi
          echo "Version OK: $VERSION"

  build:
    name: Build ${{ matrix.target }}
    needs: validate
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        include:
          - target: x86_64-unknown-linux-gnu
            os: ubuntu-latest
            archive: tar.gz
          - target: aarch64-unknown-linux-gnu
            os: ubuntu-latest
            archive: tar.gz
            cross: true
          - target: x86_64-apple-darwin
            os: macos-latest
            archive: tar.gz
          - target: aarch64-apple-darwin
            os: macos-latest
            archive: tar.gz
          - target: x86_64-pc-windows-msvc
            os: windows-latest
            archive: zip

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: 1.88.0
          targets: ${{ matrix.target }}

      - name: Install cross-compilation tools
        if: matrix.cross
        run: |
          sudo apt-get update
          sudo apt-get install -y gcc-aarch64-linux-gnu
          echo "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc" >> $GITHUB_ENV

      - name: Build
        run: cargo build --release -p kprun --target ${{ matrix.target }}

      - name: Package (Unix)
        if: matrix.os != 'windows-latest'
        run: |
          mkdir -p staging
          cd target/${{ matrix.target }}/release
          tar -czvf ../../../staging/kprun-${{ matrix.target }}.${{ matrix.archive }} kprun
          cd ../../..

      - name: Package (Windows)
        if: matrix.os == 'windows-latest'
        shell: pwsh
        run: |
          New-Item -ItemType Directory -Force -Path staging | Out-Null
          $release = "target/${{ matrix.target }}/release"
          Compress-Archive -Path "$release/kprun.exe" -DestinationPath "staging/kprun-${{ matrix.target }}.zip" -Force
          Copy-Item "$release/kprun.exe" "staging/kprun.exe"

      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: kprun-${{ matrix.target }}
          path: staging/

  release:
    name: Create Release
    needs: build
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Parse version from tag
        run: echo "VERSION=${GITHUB_REF#refs/tags/v}" >> $GITHUB_ENV

      - name: Download artifacts
        uses: actions/download-artifact@v4
        with:
          path: artifacts

      - name: Flatten artifacts
        run: |
          mkdir -p release
          find artifacts -type f \( -name "*.tar.gz" -o -name "*.zip" -o -name "*.exe" \) -exec cp {} release/ \;

      - name: Create checksums
        run: |
          cd release
          sha256sum * > checksums.txt

      - name: Upload Release Assets
        uses: softprops/action-gh-release@v2
        with:
          body_path: docs/changelogs/v${{ env.VERSION }}.md
          generate_release_notes: false
          files: release/*
```

- [ ] **Step 2: Run local validate script (happy path)**

Run:

```powershell
$VERSION = "0.1.0"
Test-Path "docs/changelogs/v$VERSION.md"
$cargo_version = (Select-String -Path Cargo.toml -Pattern '^version' | Select-Object -First 1).Line -replace '.*"(.*)".*','$1'
Write-Host "cargo=$cargo_version tag=$VERSION match=$($cargo_version -eq $VERSION)"
```

Expected: `True` and `match=True`.

- [ ] **Step 3: Run local validate script (missing changelog — negative test)**

Run:

```powershell
$VERSION = "9.9.9"
Test-Path "docs/changelogs/v$VERSION.md"
```

Expected: `False` (would fail CI validate step).

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci(release): validate changelog and version before publishing"
```

---

### Task 8: Create `prepare-release` Cursor skill

**Files:**
- Create: `.cursor/skills/prepare-release/SKILL.md`

**Interfaces:**
- Consumes: git history since last tag, Conventional Commits, existing changelog pattern from Task 2.
- Produces: `docs/changelogs/vX.Y.Z.md`, updated `CHANGELOG.md`, bumped Cargo versions, commit `chore(release): prepare vX.Y.Z`.

- [ ] **Step 1: Create directory and skill file**

Create `.cursor/skills/prepare-release/SKILL.md`:

```markdown
---
name: prepare-release
description: Prepare a kprun release — write Keep a Changelog files, bump Cargo versions, commit. Use when the user asks to prepare release vX.Y.Z or run /prepare-release.
---

# Prepare release

Prepare a kprun release locally. **No LLM calls in CI** — all changelog writing happens here in the IDE.

## Invocation

User runs `/prepare-release X.Y.Z` where `X.Y.Z` is semver **without** the `v` prefix (e.g. `0.2.0`).

## Mandatory checklist (follow in order)

### 1. Resolve commit range

```bash
git fetch --tags
PREV=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
if [ -z "$PREV" ]; then
  RANGE="first commit..HEAD"
else
  RANGE="${PREV}..HEAD"
fi
git log $RANGE --oneline
git log $RANGE --format="%s"
```

If range is empty (no commits since last tag), **stop** and ask the user to confirm before writing an empty changelog.

### 2. Classify commits

Group `git log` subjects by Conventional Commits type:

| Type | Keep a Changelog section |
|------|--------------------------|
| `feat` | Added |
| `fix` | Fixed |
| `perf` | Changed |
| `refactor` | Changed |
| `docs` | Changed (or omit if internal-only) |
| `ci`, `build`, `chore` | omit unless user-facing |
| `feat!`, `fix!`, footer `BREAKING CHANGE:` | Changed + breaking note |

Write **user-facing** bullets in English. No raw SHAs in bullet text. Optional `<details>` footer with full commit list.

### 3. Write per-version file

Create `docs/changelogs/vX.Y.Z.md`:

- Format: [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/)
- Title/header includes version and date (**UTC**: `YYYY-MM-DD` from `date -u +%Y-%m-%d`)
- Sections (omit empty): `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`
- Reference prior file `docs/changelogs/v0.1.0.md` for tone and structure

### 4. Update root CHANGELOG.md

Prepend a new section at the top (after the intro paragraphs):

```markdown
## [X.Y.Z] - YYYY-MM-DD

See [docs/changelogs/vX.Y.Z.md](docs/changelogs/vX.Y.Z.md) for details.

### Added
- (short summary bullets)
```

Keep root entries as summaries; full detail stays in per-version file.

### 5. Version bump

Update **all three** locations to `X.Y.Z`:

1. `[workspace.package].version` in root `Cargo.toml`
2. `crates/kprun/Cargo.toml` — uses `version.workspace = true` (verify, do not duplicate)
3. `crates/kprun-core/Cargo.toml` — uses `version.workspace = true` (verify)

Only the workspace root `version = "..."` line needs editing if crates use `version.workspace = true`.

Update `tests/version.rs` expected string if present (`contains("X.Y.Z")`).

Update README title badge line `# kprun vX.Y.Z` if present.

### 6. Self-check (must pass before commit)

- [ ] `docs/changelogs/vX.Y.Z.md` exists
- [ ] No `TBD`, `TODO`, or placeholder text in changelog files
- [ ] Semver `X.Y.Z` consistent: tag target version = `Cargo.toml` workspace version = filename
- [ ] Date is today UTC
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo test --all` passes (especially `tests/version.rs`)

### 7. Commit

Single commit only:

```bash
git add CHANGELOG.md docs/changelogs/vX.Y.Z.md Cargo.toml README.md tests/version.rs
git commit -m "chore(release): prepare vX.Y.Z"
```

## Maintainer steps after skill (tell the user)

```bash
git tag vX.Y.Z
git push origin main --tags
```

CI `release.yml` will validate changelog file + version match, build matrix, and publish GitHub Release with `body_path: docs/changelogs/vX.Y.Z.md`.

## First release bootstrap

When no prior tag exists, generate `docs/changelogs/v0.1.0.md` from full project history and seed `CHANGELOG.md`. Maintainer tags `v0.1.0` on that commit.

## Error handling

| Scenario | Action |
|----------|--------|
| Empty commit range | Ask user to confirm before empty changelog |
| Placeholders left | Fix before commit; never commit TBD/TODO |
| Version mismatch | Fix manifests before commit |
| User gives `v0.2.0` prefix | Strip leading `v` and use `0.2.0` |
```

- [ ] **Step 2: Verify skill file path**

Run:

```powershell
Test-Path .cursor/skills/prepare-release/SKILL.md
```

Expected: `True`.

- [ ] **Step 3: Commit**

```bash
git add .cursor/skills/prepare-release/SKILL.md
git commit -m "chore: add prepare-release Cursor skill for changelog and version bumps"
```

Note: `.cursor/` is not gitignored — skill is tracked in repo for all contributors.

---

### Task 9: Add `docs/github-setup.md` and update README

**Files:**
- Create: `docs/github-setup.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: CI job names `test`, `audit` from Tasks 5–6.
- Produces: maintainer documentation for GitHub UI settings and user-facing release workflow docs.

- [ ] **Step 1: Create `docs/github-setup.md`**

```markdown
# GitHub repository setup

Manual steps for the `numikel/kprun` repository owner. Not enforced as code.

## 1. License

Set the GitHub repository license to **MIT** (Settings → General → License). It must match the [LICENSE](../LICENSE) file in this repo.

## 2. Dependabot and security

- Settings → Code security and analysis
- Enable **Dependabot alerts**
- Enable **Dependabot security updates**

Dependabot version updates are configured in [.github/dependabot.yml](../.github/dependabot.yml) (weekly Cargo + GitHub Actions).

## 3. Branch protection on `main`

Settings → Branches → Add rule for `main`:

- Require status checks before merging:
  - `test` (CI matrix)
  - `audit` (cargo audit)
- Do not allow force pushes
- Optional for solo maintainer: require pull request reviews

## 4. First release

After changelog bootstrap and CI changes are merged:

```bash
git tag v0.1.0
git push origin main --tags
```

Verify the GitHub Release body matches [docs/changelogs/v0.1.0.md](changelogs/v0.1.0.md) and assets include platform archives plus `checksums.txt`.

## 5. Subsequent releases

In Cursor, run `/prepare-release X.Y.Z`, review the commit, then:

```bash
git tag vX.Y.Z
git push origin main --tags
```
```

- [ ] **Step 2: Update README — add changelog link after header badges**

After the badge line block (line ~6), add:

```markdown
[Changelog](CHANGELOG.md) ·
```

So the links row becomes:

```markdown
[Releases](https://github.com/numikel/kprun/releases) · [Changelog](CHANGELOG.md) · [Install](#installation) · [Quick start](#quick-start) · [MCP integration](#mcp-integration) · [Security model](#security-model)
```

- [ ] **Step 3: Update README — expand Security model section**

After the first bullet in `## Security model`, add:

```markdown
- Report vulnerabilities per [SECURITY.md](SECURITY.md) (**contact@michalsk.pl**); do not file public issues for security bugs.
```

- [ ] **Step 4: Add `## Releases` section before `## Contributing`**

Insert before `## Contributing`:

```markdown
## Releases

kprun uses a two-step release process:

1. **Prepare (local)** — In Cursor, run `/prepare-release X.Y.Z`. The agent writes `docs/changelogs/vX.Y.Z.md`, updates [CHANGELOG.md](CHANGELOG.md), bumps the workspace version, and commits `chore(release): prepare vX.Y.Z`.
2. **Publish (manual)** — Tag and push:

   ```bash
   git tag vX.Y.Z
   git push origin main --tags
   ```

CI validates the changelog file and version match, builds release binaries for five targets, and publishes a GitHub Release whose body comes from the per-version changelog file.

See [docs/github-setup.md](docs/github-setup.md) for repository settings (branch protection, Dependabot, first release).
```

- [ ] **Step 5: Update Contributing section**

Add to the Contributing numbered list after item 3:

```markdown
3.5. For release preparation, use `/prepare-release X.Y.Z` (maintainers only).
```

(Renumber subsequent items if desired, or keep as sub-bullet.)

- [ ] **Step 6: Verify markdown links**

Run:

```powershell
@('CHANGELOG.md','SECURITY.md','LICENSE','docs/github-setup.md','docs/changelogs/v0.1.0.md') | ForEach-Object { "$_ : $(Test-Path $_)" }
```

Expected: all `True`.

- [ ] **Step 7: Commit**

```bash
git add docs/github-setup.md README.md
git commit -m "docs: add GitHub setup guide and document release workflow in README"
```

---

### Task 10: Final verification

**Files:**
- Verify: all files from spec inventory

**Interfaces:**
- Consumes: entire implementation from Tasks 1–9.

- [ ] **Step 1: Run full local quality gate**

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo audit
```

Expected: all pass.

- [ ] **Step 2: Verify spec file inventory**

Run:

```powershell
@(
  '.cursor/skills/prepare-release/SKILL.md',
  'CHANGELOG.md',
  'docs/changelogs/v0.1.0.md',
  'docs/github-setup.md',
  'LICENSE',
  'SECURITY.md',
  'CODE_OF_CONDUCT.md',
  '.github/dependabot.yml',
  '.github/CODEOWNERS',
  '.github/ISSUE_TEMPLATE/bug_report.yml',
  '.github/ISSUE_TEMPLATE/feature_request.yml',
  '.github/ISSUE_TEMPLATE/config.yml',
  '.github/pull_request_template.md',
  '.github/workflows/release.yml',
  '.github/workflows/ci.yml',
  '.gitignore',
  'README.md'
) | ForEach-Object { if (-not (Test-Path $_)) { Write-Error "MISSING: $_" } }
```

Expected: no MISSING errors.

- [ ] **Step 3: Dry-run prepare-release skill (optional smoke)**

On a throwaway branch, invoke `/prepare-release 0.1.1` and verify it would produce consistent files (do not push tag). Revert or discard if only testing.

- [ ] **Step 4: Final commit if any fixups needed**

Only if Steps 1–3 surfaced fixes:

```bash
git add -A
git commit -m "chore: address release hygiene verification fixups"
```

---

## Self-review

### Spec coverage

| Spec requirement | Task |
|------------------|------|
| `prepare-release` skill | Task 8 |
| `CHANGELOG.md` + `docs/changelogs/vX.Y.Z.md` | Task 2 |
| `release.yml` validate + `body_path` | Task 7 |
| `ci.yml` `cargo audit` | Task 5 |
| `release-prep-check` on PRs | Task 6 |
| LICENSE (MIT, Michał Sk) | Task 3 |
| SECURITY.md (contact@michalsk.pl) | Task 3 |
| Dependabot Cargo + Actions | Task 4 |
| Issue/PR templates | Task 4 |
| CODEOWNERS | Task 4 |
| CODE_OF_CONDUCT.md | Task 3 |
| `docs/github-setup.md` | Task 9 |
| `.gitignore` un-ignore docs paths | Task 1 |
| README updates | Task 9 |
| Bootstrap v0.1.0 | Task 2 |
| No LLM in Actions | All workflow tasks (no AI steps) |

No spec gaps identified.

### Placeholder scan

No `TBD`, `TODO`, or "implement later" steps in this plan.

### Type consistency

- Version env var `VERSION` used consistently in `release.yml` validate and release jobs.
- Changelog path pattern `docs/changelogs/v${VERSION}.md` consistent across skill, CI check, and release workflow.
- Security contact `contact@michalsk.pl` consistent across SECURITY.md, CoC, issue config, README.
