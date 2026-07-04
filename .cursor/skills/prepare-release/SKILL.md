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
