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
