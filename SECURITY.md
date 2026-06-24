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

### File permissions

Vault databases, keyfiles, audit logs, and export files are created with owner-only permissions (`0600` on Unix; on Windows, inheritance is removed and access is limited to the current user).

### Keychain storage

When you run `kprun init` without `--no-store`, the KeePass master password is stored in the OS keychain (Credential Manager on Windows, Keychain on macOS, Secret Service on Linux). The entry is keyed per vault path (`kprun` / `master:<sha256(db_path)>`), not shared across vaults. The password is stored as plaintext in the keychain — anyone with access to your unlocked OS session can read it. Use `kprun deinit` to remove the stored password for the current vault.

### Process environment exposure

Injected secrets are visible to the child process and, on many systems, to other users with sufficient privileges via `/proc/<pid>/environ`, Process Explorer, or `ps e`. Use `kprun run --clean-env` to drop the parent environment and pass only injected secrets plus a minimal safe baseline.

### Verifying releases

Release `checksums.txt` is signed with minisign. Verify with:

```sh
minisign -Vm checksums.txt -P RWS4FT610kpYiZVGSJF6QfIJEFHB1DKxvSQkISakpp4e86kABel6WVkr
sha256sum -c checksums.txt
```

kprun minisign public key:

```
untrusted comment: minisign public key 89584AD2B53E15B8
RWS4FT610kpYiZVGSJF6QfIJEFHB1DKxvSQkISakpp4e86kABel6WVkr
```

Install scripts verify the minisign signature when `minisign` is available and a real public key is configured.

### test-hooks scope

`KPRUN_TEST_MASTER` is honored only in builds compiled with `--features test-hooks`. GitHub Release binaries do not include this feature; the variable has no effect on release installs.
