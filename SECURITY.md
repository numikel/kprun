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
