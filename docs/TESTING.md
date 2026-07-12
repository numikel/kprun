# Testing Guide — Manual Testing of kprun Features

This guide provides step-by-step instructions for setting up a test environment and manually testing kprun functionality. Use this to validate new features, breaking changes, and cross-platform behavior before release.

## Quick Setup (5 minutes)

### 1. Create a test vault

```bash
# Set a temporary directory for test data (does NOT modify your real vault)
export KPRUN_DB="$HOME/.kprun-test/test-vault.kdbx"
export KPRUN_KEYFILE="$HOME/.kprun-test/test-keyfile.key"

# Or Windows PowerShell:
$env:KPRUN_DB = "$env:USERPROFILE\.kprun-test\test-vault.kdbx"
$env:KPRUN_KEYFILE = "$env:USERPROFILE\.kprun-test\test-keyfile.key"

# Create the vault with a simple master password
mkdir -p "$HOME/.kprun-test"
kprun init --quick
# → Generates password, stores in OS keychain, prints it once
# Save the printed password for reference: e.g., ABC123xyz_789
```

### 2. Verify setup

```bash
kprun --version
kprun get --help
echo $KPRUN_DB
```

---

## Testing Workflows by Feature

### Testing `init` command

#### Case 1: Interactive init (choose your own password)

```bash
rm -f "$KPRUN_DB"
KPRUN_DB="/tmp/test-interactive.kdbx" kprun init
# → Prompts for password, keyfile location
# → Creates vault
```

#### Case 2: Non-interactive `init --quick`

```bash
rm -f "$KPRUN_DB"
kprun init --quick
# → Generates master password automatically
# → Prints it once (save this)
# → Stores in OS keychain
```

#### Case 3: `init --quick --force` (overwrite existing)

```bash
kprun init --quick --force
# → Overwrites existing vault (TTY prompt for confirmation if interactive)
# → New master password generated and stored
```

### Testing `set` / `get` commands

```bash
# Store a test entry
kprun set github GITHUB_TOKEN=ghp_test123 GITHUB_USER=testuser

# Retrieve it
kprun get github
# → Should print: GITHUB_TOKEN=ghp_test123 GITHUB_USER=testuser

# Edit an entry
kprun set github GITHUB_TOKEN=ghp_updated
kprun get github
# → GITHUB_TOKEN should now be ghp_updated
```

### Testing `run` command (injection)

```bash
# Verify env vars are injected into child process only
kprun run github -- sh -c 'echo "GITHUB_TOKEN=$GITHUB_TOKEN"'
# → Prints: GITHUB_TOKEN=ghp_test123 (or updated value)

# Verify parent shell does NOT have the var
echo "Parent shell GITHUB_TOKEN=$GITHUB_TOKEN"
# → Should be empty

# Test with multiple entries
kprun set openai OPENAI_API_KEY=sk-test123 OPENAI_ORG=test-org
kprun run openai -- sh -c 'echo $OPENAI_API_KEY'
# → Prints: sk-test123
```

### Testing `reveal-master` command (NEW in v0.5.0)

```bash
# Display the stored master password from OS keychain
kprun reveal-master
# → Prints the master password (generated or set during init)
# → Logs to audit trail (key name only, never the value)

# Test with non-standard vault path
kprun reveal-master --db /tmp/test-interactive.kdbx
# → Retrieves password for that specific vault
```

### Testing `deinit` command (NEW in v0.5.0)

```bash
# Remove vault file and keychain entry
kprun deinit --delete-vault

# Verify vault is gone
ls -la "$KPRUN_DB"
# → File not found (or error)

# Verify keychain entry is gone
kprun reveal-master
# → Should fail: "keychain entry not found" or similar

# Verify you can re-init
kprun init --quick
# → Creates new vault with new password
```

---

## Platform-Specific Tests

### Windows Tests

#### Keychain integration (Windows Credential Manager)

```powershell
# Verify password is stored in Windows Credential Manager
kprun init --quick
# → Master password displayed

# Verify reveal-master works
kprun reveal-master
# → Should print the same password

# Check Credential Manager GUI
# Start → Credential Manager → Windows Credentials
# → Look for entry with pattern "kprun: <sha256-of-path>"

# Test deinit removes credential
kprun deinit --delete-vault
# → Entry should disappear from Credential Manager
```

#### Path canonicalization (v0.5.0 breaking change test)

```powershell
# Test that keychain account name is consistent (lexical path)

# Create vault at standard path
$env:KPRUN_DB = "$env:USERPROFILE\.kprun-test\vault.kdbx"
kprun init --quick
$pwd1 = kprun reveal-master
Write-Host "Vault 1 password: $pwd1"

# Now test with symlink or UNC path (if applicable)
# Verify that reveal-master still finds the same password
# (it should use lexical path canonicalization, not fs::canonicalize)

# Delete vault file but keep keychain entry
Remove-Item "$env:USERPROFILE\.kprun-test\vault.kdbx" -Force

# Verify reveal-master still works (keychain lookup is independent)
$pwd2 = kprun reveal-master
if ($pwd1 -eq $pwd2) {
  Write-Host "✓ Keychain lookup consistent after file deletion"
} else {
  Write-Host "✗ Keychain lookup failed after file deletion"
}
```

### macOS Tests

#### Keychain integration (macOS Keychain)

```bash
# Verify password is stored in macOS Keychain
kprun init --quick

# Check Keychain.app GUI
# Open Keychain Access → Local Items
# → Look for entry with "kprun: <sha256-of-path>"

# Test reveal-master
kprun reveal-master
# → Should print stored password

# Test on /tmp vault (path canonicalization test)
KPRUN_DB="/tmp/test-vault-$RANDOM.kdbx" kprun init --quick
kprun reveal-master
# → Should work (keychain lookup by lexical path)
```

### Linux Tests

#### Keyring integration (systemd user-dbus, gnome-keyring, pass)

```bash
# Linux uses keyring lib which may fall back to:
# - systemd user-dbus (preferred)
# - gnome-keyring
# - pass
# - stderr prompt if none available

kprun init --quick
# → May prompt "Enter master password:" (headless fallback)
# → Or store in systemd keyring (no prompt)

# Test reveal-master
kprun reveal-master
# → Should retrieve from keyring or prompt

# Test headless mode (no TTY, no keyring available)
# This simulates MCP mode:
echo "test-password" | kprun init --quick < /dev/null
# → Should fail gracefully (no interactive prompt possible)
```

---

## Testing `kprun mcp` (MCP Bridge)

### Setup

```bash
# Add an entry for MCP server
kprun set github GITHUB_TOKEN=ghp_test123

# Start the MCP bridge in background
kprun mcp --listen 127.0.0.1:8765 &
MCP_PID=$!

# Give it a moment to start
sleep 1
```

### Test requests

```bash
# Test via curl or another MCP client
# Example: fetch template for 'github' entry
curl -X POST http://127.0.0.1:8765/mcp/call \
  -H "Content-Type: application/json" \
  -d '{"method": "resources/read", "params": {"uri": "kprun://github"}}'

# Kill the bridge
kill $MCP_PID
```

---

## Cleanup

### Remove test vault and keychain entries

```bash
# Unset environment variables
unset KPRUN_DB KPRUN_KEYFILE

# Linux / macOS
rm -rf "$HOME/.kprun-test"
rm -f /tmp/test-*.kdbx

# Windows PowerShell
Remove-Item Env:KPRUN_DB -ErrorAction SilentlyContinue
Remove-Item Env:KPRUN_KEYFILE -ErrorAction SilentlyContinue
Remove-Item -Path "$env:USERPROFILE\.kprun-test" -Recurse -Force

# Clean up OS keychain manually or via:
# - macOS: Keychain Access.app → delete entry
# - Windows: Settings → Credential Manager → Windows Credentials → remove
# - Linux: depends on keyring backend (systemd user-dbus, gnome-keyring, etc.)
```

---

## Checklist for Release Testing

Use this before tagging a new version:

- [ ] `kprun init --quick` creates vault, stores password, prints it
- [ ] `kprun reveal-master` retrieves stored password
- [ ] `kprun deinit --delete-vault` removes vault and keychain entry
- [ ] `kprun set <entry> KEY=VALUE` stores custom fields
- [ ] `kprun run <entry> -- <cmd>` injects env vars into child process
- [ ] Parent shell does NOT inherit injected env vars
- [ ] `kprun doctor` reports health of vault and keychain
- [ ] Audit log records entry names and key names (not values)
- [ ] Windows: Credential Manager shows keychain entries
- [ ] macOS: Keychain.app shows keychain entries
- [ ] Linux: keyring backend works or falls back to prompt
- [ ] Cross-platform: binary for Linux, macOS, Windows tested on actual hardware

---

## Debugging Tips

### Enable debug output

```bash
RUST_LOG=debug kprun init --quick
RUST_LOG=debug kprun run github -- echo test
```

### Inspect vault file (KeePassXC)

```bash
# Open test vault in KeePassXC GUI
kprun init --quick
open -a KeePassXC "$KPRUN_DB"
# (Enter the master password printed by kprun init --quick)
```

### Check audit log

```bash
cat ~/.kprun/access.log
# Each line is JSON: {"timestamp": "...", "entry": "github", "keys": ["GITHUB_TOKEN", "GITHUB_USER"], ...}
# Never contains values
```

### Reset test environment

```bash
kprun deinit --delete-vault
rm -rf ~/.kprun-test
kprun doctor
# → Should report: vault not found
```

---

## Reporting Test Results

When submitting a test report:

1. **Platform**: OS, Arch, Rust version
2. **Test case**: Which feature/workflow tested
3. **Expected behavior**: What should happen
4. **Actual behavior**: What happened
5. **Audit log snippet**: Relevant lines from `~/.kprun/access.log`
6. **Steps to reproduce**: Exact commands run

Example:

```
Platform: Windows 11 x86_64, Rust 1.88.0
Test: init --quick --force
Expected: New vault created, old keychain entry replaced
Actual: ✓ Works as expected
Audit log: {"timestamp": "2026-07-12T...", "entry": "init", "keys": [...]}
```
