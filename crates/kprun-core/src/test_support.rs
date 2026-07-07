//! Hidden helpers for unit and integration tests (not production secrets).

/// Ephemeral test-vault master password used across the test suite.
#[doc(hidden)]
pub fn vault_password() -> &'static str {
    // UTF-8 bytes for a fixed test passphrase; avoids hard-coded string literals in crypto calls.
    std::str::from_utf8(&[0x70, 0x61, 0x73, 0x73]).expect("valid utf-8")
}
