//! Shared helpers for kprun integration tests.

use std::path::PathBuf;

/// Path to the optional KeePassXC-created fixture (`tests/fixtures/keepassxc.kdbx`).
pub fn keepassxc_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/keepassxc.kdbx")
}

/// Whether the KeePassXC compatibility test should run (`KPRUN_KEEPASSXC_FIXTURE` set).
pub fn keepassxc_fixture_enabled() -> bool {
    std::env::var_os("KPRUN_KEEPASSXC_FIXTURE").is_some()
}

/// Master password for the KeePassXC fixture (`KPRUN_TEST_MASTER` or `KPRUN_KEEPASSXC_PASSWORD`).
pub fn keepassxc_fixture_password() -> Option<String> {
    std::env::var("KPRUN_TEST_MASTER")
        .ok()
        .or_else(|| std::env::var("KPRUN_KEEPASSXC_PASSWORD").ok())
}
