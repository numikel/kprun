//! KeePassXC compatibility: verifies kprun can open a database created in KeePassXC.
//!
//! ## Manual fixture workflow
//!
//! 1. In KeePassXC, create `tests/fixtures/keepassxc.kdbx` (gitignored; not committed).
//! 2. Add an entry with title `fixture` and a custom attribute `FIXTURE_KEY` (any non-empty value).
//! 3. Export or save the database. Note the master password.
//! 4. Run the test locally:
//!
//! ```bash
//! export KPRUN_KEEPASSXC_FIXTURE=1
//! export KPRUN_TEST_MASTER='your-master-password'
//! cargo test reads_keepassxc_fixture -- --ignored
//! ```
//!
//! CI skips this test by default (`#[ignore]`). Set `KPRUN_KEEPASSXC_FIXTURE` when running
//! with `--ignored` in pipelines that provide the fixture.

mod common;

use std::path::PathBuf;

use kprun_core::unlock::{build_database_key, UnlockContext};
use kprun_core::vault::{open_vault, OpenMode};

#[test]
#[ignore = "requires tests/fixtures/keepassxc.kdbx created in KeePassXC"]
fn reads_keepassxc_fixture() {
    if !common::keepassxc_fixture_enabled() {
        panic!(
            "set KPRUN_KEEPASSXC_FIXTURE=1 to run this test (fixture: {})",
            common::keepassxc_fixture_path().display()
        );
    }

    let path = common::keepassxc_fixture_path();
    assert!(
        path.exists(),
        "fixture missing at {}; create it in KeePassXC first",
        path.display()
    );

    let master = common::keepassxc_fixture_password().expect(
        "set KPRUN_TEST_MASTER or KPRUN_KEEPASSXC_PASSWORD for the fixture master password",
    );

    let ctx = UnlockContext {
        keyfile: std::env::var_os("KPRUN_KEYFILE").map(PathBuf::from),
        db_path: path.clone(),
    };
    let key = build_database_key(&ctx, &master).expect("failed to build database key");
    let vault =
        open_vault(&path, key, OpenMode::ReadOnly).expect("failed to open KeePassXC fixture");

    let id = vault
        .find_entry_by_title("fixture")
        .expect("entry 'fixture' not found in KeePassXC database");
    let values = vault.entry_custom_values(id);

    let value = values
        .get("FIXTURE_KEY")
        .expect("custom attribute FIXTURE_KEY not found on entry 'fixture'");
    assert!(!value.is_empty(), "FIXTURE_KEY must be a non-empty string");
}
