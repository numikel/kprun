use std::process;

use kprun_core::config::Config;
use kprun_core::unlock::{build_database_key, unlock_with_fallback, UnlockContext};
use kprun_core::vault::{open_vault, OpenMode, Vault};
use kprun_core::Result;

use crate::cli::{Commands, ExportFormat};

mod delete;
mod get;
mod init;
mod list;
mod run;
mod set;
mod unset;

pub fn dispatch(command: Commands) {
    match command {
        Commands::Init {
            db,
            no_store,
            keyfile,
        } => std::process::exit(init::execute(db, no_store, keyfile)),
        Commands::Run { entries, command } => std::process::exit(run::execute(entries, command)),
        Commands::List { json } => std::process::exit(list::execute(json)),
        Commands::Get {
            entry,
            keys,
            reveal,
        } => std::process::exit(get::execute(entry, keys, reveal)),
        Commands::Set { entry, pairs } => std::process::exit(set::execute(entry, pairs)),
        Commands::Unset { entry, keys } => std::process::exit(unset::execute(entry, keys)),
        Commands::Delete { entry } => std::process::exit(delete::execute(entry)),
        Commands::Export {
            format,
            stdout,
            reveal,
        } => export(format, stdout, reveal),
        Commands::Import { file, merge } => import(file, merge),
        Commands::Doctor { mcp } => doctor(mcp),
    }
}

fn unlock_vault(mode: OpenMode) -> Result<(Config, UnlockContext, Vault)> {
    let cfg = Config::from_env();
    let ctx = UnlockContext {
        keyfile: cfg.keyfile.clone(),
    };
    let master = unlock_with_fallback(&ctx)?;
    let db_key = build_database_key(&ctx, &master)?;
    let vault = open_vault(&cfg.db_path, db_key, mode)?;
    Ok((cfg, ctx, vault))
}

fn unimplemented(name: &str) -> ! {
    eprintln!("unimplemented: {name}");
    process::exit(1);
}

fn export(_format: ExportFormat, _stdout: bool, _reveal: bool) {
    unimplemented("export");
}

fn import(_file: String, _merge: bool) {
    unimplemented("import");
}

fn doctor(_mcp: Option<String>) {
    unimplemented("doctor");
}
