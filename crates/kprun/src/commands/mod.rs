use std::process;

use crate::cli::{Commands, ExportFormat};

mod init;

pub fn dispatch(command: Commands) {
    match command {
        Commands::Init {
            db,
            no_store,
            keyfile,
        } => std::process::exit(init::execute(db, no_store, keyfile)),
        Commands::Run { entries, command } => run(entries, command),
        Commands::List { json } => list(json),
        Commands::Get {
            entry,
            keys,
            reveal,
        } => get(entry, keys, reveal),
        Commands::Set { entry, pairs } => set(entry, pairs),
        Commands::Unset { entry, keys } => unset(entry, keys),
        Commands::Delete { entry } => delete(entry),
        Commands::Export {
            format,
            stdout,
            reveal,
        } => export(format, stdout, reveal),
        Commands::Import { file, merge } => import(file, merge),
        Commands::Doctor { mcp } => doctor(mcp),
    }
}

fn unimplemented(name: &str) -> ! {
    eprintln!("unimplemented: {name}");
    process::exit(1);
}

fn run(_entries: Vec<String>, _command: Vec<String>) {
    unimplemented("run");
}

fn list(_json: bool) {
    unimplemented("list");
}

fn get(_entry: String, _keys: bool, _reveal: bool) {
    unimplemented("get");
}

fn set(_entry: String, _pairs: Vec<String>) {
    unimplemented("set");
}

fn unset(_entry: String, _keys: Vec<String>) {
    unimplemented("unset");
}

fn delete(_entry: String) {
    unimplemented("delete");
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
