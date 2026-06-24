use kprun_core::config::Config;
use kprun_core::unlock::{
    build_database_key, keystore_has_master, unlock_with_fallback, UnlockContext,
};
use kprun_core::vault::{open_vault, OpenMode};
use kprun_core::Result;
use serde_json::json;

pub fn execute(mcp: Option<String>) -> i32 {
    match run(mcp) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn run(mcp: Option<String>) -> Result<()> {
    if let Some(entry) = mcp {
        print_mcp_fragment(&entry)?;
        return Ok(());
    }

    print_diagnostics()?;
    Ok(())
}

fn print_diagnostics() -> Result<()> {
    let cfg = Config::from_env();
    let ctx = UnlockContext {
        keyfile: cfg.keyfile.clone(),
        db_path: cfg.db_path.clone(),
    };

    if cfg.db_path.exists() {
        println!("vault: ok ({})", cfg.db_path.display());
    } else {
        let name = cfg
            .db_path
            .file_name()
            .map(|f| f.to_string_lossy())
            .unwrap_or_else(|| cfg.db_path.to_string_lossy());
        println!("vault: missing ({name})");
        return Err(kprun_core::KprunError::Other(
            "vault database not found".into(),
        ));
    }

    let master = unlock_with_fallback(&ctx)?;
    let db_key = build_database_key(&ctx, &master)?;
    let _vault = open_vault(&cfg.db_path, db_key, OpenMode::ReadOnly)?;
    println!("unlock: ok");

    let keystore = if keystore_has_master(&cfg.db_path) {
        "present"
    } else {
        "absent"
    };
    println!("keystore: {keystore}");

    match &cfg.keyfile {
        Some(path) => println!("keyfile: configured ({})", path.display()),
        None => println!("keyfile: not configured"),
    }

    let binary = std::env::current_exe()?;
    println!("binary: {}", binary.display());

    Ok(())
}

fn print_mcp_fragment(entry: &str) -> Result<()> {
    if entry == "github" {
        eprintln!(
            "NOTE: npx auto-install without a lockfile is a supply-chain risk; pin the MCP server version in production."
        );
    }
    let command = mcp_command()?;
    let args = mcp_args(entry);
    let fragment = json!({
        "command": command,
        "args": args,
    });
    println!("{}", serde_json::to_string_pretty(&fragment)?);
    Ok(())
}

fn mcp_command() -> Result<String> {
    let exe = std::env::current_exe()?;
    if cfg!(windows) {
        return Ok(exe.display().to_string());
    }
    if which::which("kprun").is_ok() {
        return Ok("kprun".into());
    }
    Ok(exe.display().to_string())
}

fn mcp_args(entry: &str) -> Vec<String> {
    match entry {
        "github" => vec![
            "run".into(),
            "github".into(),
            "--".into(),
            "npx".into(),
            "-y".into(),
            "@modelcontextprotocol/server-github@2025.4.8".into(),
        ],
        other => vec!["run".into(), other.to_string(), "--".into()],
    }
}
