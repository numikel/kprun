use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "kprun",
    version,
    about = "Inject KeePass secrets into a child process"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create or attach a KeePass vault and unlock it
    Init {
        #[arg(long)]
        db: Option<String>,
        #[arg(long)]
        no_store: bool,
        #[arg(long)]
        keyfile: Option<String>,
    },
    /// Inject vault secrets into a child process
    Run {
        /// Inject only vault secrets and a minimal safe environment, dropping the parent environment.
        #[arg(long)]
        clean_env: bool,
        #[arg(num_args = 1.., value_terminator = "--", required = true)]
        entries: Vec<String>,
        #[arg(
            num_args = 1..,
            trailing_var_arg = true,
            allow_hyphen_values = true,
            required = true
        )]
        command: Vec<String>,
    },
    /// List vault entries and their secret key names
    List {
        #[arg(long)]
        json: bool,
    },
    /// Show custom fields for a vault entry
    Get {
        entry: String,
        #[arg(long)]
        keys: bool,
        #[arg(long)]
        reveal: bool,
    },
    /// Set or update secret fields on a vault entry
    Set { entry: String, pairs: Vec<String> },
    /// Remove secret fields from a vault entry
    Unset { entry: String, keys: Vec<String> },
    /// Delete a vault entry
    Delete { entry: String },
    /// Export vault entries to JSON or dotenv
    Export {
        #[arg(long, value_enum, default_value_t = ExportFormat::Json)]
        format: ExportFormat,
        #[arg(long)]
        stdout: bool,
        #[arg(long)]
        reveal: bool,
        /// Write to this path instead of the default kprun-export.* in the current directory.
        #[arg(long)]
        output: Option<String>,
    },
    /// Import entries from JSON or dotenv into the vault
    Import {
        file: String,
        #[arg(long)]
        merge: bool,
    },
    /// Diagnose configuration and print an MCP config snippet
    Doctor {
        #[arg(long)]
        mcp: Option<String>,
    },
    /// Remove the stored master password for the current vault from the OS keychain.
    Deinit,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ExportFormat {
    Json,
    Dotenv,
}
