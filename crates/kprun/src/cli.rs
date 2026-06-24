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
        /// Path to the KeePass database (default: KPRUN_DB or ~/.kprun/secrets.kdbx)
        #[arg(long)]
        db: Option<String>,
        /// Do not store the master password in the OS keychain
        #[arg(long)]
        no_store: bool,
        /// Path to a key file; created if missing (default: KPRUN_KEYFILE)
        #[arg(long)]
        keyfile: Option<String>,
    },
    /// Inject vault secrets into a child process
    Run {
        /// Inject only vault secrets and a minimal safe environment, dropping the parent environment
        #[arg(long)]
        clean_env: bool,
        /// Vault entry titles whose secrets to inject
        #[arg(num_args = 1.., value_terminator = "--", required = true)]
        entries: Vec<String>,
        /// Command to run after `--` (receives injected environment variables)
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
        /// Output entry titles and key names as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show custom fields for a vault entry
    Get {
        /// Vault entry title
        entry: String,
        /// Print only key names, one per line
        #[arg(long)]
        keys: bool,
        /// Print KEY=value lines including secret values (stderr warning and audit log)
        #[arg(long)]
        reveal: bool,
    },
    /// Set or update secret fields on a vault entry
    Set {
        /// Vault entry title (created if missing)
        entry: String,
        /// KEY=value pairs to set on the entry
        pairs: Vec<String>,
    },
    /// Remove secret fields from a vault entry
    Unset {
        /// Vault entry title
        entry: String,
        /// Custom field names to remove
        keys: Vec<String>,
    },
    /// Delete a vault entry
    Delete {
        /// Vault entry title to delete
        entry: String,
    },
    /// Export vault entries to JSON or dotenv
    Export {
        /// Output format: JSON structure or kprun dotenv blocks
        #[arg(long, value_enum, default_value_t = ExportFormat::Json)]
        format: ExportFormat,
        /// Write export to stdout instead of a file (skips banner; suitable for piping)
        #[arg(long)]
        stdout: bool,
        /// Include secret values in the export (default: key names only)
        #[arg(long)]
        reveal: bool,
        /// Write to this path instead of the default kprun-export.* in the current directory
        #[arg(long)]
        output: Option<String>,
    },
    /// Import entries from JSON or dotenv into the vault
    Import {
        /// JSON or kprun dotenv file to import
        file: String,
        /// Add or update imported entries without deleting others in the vault
        #[arg(long)]
        merge: bool,
    },
    /// Diagnose configuration and print an MCP config snippet
    Doctor {
        /// Print an MCP config JSON snippet for this vault entry instead of diagnostics
        #[arg(long)]
        mcp: Option<String>,
        /// MCP server command to append after `run <entry> --` (place after `--` on the CLI)
        #[arg(
            num_args = 0..,
            trailing_var_arg = true,
            allow_hyphen_values = true,
            requires = "mcp"
        )]
        command: Vec<String>,
    },
    /// Remove the stored master password for the current vault from the OS keychain
    Deinit,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ExportFormat {
    /// JSON object with an `entries` array
    Json,
    /// kprun dotenv blocks (`# entry` headers and KEY=value lines)
    Dotenv,
}
