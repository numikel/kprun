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
    Init {
        #[arg(long)]
        db: Option<String>,
        #[arg(long)]
        no_store: bool,
        #[arg(long)]
        keyfile: Option<String>,
    },
    /// kprun run <entry>... -- <command> [args...]
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
    List {
        #[arg(long)]
        json: bool,
    },
    Get {
        entry: String,
        #[arg(long)]
        keys: bool,
        #[arg(long)]
        reveal: bool,
    },
    Set {
        entry: String,
        pairs: Vec<String>,
    },
    Unset {
        entry: String,
        keys: Vec<String>,
    },
    Delete {
        entry: String,
    },
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
    Import {
        file: String,
        #[arg(long)]
        merge: bool,
    },
    Doctor {
        #[arg(long)]
        mcp: Option<String>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ExportFormat {
    Json,
    Dotenv,
}
