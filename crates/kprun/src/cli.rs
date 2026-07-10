use clap::{Parser, Subcommand, ValueEnum};

use crate::mcp_bridge::Transport;

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
        /// Read KEY=value lines from stdin (avoids argv / shell-history exposure)
        #[arg(long, conflicts_with = "pairs")]
        stdin: bool,
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
    /// Bridge stdio JSON-RPC to a remote HTTP MCP server, injecting vault-backed auth headers
    Mcp {
        /// Vault entry whose custom fields fill {{FIELD}} templates
        #[arg(short = 'e', long)]
        entry: String,
        /// Extra header as 'Name: template' with {{FIELD}} substitution (repeatable)
        #[arg(long = "header")]
        headers: Vec<String>,
        /// Shorthand for --header "Authorization: Bearer {{FIELD}}"
        #[arg(long, value_name = "FIELD")]
        bearer: Option<String>,
        /// Remote transport (auto follows MCP spec backwards-compatibility detection)
        #[arg(long, value_enum, default_value_t = Transport::Auto)]
        transport: Transport,
        /// Timeout in seconds for connect and response headers (response bodies and SSE streams are exempt)
        #[arg(long, default_value_t = 30)]
        timeout: u64,
        /// Allow vault-backed credentials over plaintext http:// to a non-loopback host
        #[arg(long)]
        allow_insecure_http: bool,
        /// Remote MCP endpoint URL (supports {{FIELD}} substitution)
        url: String,
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn mcp_parses_all_flags() {
        let cli = Cli::try_parse_from([
            "kprun",
            "mcp",
            "-e",
            "github",
            "--bearer",
            "TOKEN",
            "--header",
            "X-Org: {{ORG}}",
            "--transport",
            "streamable-http",
            "--timeout",
            "10",
            "https://api.example.com/mcp/",
        ])
        .unwrap();
        match cli.command {
            Commands::Mcp {
                entry,
                headers,
                bearer,
                transport,
                timeout,
                allow_insecure_http,
                url,
            } => {
                assert_eq!(entry, "github");
                assert_eq!(headers, vec!["X-Org: {{ORG}}".to_string()]);
                assert_eq!(bearer.as_deref(), Some("TOKEN"));
                assert!(matches!(transport, Transport::Streamable));
                assert_eq!(timeout, 10);
                assert!(!allow_insecure_http);
                assert_eq!(url, "https://api.example.com/mcp/");
            }
            _ => panic!("expected Commands::Mcp"),
        }
    }

    #[test]
    fn mcp_parses_allow_insecure_http() {
        let cli = Cli::try_parse_from([
            "kprun",
            "mcp",
            "-e",
            "gh",
            "--allow-insecure-http",
            "http://intranet.local/mcp/",
        ])
        .unwrap();
        match cli.command {
            Commands::Mcp {
                allow_insecure_http,
                ..
            } => assert!(allow_insecure_http),
            _ => panic!("expected Commands::Mcp"),
        }
    }

    #[test]
    fn mcp_defaults_transport_auto_timeout_30() {
        let cli = Cli::try_parse_from(["kprun", "mcp", "-e", "gh", "https://x.test/"]).unwrap();
        match cli.command {
            Commands::Mcp {
                transport, timeout, ..
            } => {
                assert!(matches!(transport, Transport::Auto));
                assert_eq!(timeout, 30);
            }
            _ => panic!("expected Commands::Mcp"),
        }
    }

    #[test]
    fn mcp_requires_entry_and_url() {
        assert!(Cli::try_parse_from(["kprun", "mcp", "https://x.test/"]).is_err());
        assert!(Cli::try_parse_from(["kprun", "mcp", "-e", "gh"]).is_err());
    }

    #[test]
    fn set_stdin_conflicts_with_pairs() {
        assert!(Cli::try_parse_from(["kprun", "set", "e", "A=1", "--stdin"]).is_err());
        assert!(Cli::try_parse_from(["kprun", "set", "e", "--stdin"]).is_ok());
        assert!(Cli::try_parse_from(["kprun", "set", "e", "A=1"]).is_ok());
    }
}
