use clap::Parser;

#[derive(Parser)]
#[command(name = "kprun", version, about = "Local secrets injector for dev workflows")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Placeholder until commands land
    Version,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        None | Some(Commands::Version) => {
            println!("kprun {}", env!("CARGO_PKG_VERSION"));
        }
    }
}
