mod cli;
mod commands;
mod mcp_bridge;
mod spawn;
mod ui;

use clap::Parser;

use cli::Cli;

fn main() {
    let cli = Cli::parse();
    commands::dispatch(cli.command);
}
