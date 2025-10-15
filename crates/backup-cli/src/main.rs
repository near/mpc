use backup_cli::backup::run_command;
use backup_cli::cli;
use clap::Parser as _;

#[tokio::main]
async fn main() {
    let args = cli::Args::parse();
    run_command(args).await;
}
