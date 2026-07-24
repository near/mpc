use backup_cli::backup::run_command;
use backup_cli::cli;
use clap::Parser as _;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let args = cli::Args::parse();
    run_command(args).await;
}
