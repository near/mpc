use backup_cli::backup::run_command;
use backup_cli::cli;
use clap::Parser as _;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;

#[tokio::main]
async fn main() {
    // Without a default directive an unset `RUST_LOG` would admit `error` only, silencing
    // the backup service.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
    let args = cli::Args::parse();
    run_command(args).await;
}
