use clap::Parser;
use tracing::init_logging;

mod cli;
mod config;
mod key_generation;
mod metrics;
mod mpc_client;
mod network;
mod p2p;
mod primitives;
mod protocol;
mod sign;
mod tracing;
mod tracking;
mod triple;
mod web;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();
    let cli = cli::Cli::parse();
    cli.run().await
}
