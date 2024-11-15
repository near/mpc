use clap::Parser;
use tracing::init_logging;

mod cli;
pub mod config;
mod indexer;
pub mod key_generation;
mod mpc_client;
pub mod network;
pub mod p2p;
pub mod primitives;
mod tracing;
pub mod tracking;
pub mod triple;
mod web;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();
    let cli = cli::Cli::parse();
    cli.run().await
}
