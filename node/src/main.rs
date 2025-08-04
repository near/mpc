use clap::Parser;
use std::sync::LazyLock;
use tracing::init_logging;

mod assets;
#[cfg(test)]
mod async_testing;
mod background;
mod cli;
mod config;
mod coordinator;
mod db;
mod indexer;
mod key_events;
mod keyshare;
mod metrics;
mod mpc_client;
mod network;
mod p2p;
mod primitives;
mod protocol;
mod protocol_version;
mod providers;
mod runtime;
mod sign_request;
pub mod signing;
mod tee;
#[cfg(test)]
mod tests;
mod tracing;
mod tracking;
mod web;

static MPC_VERSION: &str = env!("MPC_VERSION");
static MPC_BUILD: &str = env!("MPC_BUILD");
static MPC_COMMIT: &str = env!("MPC_COMMIT");
static RUSTC_VERSION: &str = env!("MPC_RUSTC_VERSION");



pub static MPC_VERSION_STRING: LazyLock<String> = LazyLock::new(|| {
    format!(
        "mpc-node {}\n(release {}) (build {}) (commit {}) (rustc {})",
        MPC_VERSION,
        MPC_VERSION,
        MPC_BUILD,
        MPC_COMMIT,
        RUSTC_VERSION,
    )
});



fn main() -> anyhow::Result<()> {
    init_logging();
    
    // Initialize build info metric
    metrics::init_build_info_metric();
    
    // Handle version flags before parsing CLI
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && (args[1] == "--version" || args[1] == "-V") {
        println!("{}", *MPC_VERSION_STRING);
        return Ok(());
    }
    
    // Parse CLI arguments
    let cli = cli::Cli::parse();
    futures::executor::block_on(cli.run())
}



