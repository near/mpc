use crate::config::ConfigFile;
use clap::Parser;
use std::path::PathBuf;
use tracing::init_logging;
mod assets;
mod background;
mod cli;
mod config;
mod db;
mod hkdf;
mod indexer;
mod key_generation;
mod metrics;
mod mpc_client;
mod network;
mod p2p;
mod primitives;
mod protocol;
mod sign;
mod sign_request;
#[cfg(test)]
mod tests;
mod tracing;
mod tracking;
mod triple;
mod web;
#[cfg(test)]
mod web_test;

fn main() -> anyhow::Result<()> {
    init_logging();
    let cli = cli::Cli::parse();
    let runtime = match &cli {
        cli::Cli::Start { home_dir, .. } => {
            let n_threads = ConfigFile::from_file(&PathBuf::from(home_dir).join("config.yaml"))
                .unwrap()
                .cores
                .unwrap_or(24);
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(n_threads)
                .build()?
        }
        _ => tokio::runtime::Builder::new_multi_thread().build()?,
    };
    let mpc_handle = std::thread::spawn(move || runtime.block_on(async { cli.run().await }));
    mpc_handle.join().unwrap()
}
