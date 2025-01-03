use clap::Parser;
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
    if let Ok(Some(mut start_response)) = cli.run() {
        if let Some(indexer_handle) = start_response.indexer_handle {
            indexer_handle
                .join()
                .map_err(|_| anyhow::anyhow!("Indexer thread panicked!"))?;
        }
        let ret = if let Some(mpc_handle) = start_response.mpc_handle.handle.take() {
            mpc_handle
                .join()
                .map_err(|_| anyhow::anyhow!("mpc thread panicked!"))?
        } else {
            Err(anyhow::anyhow!("expected thread handle"))?
        };
        ret?
    }
    Ok(())
}
