mod account;
mod cli;
mod constants;
mod contracts;
mod devnet;
mod funding;
mod loadtest;
mod mpc;
mod queries;
mod terraform;
mod tx;

pub mod rpc;
pub mod types;

pub use mpc::read_contract_state;

/// Entry point for the `mpc-devnet` binary.
pub async fn run() {
    use clap::Parser;
    cli::Cli::parse().run().await;
}
