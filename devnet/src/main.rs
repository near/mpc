use clap::Parser;
use cli::Cli;

mod account;
mod cli;
mod constants;
mod devnet;
mod funding;
mod loadtest;
mod rpc;
mod types;
mod mpc;
mod terraform;

#[tokio::main]
async fn main() {
    Cli::parse().run().await;
}
