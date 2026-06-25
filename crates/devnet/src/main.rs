use clap::Parser;
use mpc_devnet::cli::Cli;

#[tokio::main]
async fn main() {
    Cli::parse().run().await;
}
