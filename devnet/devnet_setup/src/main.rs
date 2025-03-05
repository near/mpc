use clap::Parser;
use cli::Cli;

mod account;
mod cli;
mod rpc;
mod types;

#[tokio::main]
async fn main() {
    Cli::parse().run().await;
}
