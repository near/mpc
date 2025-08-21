// TODO: remove this allow lint once `near_crypto` is removed
// from devnet crate.
// https://github.com/near/mpc/issues/915
#![allow(clippy::disallowed_types)]

use clap::Parser;
use cli::Cli;

mod account;
mod cli;
mod constants;
mod contracts;
mod devnet;
mod funding;
mod loadtest;
mod mpc;
mod queries;
mod rpc;
mod terraform;
mod tx;
mod types;

#[tokio::main]
async fn main() {
    Cli::parse().run().await;
}
