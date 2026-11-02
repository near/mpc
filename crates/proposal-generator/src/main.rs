//! Prints the `vote_update_foreign_chain_providers` argument for a whitelist proposal.
//!
//! Run:
//!   cargo run -p proposal-generator -- crates/proposal-generator/proposals/testnet-rpc-whitelist.toml

use anyhow::Context as _;
use clap::Parser;
use proposal_generator::{ProposalConfig, build_payload};
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "Builds the call argument for a whitelisting proposal from a TOML config")]
struct Args {
    /// Path to the TOML proposal config.
    config: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let raw = std::fs::read_to_string(&args.config)
        .with_context(|| format!("reading {}", args.config.display()))?;
    let config: ProposalConfig =
        toml::from_str(&raw).with_context(|| format!("parsing {}", args.config.display()))?;
    println!("{}", build_payload(config)?);
    Ok(())
}
