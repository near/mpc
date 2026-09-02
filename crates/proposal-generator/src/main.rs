//! Prints the borsh-encoded base64 argument foreign chain whitelist proposal.
//!
//! Run:
//!   cargo run -p proposal-generator -- crates/proposal-generator/proposals/testnet-rpc-whitelist.toml

use anyhow::Context as _;
use base64::Engine as _;
use clap::Parser;
use proposal_generator::{ProposalConfig, build_payload};
use sha2::{Digest as _, Sha256};
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "Builds the base64 payload for whitelisting proposal from a TOML config")]
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
    let payload = build_payload(config)?;

    println!(
        "{}",
        base64::engine::general_purpose::STANDARD.encode(&payload)
    );
    println!("sha256: {}", hex::encode(Sha256::digest(&payload)));
    Ok(())
}
