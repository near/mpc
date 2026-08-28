//! Prints the borsh-encoded base64 argument for `vote_update_foreign_chain_providers`
//! built from a TOML proposal config (see the crate docs for the schema).
//!
//! Run:
//!   cargo run -p proposal-generator -- crates/proposal-generator/proposals/testnet-rpc-whitelist.toml

use anyhow::Context as _;
use base64::Engine as _;
use clap::Parser;
use proposal_generator::{ProposalConfig, build_batch};
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    /// Path to the TOML proposal config.
    config: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let raw = std::fs::read_to_string(&args.config)
        .with_context(|| format!("reading {}", args.config.display()))?;
    let config: ProposalConfig = toml::from_str(&raw).context("parsing config")?;
    let batch = build_batch(config)?;

    let bytes = borsh::to_vec(&batch).context("borsh serialization")?;
    println!(
        "{}",
        base64::engine::general_purpose::STANDARD.encode(&bytes)
    );
    Ok(())
}
