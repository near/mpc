//! Foreign-chain RPC config tester: probe every configured provider with a fixed
//! golden request so operators can verify their config without running the node.
//! Sui is probed differently — see the README.

mod config;
mod report;

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use foreign_chain_health_check::{Network, check_all_providers};

/// Verify a node's foreign-chain RPC provider configuration.
///
/// Probes every configured provider with a fixed golden request.
#[derive(Parser)]
#[command(about, long_about = None)]
struct Args {
    /// Path to the config file to check (`.yaml`, `.yml`, or `.toml`).
    #[arg(long)]
    config: PathBuf,

    /// Network the reference transactions belong to. Auto-detected from
    /// the config (`chain_id` / `mpc_contract_id`) when omitted.
    #[arg(long, value_enum)]
    network: Option<Network>,
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    let args = Args::parse();
    let contents = fs::read_to_string(&args.config)
        .with_context(|| format!("failed to read {}", args.config.display()))?;
    let foreign_chains = config::parse_foreign_chains(&contents, &args.config)?;
    let network = match args.network {
        Some(network) => network,
        None => config::detect_network(&contents, &args.config)?.ok_or_else(|| {
            anyhow::anyhow!(
                "could not determine network from config (no chain_id / mpc_contract_id found); \
                 pass --network mainnet|testnet"
            )
        })?,
    };

    let results = check_all_providers(&foreign_chains, network).await;
    print!("{}", report::render(&results));

    Ok(if report::any_failed(&results) {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}
