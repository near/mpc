//! Foreign chain RPC config tester: runs the node's network fingerprint probe over every provider
//! in a config file, so operators can verify their `foreign_chains` section without running the
//! node.

mod config;
mod report;

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use foreign_chain_health_check::probe::probe_all_providers;
use foreign_chain_rpc_factory::inspectors::InspectorFactory;

/// Verify a node's foreign chain RPC provider configuration.
///
/// Asks every configured provider which network it serves and compares the answer with the
/// chain's `expected_network_fingerprint`, exactly as the node does after startup.
#[derive(Parser)]
#[command(about, long_about = None)]
struct Args {
    /// Path to the config file to check (`.yaml`, `.yml`, or `.toml`).
    #[arg(long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    let args = Args::parse();
    let contents = fs::read_to_string(&args.config)
        .with_context(|| format!("failed to read {}", args.config.display()))?;
    let foreign_chains = config::parse_foreign_chains(&contents, &args.config)?;
    foreign_chains
        .validate()
        .context("the node would refuse this foreign_chains config")?;

    let report = probe_all_providers(&foreign_chains, &InspectorFactory).await;
    print!("{}", report::render(&foreign_chains, &report));

    Ok(
        if report::any_failed(&report) || foreign_chains.is_empty() {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        },
    )
}
