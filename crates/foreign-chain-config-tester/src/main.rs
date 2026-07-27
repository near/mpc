//! Foreign-chain RPC config tester: probe every configured provider so operators can
//! verify their config without running the node. Each provider is checked by chain
//! identity plus a dynamically discovered transaction — see the README.

mod config;
mod report;

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use foreign_chain_health_check::check_all_providers;

/// Verify a node's foreign-chain RPC provider configuration.
///
/// Probes every configured provider by chain identity and a recent transaction.
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
    let identities = config::detect_expected_identities(&contents, &args.config)?;

    let results = check_all_providers(&foreign_chains, &identities).await;
    print!("{}", report::render(&results));

    Ok(if report::any_failed(&results) {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}
