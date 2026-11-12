//! Foreign chain RPC config tester: runs the node's network fingerprint probe over every provider
//! in a config file, so operators can verify their `foreign_chains` section without running the
//! node.

mod config;
mod report;

#[expect(
    clippy::allow_attributes,
    reason = "built.rs files are included verbatim and use allow()"
)]
mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::LazyLock;

use anyhow::Context;
use clap::Parser;
use foreign_chain_health_check::probe::probe_all_providers;
use foreign_chain_rpc_factory::inspectors::InspectorFactory;
use mpc_node_config::foreign_chains::resolve_with_embedded;

static VERSION: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{} (commit {}) ({})",
        built_info::PKG_VERSION,
        built_info::GIT_COMMIT_HASH_SHORT.unwrap_or("unknown"),
        built_info::RUSTC_VERSION,
    )
});

/// Verify a node's foreign chain RPC provider configuration.
///
/// Asks every configured provider which network it serves and compares the answer with the
/// chain's `expected_network_fingerprint`, exactly as the node does after startup.
#[derive(Parser)]
#[command(about, long_about = None, version = VERSION.as_str())]
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
    let resolved = resolve_with_embedded(&foreign_chains)
        .context("the node would refuse this foreign_chains config")?;
    for diagnostic in resolved.diagnostics.iter().filter(|d| d.is_warning()) {
        eprintln!("warning: {diagnostic}");
    }
    let foreign_chains = resolved.config;

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
