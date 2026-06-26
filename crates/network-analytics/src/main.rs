use std::sync::Arc;

use clap::{Args, Parser, Subcommand};
use mpc_devnet::rpc::NearRpcClients;
use mpc_devnet::types::RpcConfig;
use near_primitives::types::AccountId;
use network_analytics::{
    network::{Network, resolve},
    render, report,
};

#[derive(Parser, Debug)]
#[command(about = "Analytics tooling for the MPC contract")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Provides a concise overview of the current network state
    Overview(OverviewArgs),
}

#[derive(Args, Debug)]
struct OverviewArgs {
    #[arg(long, value_enum, default_value_t = Network::Mainnet)]
    network: Network,
    #[arg(long)]
    rpc_url: Option<String>,
    #[arg(long)]
    contract: Option<AccountId>,
    #[arg(long)]
    pretty_print: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Overview(args) => run_attestations(args).await,
    }
}

async fn run_attestations(args: OverviewArgs) -> anyhow::Result<()> {
    let endpoint = resolve(args.network, args.rpc_url, args.contract)?;
    let rpc = Arc::new(
        NearRpcClients::new(vec![RpcConfig {
            url: endpoint.rpc_url,
            rate_limit: 20,
            max_concurrency: 20,
            api_key: None,
        }])
        .await,
    );
    let snapshot = report::collect(&rpc, &endpoint.contract_id).await?;
    if args.pretty_print {
        render::table(&snapshot)?;
    } else {
        render::json(&snapshot)?;
    }
    Ok(())
}
