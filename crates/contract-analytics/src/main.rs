use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use contract_analytics::{
    network::{Network, resolve},
    render, report,
};
use mpc_devnet::rpc::NearRpcClients;
use mpc_devnet::types::RpcConfig;
use near_primitives::types::AccountId;

#[derive(Parser, Debug)]
#[command(about = "Fetch attestation expiries for every TLS key in the MPC contract")]
struct Cli {
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
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let endpoint = resolve(cli.network, cli.rpc_url, cli.contract)?;
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
    if cli.pretty_print {
        render::table(&snapshot)?;
    } else {
        render::json(&snapshot)?;
    }
    Ok(())
}
