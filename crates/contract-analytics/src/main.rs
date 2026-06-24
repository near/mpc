use anyhow::Result;
use clap::Parser;
use contract_analytics::{
    client::Client,
    network::{Network, resolve},
    render, report,
};
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
    let client = Client::new(&endpoint.rpc_url, endpoint.contract_id);
    let snapshot = report::collect(&client).await?;
    if cli.pretty_print {
        render::table(&snapshot)?;
    } else {
        render::json(&snapshot)?;
    }
    Ok(())
}
