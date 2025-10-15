use clap::Parser;

#[derive(Parser, Debug)]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub struct Args {
    #[arg(long, env)]
    pub mpc_node_url: String,
    #[arg(long, env)]
    pub mpc_contract_name: String,
    #[arg(long, env)]
    pub near_network: String,
}
