use clap::Parser;

#[derive(Parser, Debug)]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub struct Args {
    #[arg(long, env)]
    pub mpc_node_url: String,
    #[arg(long, env)]
    pub mpc_node_p2p_key: String,
    #[arg(long, env)]
    pub mpc_contract_name: String,
    #[arg(long, env)]
    pub near_network: String,
}

pub enum Command {
    GenerateKeys(GenerateKeysArgs),
    Register(RegisterArgs),
    GetKeyshares(GetKeysharesArgs),
    PutKeyshares(PutKeysharesArgs),
}

pub struct GenerateKeysArgs {}

pub struct RegisterArgs {}

pub struct GetKeysharesArgs {}

pub struct PutKeysharesArgs {}
