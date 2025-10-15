#[derive(clap::Parser, Debug)]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    GenerateKeys(GenerateKeysArgs),
    Register(RegisterArgs),
    GetKeyshares(GetKeysharesArgs),
    PutKeyshares(PutKeysharesArgs),
}

#[derive(clap::Args, Debug)]
pub struct GenerateKeysArgs {}

#[derive(clap::Args, Debug)]
pub struct RegisterArgs {
    #[arg(long, env)]
    pub mpc_contract_name: String,
    #[arg(long, env)]
    pub near_network: String,
}

#[derive(clap::Args, Debug)]
pub struct GetKeysharesArgs {
    #[arg(long, env)]
    pub mpc_node_url: String,
    #[arg(long, env)]
    pub mpc_node_p2p_key: String,
}

#[derive(clap::Args, Debug)]
pub struct PutKeysharesArgs {
    #[arg(long, env)]
    pub mpc_node_url: String,
    #[arg(long, env)]
    pub mpc_node_p2p_key: String,
}
