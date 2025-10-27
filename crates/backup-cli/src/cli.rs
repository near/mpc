#[derive(clap::Parser, Debug)]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub struct Args {
    #[arg(long, env("BACKUP_HOME_DIR"))]
    pub home_dir: String,
    #[clap(subcommand)]
    pub command: Command,
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

#[derive(clap::ValueEnum, Clone, Debug)]
#[clap(rename_all = "lowercase")]
pub enum Network {
    Testnet,
    Mainnet,
    Sandbox,
    Localnet,
}

#[derive(clap::Args, Debug)]
pub struct RegisterArgs {
    #[arg(long, env)]
    pub mpc_contract_name: String,
    #[arg(long, env)]
    pub near_network: Network,
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
