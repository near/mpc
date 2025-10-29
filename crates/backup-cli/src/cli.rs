use near_primitives::types::AccountId;
use url::Url;

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

#[derive(Clone, Debug)]
pub enum Network {
    Testnet,
    Mainnet,
    Sandbox,
    Localnet(Url),
}

impl std::str::FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "testnet" => Ok(Network::Testnet),
            "mainnet" => Ok(Network::Mainnet),
            "sandbox" => Ok(Network::Sandbox),
            s if s.starts_with("localnet ") => {
                let url_str = s.strip_prefix("localnet ").unwrap();
                Url::parse(url_str)
                    .map(Network::Localnet)
                    .map_err(|e| format!("Invalid URL for localnet: {}", e))
            }
            _ => Err(format!(
                "Invalid network: '{}'. Must be one of: testnet, mainnet, sandbox, or 'localnet <url>'",
                s
            )),
        }
    }
}

#[derive(clap::Args, Debug)]
pub struct RegisterArgs {
    /// MPC contract account ID
    #[arg(long, env)]
    pub mpc_contract_account_id: AccountId,
    
    /// Network to connect to: testnet, mainnet, sandbox, or "localnet <url>"
    #[arg(long, env)]
    pub near_network: Network,
    
    /// Named account that will sign the registration transaction.
    /// Note: The public key derived from near_signer_key (in secrets file) must be added
    /// as an access key to this account before calling this command.
    #[arg(long, env)]
    pub signer_account_id: AccountId,
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
