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

#[derive(Clone, Debug)]
pub struct NearSecretKeyString(pub String);

impl std::str::FromStr for NearSecretKeyString {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("ed25519:") {
            return Err(format!(
                "Invalid NEAR secret key format. Must start with 'ed25519:', got: {}",
                s
            ));
        }

        let key_part = s.strip_prefix("ed25519:").unwrap();
        if key_part.is_empty() {
            return Err("NEAR secret key cannot be empty after 'ed25519:' prefix".to_string());
        }

        Ok(NearSecretKeyString(s.to_string()))
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

    /// Named account that will sign the registration transaction (e.g., sam.test.near).
    /// This is the operator's account that has permission to register backup services.
    #[arg(long, env)]
    pub signer_account_id: AccountId,

    /// Operator's NEAR secret key in the format: ed25519:...
    /// This key must have permission to sign transactions for the signer_account_id.
    /// Example: ed25519:38sDEfkYcDuJpspMf8RaYB7eCgUV5V6wSAdQYR8wuB4pKsDqamKJYNpqzzZNc6MSRgyYxCK12e5kTJ7vnWm3KZbv
    #[arg(long, env)]
    pub signer_secret_key: NearSecretKeyString,
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
