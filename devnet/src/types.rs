use crate::rpc::NearRpcClients;
use near_crypto::SecretKey;
use near_sdk::AccountId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NearAccount {
    pub account_id: AccountId,
    pub access_keys: Vec<SecretKey>,
    pub kind: NearAccountKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NearAccountKind {
    /// Account that is only used for funding other accounts.
    FundingAccount,
    /// Account that is used for sending miscellaneous transactions.
    Normal,
    /// Account used by MPC participants.
    MpcParticipant(MpcParticipantSetup),
    /// Account hosting a contract.
    Contract(ContractSetup),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MpcParticipantSetup {
    pub p2p_private_key: SecretKey,
    pub responding_account_id: AccountId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractSetup {
    pub deployed_filename: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DevnetSetupRepository {
    pub accounts: HashMap<AccountId, NearAccount>,
    pub mpc_setups: HashMap<String, MpcNetworkSetup>,
    pub loadtest_setups: HashMap<String, LoadtestSetup>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct MpcNetworkSetup {
    pub participants: Vec<AccountId>,
    pub contract: Option<AccountId>,
    pub threshold: usize,
    pub desired_balance_per_account: u128,
    pub num_responding_access_keys: usize,
    pub desired_balance_per_responding_account: u128,
    pub nomad_server_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct LoadtestSetup {
    pub load_senders: Vec<AccountId>,
    pub desired_balance_per_account: u128,
    pub desired_keys_per_account: usize,
    pub parallel_signatures_contract: Option<AccountId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub rpcs: Vec<RpcConfig>,
    // Path of the Near-One/infra-ops repository.
    // Used only for terraform deployment commands.
    pub infra_ops_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcConfig {
    pub url: String,
    pub rate_limit: usize,
    pub max_concurrency: usize,
}

pub struct ParsedConfig {
    pub rpc: Arc<NearRpcClients>,
    pub infra_ops_path: PathBuf,
}

pub async fn load_config() -> ParsedConfig {
    const CONFIG_FILE: &str = "config.yaml";
    let config = std::fs::read_to_string(CONFIG_FILE).unwrap();
    let config: Config = serde_yaml::from_str(&config).unwrap();
    let client = Arc::new(NearRpcClients::new(config.rpcs).await);
    ParsedConfig {
        rpc: client,
        infra_ops_path: PathBuf::from(config.infra_ops_path),
    }
}
