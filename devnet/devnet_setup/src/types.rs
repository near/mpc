use near_crypto::SecretKey;
use near_sdk::AccountId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcConfig {
    pub url: String,
    pub rate_limit: usize,
    pub max_concurrency: usize,
}
