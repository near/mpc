use near_crypto::{PublicKey, SecretKey};
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
    /// Account hosting the MPC contract.
    MpcContract,
    /// Account hosting the loadtesting contract.
    LoadtestContract,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MpcParticipantSetup {
    pub p2p_private_key: SecretKey,
    pub p2p_public_key: PublicKey,
    pub respond_yaml_file_contents: String,
}

// From mpc code.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RespondConfigFile {
    pub account_id: AccountId,
    pub access_keys: Vec<SecretKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DevnetSetupRepository {
    pub accounts: HashMap<AccountId, NearAccount>,
    pub mpc_setups: HashMap<String, DevnetSetup>,
    pub loadtest_setups: HashMap<String, LoadtestSetup>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DevnetSetup {
    pub participants: Vec<AccountId>,
    pub contract: AccountId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoadtestSetup {
    pub load_senders: Vec<AccountId>,
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
