use crate::rpc::NearRpcClients;
use ed25519_dalek::{SigningKey, VerifyingKey};
use near_account_id::AccountId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

/// Locally stored Near account information.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NearAccount {
    pub account_id: AccountId,
    #[serde(with = "near_crypto_compatible_serialization::signing_keys")]
    pub access_keys: Vec<SigningKey>,
    pub kind: NearAccountKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
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

/// Locally stored MPC participant keys and other info.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MpcParticipantSetup {
    /// The account this participant uses to respond to signature requests.
    pub responding_account_id: AccountId,
    #[serde(with = "near_crypto_compatible_serialization::verifying_key")]
    pub p2p_public_key: VerifyingKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractSetup {
    /// The filename that was deployed last time. This is just for informational purposes.
    pub deployed_filename: String,
}

/// The format of the devnet_setup.yaml file - all the local state we store.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DevnetSetupRepository {
    pub accounts: HashMap<AccountId, NearAccount>,
    pub mpc_setups: HashMap<String, MpcNetworkSetup>,
    pub loadtest_setups: HashMap<String, LoadtestSetup>,
}

/// Local state for a single MPC network.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct MpcNetworkSetup {
    pub participants: Vec<AccountId>,
    pub contract: Option<AccountId>,
    // These desired fields are used when updating the network.
    pub desired_balance_per_account: u128,
    pub num_responding_access_keys: usize,
    pub desired_balance_per_responding_account: u128,
    pub nomad_server_url: Option<String>,
    #[serde(default)]
    pub ssd: bool,
}

impl fmt::Display for MpcNetworkSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "MPC Network Setup:")?;
        writeln!(f, "  Participants:")?;
        for (i, participant) in self.participants.iter().enumerate() {
            writeln!(f, "    {}: {}", i + 1, participant)?;
        }

        if let Some(contract) = &self.contract {
            writeln!(f, "  Contract: {}", contract)?;
        } else {
            writeln!(f, "  Contract: None")?;
        }

        writeln!(
            f,
            "  Desired Balance per Account: {}",
            self.desired_balance_per_account
        )?;
        writeln!(
            f,
            "  Number of Responding Access Keys: {}",
            self.num_responding_access_keys
        )?;
        writeln!(
            f,
            "  Desired Balance per Responding Account: {}",
            self.desired_balance_per_responding_account
        )?;

        match &self.nomad_server_url {
            Some(url) => {
                writeln!(f, "  Nomad Server URL: {}", url)?;
            }
            None => {
                writeln!(f, "  Nomad Server URL: None")?;
            }
        };
        let disk_type = if self.ssd { "SSD" } else { "HDD" };
        writeln!(f, " Running on {disk_type}")
    }
}

/// Local state for a single loadtest setup.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct LoadtestSetup {
    pub load_senders: Vec<AccountId>,
    pub desired_balance_per_account: u128,
    pub desired_keys_per_account: usize,
    pub parallel_signatures_contract: Option<AccountId>,
}

impl fmt::Display for LoadtestSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "LoadtestSetup {{")?;
        writeln!(f, "  load_senders: {:?}", self.load_senders)?;
        writeln!(
            f,
            "  desired_balance_per_account: {}",
            self.desired_balance_per_account
        )?;
        writeln!(
            f,
            "  desired_keys_per_account: {}",
            self.desired_keys_per_account
        )?;
        writeln!(
            f,
            "  parallel_signatures_contract: {}",
            self.parallel_signatures_contract
                .as_ref()
                .map(|x| x.as_str())
                .unwrap_or("None")
        )?;
        write!(f, "}}")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub rpcs: Vec<RpcConfig>,
    pub funding_account: Option<NearAccount>,
    // Path of the Near-One/infra-ops repository.
    // Used only for terraform deployment commands.
    pub infra_ops_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcConfig {
    pub url: String,
    /// Maximum number of requests per second that the RPC server will allow.
    pub rate_limit: usize,
    /// Maximum number of in-flight requests that the RPC server will allow.
    pub max_concurrency: usize,
}

pub struct ParsedConfig {
    pub rpc: Arc<NearRpcClients>,
    pub infra_ops_path: PathBuf,
    pub funding_account: Option<NearAccount>,
}

pub async fn load_config() -> ParsedConfig {
    const CONFIG_FILE: &str = "config.yaml";
    let config = std::fs::read_to_string(CONFIG_FILE)
        .expect("A `config.yaml` should exist in the working directory.");
    let config: Config = serde_yaml::from_str(&config).unwrap();
    let client = Arc::new(NearRpcClients::new(config.rpcs).await);
    ParsedConfig {
        rpc: client,
        infra_ops_path: PathBuf::from(config.infra_ops_path),
        funding_account: config.funding_account,
    }
}

/// 1. We need to serialize the keys with [`bs58`] encoding, to maintain
///    backwards compatibility with the binary version previous to https://github.com/near/mpc/issues/880
///    which removes [`near_crypto`] representation of keys on the node in favor of the [`ed25519_dalek`] crate.
///
/// 2. [`serde_yaml`] serialization will fail as [`SigningKey`] and [`VerifyingKey`] serialize into bytes, and [`serde_yaml`] does
///    not allow values to be defined as bytes.
pub mod near_crypto_compatible_serialization {
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
    const ED25519_PREFIX: &str = "ed25519";

    pub mod signing_keys {
        use super::*;

        pub fn serialize<S>(keys: &[SigningKey], serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let bs58_strings: Vec<String> = keys
                .iter()
                .map(|key| {
                    format!(
                        "{ED25519_PREFIX}:{}",
                        bs58::encode(key.to_keypair_bytes()).into_string()
                    )
                })
                .collect();
            bs58_strings.serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<SigningKey>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bs58_strings: Vec<String> = Vec::deserialize(deserializer)?;
            bs58_strings
                .into_iter()
                .map(|bs58_str| {
                    let Some((ED25519_PREFIX, encoded_key)) = &bs58_str.split_once(":") else {
                        return Err(de::Error::custom("Key must start with 'ed25519:' prefix"));
                    };

                    let bytes: [u8; 64] = bs58::decode(encoded_key)
                        .into_vec()
                        .map_err(de::Error::custom)?
                        .try_into()
                        .map_err(|_| de::Error::custom("Key pair bytes must be 64 bytes."))?;

                    SigningKey::from_keypair_bytes(&bytes).map_err(de::Error::custom)
                })
                .collect()
        }
    }

    pub mod verifying_key {
        use anyhow::Context;

        use super::*;

        pub fn serialize<S>(key: &VerifyingKey, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let bs58_key = format!(
                "{ED25519_PREFIX}:{}",
                bs58::encode(key.as_bytes()).into_string(),
            );
            bs58_key.serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<VerifyingKey, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bs58_string: String = String::deserialize(deserializer)?;

            let Some((ED25519_PREFIX, encoded_key)) = &bs58_string.split_once(":") else {
                return Err(de::Error::custom(format!(
                    "Key must start with '{ED25519_PREFIX}:' prefix"
                )));
            };

            let bytes = bs58::decode(encoded_key)
                .into_vec()
                .map_err(de::Error::custom)?;

            let key_bytes: [u8; 32] = bytes.try_into().map_err(|provided_bytes: Vec<u8>| {
                let error_message = format!(
                    "Provided bytes is not 32 bytes. Actual length {:?}",
                    provided_bytes.len()
                );
                de::Error::custom(error_message)
            })?;

            VerifyingKey::from_bytes(&key_bytes)
                .context("Failed to create verifying key from deserialized bytes.")
                .map_err(de::Error::custom)
        }
    }
}
