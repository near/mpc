use crate::primitives::ParticipantId;

use anyhow::Context;
use ed25519_dalek::{SigningKey, VerifyingKey};
use either::Either;
use near_account_id::AccountId;
use near_indexer_primitives::types::Finality;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, ToSocketAddrs},
    path::Path,
};

mod foreign_chains;
pub use foreign_chains::{
    AbstractApiVariant, AbstractChainConfig, AbstractProviderConfig, AuthConfig, BitcoinApiVariant,
    BitcoinChainConfig, BitcoinProviderConfig, EthereumApiVariant, EthereumChainConfig,
    EthereumProviderConfig, ForeignChainsConfig, SolanaApiVariant, SolanaChainConfig,
    SolanaProviderConfig, StarknetApiVariant, StarknetChainConfig, StarknetProviderConfig,
    TokenConfig,
};

const DEFAULT_PPROF_PORT: u16 = 34001;

pub type AesKey256 = [u8; 32];
pub type AesKey128 = [u8; 16];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TripleConfig {
    pub concurrency: usize,
    pub desired_triples_to_buffer: usize,
    pub timeout_sec: u64,
    /// If we issued a triple generation, wait at least this number of seconds
    /// before issuing another one. This is to avoid thundering herd situations.
    pub parallel_triple_generation_stagger_time_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresignatureConfig {
    pub concurrency: usize,
    pub desired_presignatures_to_buffer: usize,
    pub timeout_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureConfig {
    pub timeout_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CKDConfig {
    pub timeout_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeygenConfig {
    pub timeout_sec: u64,
}

impl Default for KeygenConfig {
    fn default() -> KeygenConfig {
        KeygenConfig { timeout_sec: 60 }
    }
}

/// Configuration about the MPC protocol. It can come from either the contract
/// on chain, or static offline config file.
#[derive(Debug, Clone)]
pub struct MpcConfig {
    pub my_participant_id: ParticipantId,
    pub participants: ParticipantsConfig,
}

impl MpcConfig {
    /// Finds the participant ID of the local node from the participants config
    /// and constructs the MpcConfig. Returns None if the local node is not
    /// found in the participants config.
    pub fn from_participants_with_near_account_id(
        participants: ParticipantsConfig,
        my_near_account_id: &AccountId,
        my_p2p_public_key: &ed25519_dalek::VerifyingKey,
    ) -> Option<Self> {
        let my_participant_id =
            participants.get_participant_id_by_node_id(my_near_account_id, my_p2p_public_key)?;
        Some(Self {
            my_participant_id,
            participants,
        })
    }

    /// When performing a key generation or key resharing protocol, someone has to create a channel.
    /// Don't confuse with Leader Centric Computations.
    pub fn is_leader_for_key_event(&self) -> bool {
        let my_participant_id = self.my_participant_id;
        let participant_with_lowest_id = self
            .participants
            .participants
            .iter()
            .map(|p| p.id)
            .min()
            .expect("Participants list should not be empty");
        my_participant_id == participant_with_lowest_id
    }
}

/// Config for the web UI, which is mostly for debugging and metrics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebUIConfig {
    pub host: String,
    pub port: u16,
}

/// Configures behavior of the near indexer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexerConfig {
    /// Tells whether to validate the genesis file before starting
    pub validate_genesis: bool,
    /// Sets the starting point for indexing
    pub sync_mode: SyncMode,
    /// Sets the finality level at which blocks are streamed
    pub finality: Finality,
    /// Sets the concurrency for indexing
    pub concurrency: std::num::NonZeroU16,
    /// MPC contract id
    pub mpc_contract_id: AccountId,
    /// If specified, replaces the port number in any ParticipantInfos read from chain
    pub port_override: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncMode {
    /// continue from the block Indexer was interrupted
    Interruption,
    /// start from the newest block after node finishes syncing
    Latest,
    /// start from specified block height
    Block(BlockArgs),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockArgs {
    /// block height for block sync mode
    pub height: u64,
}

/// The contents of the on-disk config.yaml file. Contains no secrets.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigFile {
    /// The near account ID that this node owns.
    /// If an on-chain contract is used, this account is used to invoke
    /// identity-sensitive functions of the contract (join, vote, etc.).
    /// If static ParticipantsConfig is specified, this account id is used
    /// to identify our own participant ID from within the static config.
    /// In both cases this account is *not* used to send signature responses.
    pub my_near_account_id: AccountId,

    /// Near account ID of the account that will be used to submit signature responses.
    /// For reference, go to the `spawn_real_indexer` logic.
    pub near_responder_account_id: AccountId,
    /// Number of keys that will be used to sign the signature responses.
    pub number_of_responder_keys: usize,
    // TODO(#2038): remove custom deserializer
    #[serde(deserialize_with = "deserialize_to_socket_addr")]
    pub web_ui: SocketAddr,
    // TODO(#2038): remove custom deserializer
    #[serde(deserialize_with = "deserialize_to_socket_addr")]
    pub migration_web_ui: SocketAddr,
    #[serde(default = "default_pprof_bind_address")]
    pub pprof_bind_address: SocketAddr,
    pub indexer: IndexerConfig,
    pub triple: TripleConfig,
    pub presignature: PresignatureConfig,
    pub signature: SignatureConfig,
    pub ckd: CKDConfig,
    #[serde(default)]
    pub keygen: KeygenConfig,
    #[serde(default)]
    pub foreign_chains: ForeignChainsConfig,
    /// This value is only considered when the node is run in normal node. It defines the number of
    /// working threads for the runtime.
    pub cores: Option<usize>,
}

impl ConfigFile {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let original_config_string =
            fs::read_to_string(path).context("failed to read config file")?;
        let config: Self = serde_yaml::from_str(&original_config_string)?;
        config.validate().context("Validate config.yaml")?;

        // re-serialize if needed
        {
            let re_serialized = serde_yaml::to_string(&config)?;
            let update_config_with_new_schema = re_serialized != original_config_string;

            if update_config_with_new_schema {
                let tmp = path.with_extension("yaml.tmp");
                fs::write(&tmp, re_serialized.as_bytes())?;
                fs::rename(&tmp, path)?;
            }
        }

        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        self.foreign_chains.validate()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParticipantsConfig {
    /// The threshold for the MPC protocol.
    pub threshold: u64,
    pub participants: Vec<ParticipantInfo>,
}

#[cfg(test)]
impl ParticipantsConfig {
    pub fn change_participant_pk(
        &mut self,
        account_id: &AccountId,
        new_p2p_public_key: VerifyingKey,
    ) -> anyhow::Result<()> {
        if let Some(p_info) = self
            .participants
            .iter_mut()
            .find(|p_info| p_info.near_account_id == *account_id)
        {
            p_info.p2p_public_key = new_p2p_public_key;
        } else {
            anyhow::bail!("expected participant");
        }
        Ok(())
    }
}

/// Indicates whether a registered node is currently active or idle.
#[derive(PartialEq, Debug)]
pub enum NodeStatus {
    Active,
    Idle,
}

#[derive(Debug)]
/// Describes whether a participant is part of the contract and, if so, specifies a node status.
pub enum ParticipantStatus {
    Inactive,
    Active(NodeStatus),
}

impl ParticipantsConfig {
    /// Returns the participation status for the node of matching account_id and p2p public key.
    ///
    /// If the account_id exists in the participant list, returns
    /// [`ParticipantStatus::Active`] with either [`NodeStatus::Active`] if the
    /// stored P2P public key matches, or [`NodeStatus::Idle`] otherwise.  
    /// Returns [`ParticipantStatus::Inactive`] if the account is not found.
    pub fn participant_status(
        &self,
        account_id: &AccountId,
        p2p_public_key: &VerifyingKey,
    ) -> ParticipantStatus {
        if let Some(participant_info) = self.get_info_by_account_id(account_id) {
            let status = if &participant_info.p2p_public_key == p2p_public_key {
                NodeStatus::Active
            } else {
                NodeStatus::Idle
            };
            ParticipantStatus::Active(status)
        } else {
            ParticipantStatus::Inactive
        }
    }

    pub fn get_info_by_account_id(&self, account_id: &AccountId) -> Option<&ParticipantInfo> {
        self.participants
            .iter()
            .find(|participant_info| participant_info.near_account_id == *account_id)
    }

    pub fn get_info(&self, id: ParticipantId) -> Option<&ParticipantInfo> {
        self.participants
            .iter()
            .find(|participant_info| participant_info.id == id)
    }

    pub fn get_participant_id(&self, account_id: &AccountId) -> Option<ParticipantId> {
        self.get_info_by_account_id(account_id)
            .map(|participant_info| participant_info.id)
    }

    pub fn get_participant_id_by_node_id(
        &self,
        account_id: &AccountId,
        p2p_public_key: &VerifyingKey,
    ) -> Option<ParticipantId> {
        if let Some(participant_info) = self.get_info_by_account_id(account_id) {
            if &participant_info.p2p_public_key == p2p_public_key {
                return Some(participant_info.id);
            }
        };
        None
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParticipantInfo {
    pub id: ParticipantId,
    /// Address and port that this participant can be directly reached at.
    /// Used for the P2P communication. Communication happens over TCP.
    pub address: String,
    pub port: u16,
    /// Public key that corresponds to this P2P peer's private key.
    pub p2p_public_key: ed25519_dalek::VerifyingKey,
    pub near_account_id: AccountId,
}

pub fn load_config_file(home_dir: &Path) -> anyhow::Result<ConfigFile> {
    let config_path = home_dir.join("config.yaml");
    ConfigFile::from_file(&config_path).context("Load config.yaml")
}

#[derive(Clone)]
pub struct SecretsConfig {
    // Ed25519 keys. `near_crypto` API too rigid to store this exact enum type.
    // e.g. you can not call `public_key` on the `ED25519SecretKey` type.
    pub persistent_secrets: PersistentSecrets,
    pub local_storage_aes_key: AesKey128,
    pub backup_encryption_key: AesKey256,
}

pub fn hex_to_binary_key<const N: usize>(hex_key: &str) -> anyhow::Result<[u8; N]> {
    let decoded_key =
        hex::decode(hex_key).context(format!("Encryption key must be {} hex characters", N * 2))?;
    decoded_key.as_slice().try_into().context(format!(
        "Encryption key must be {} bytes ({} hex characters)",
        N,
        N * 2
    ))
}

pub fn generate_and_write_backup_encryption_key_to_disk(home_dir: &Path) -> anyhow::Result<String> {
    tracing::info!("generating encryption key");
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    let key_path = home_dir.join("backup_encryption_key.hex");
    let key_hex = hex::encode(key);
    std::fs::write(&key_path, &key_hex)?;
    tracing::info!("wrote encryption key to disk {:?}", key_path);
    Ok(key_hex)
}

impl SecretsConfig {
    pub fn from_parts(
        local_storage_aes_key_hex: &str,
        persistent_secrets: PersistentSecrets,
        backup_encryption_key_hex: &str,
    ) -> anyhow::Result<Self> {
        let local_storage_aes_key = hex_to_binary_key(local_storage_aes_key_hex)
            .context("invalid local storage aes key hex")?;
        let backup_encryption_key = hex_to_binary_key(backup_encryption_key_hex)
            .context("invalid backup symmetric key hex")?;
        Ok(Self {
            persistent_secrets,
            local_storage_aes_key,
            backup_encryption_key,
        })
    }
}

/// Secrets that are stored on disk. They are generated on the first run.
/// The idea is when using a TEE, it's safer to generate them inside enclave, rather than provide it
/// from outside.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PersistentSecrets {
    #[serde(
        serialize_with = "serialize_signing_key",
        deserialize_with = "deserialize_signing_key"
    )]
    pub p2p_private_key: SigningKey,
    #[serde(
        serialize_with = "serialize_signing_key",
        deserialize_with = "deserialize_signing_key"
    )]
    pub near_signer_key: SigningKey,
    #[serde(
        serialize_with = "serialize_signing_key_vec",
        deserialize_with = "deserialize_signing_key_vec"
    )]
    pub near_responder_keys: Vec<SigningKey>,
}

impl PersistentSecrets {
    const SECRETS_FILE_NAME: &'static str = "secrets.json";

    fn maybe_get_existing(home_dir: &Path) -> anyhow::Result<Option<PersistentSecrets>> {
        let file_path = home_dir.join(Self::SECRETS_FILE_NAME);
        let secrets = if file_path.exists() {
            let str = std::fs::read_to_string(&file_path)?;
            let secrets_file: PersistentSecrets = serde_json::from_str(&str)?;
            Some(secrets_file)
        } else {
            None
        };
        Ok(secrets)
    }

    fn gen_secrets_and_write_to_disk(
        home_dir: &Path,
        number_of_responder_keys: usize,
    ) -> anyhow::Result<PersistentSecrets> {
        if !home_dir.exists() {
            std::fs::create_dir_all(home_dir)?;
        }

        let mut os_rng = rand::rngs::OsRng;
        let p2p_secret = SigningKey::generate(&mut os_rng);
        let near_signer_key = SigningKey::generate(&mut os_rng);

        let near_responder_keys = (0..number_of_responder_keys)
            .map(|_| SigningKey::generate(&mut os_rng))
            .collect::<Vec<_>>();

        let secrets = PersistentSecrets {
            p2p_private_key: p2p_secret,
            near_signer_key,
            near_responder_keys,
        };

        let path = home_dir.join(Self::SECRETS_FILE_NAME);
        if path.exists() {
            anyhow::bail!("secrets.json already exists. Refusing to overwrite.");
        }
        std::fs::write(&path, serde_json::to_vec(&secrets)?)?;
        tracing::debug!("p2p and near account key generated in {}", path.display());

        Ok(secrets)
    }

    pub fn generate_or_get_existing(
        home_dir: &Path,
        number_of_responder_keys: usize, // Number of responder keys to generate
    ) -> anyhow::Result<PersistentSecrets> {
        anyhow::ensure!(
            number_of_responder_keys > 0,
            "At least one access key must be provided"
        );
        let secrets = if let Some(secrets) = Self::maybe_get_existing(home_dir)? {
            tracing::debug!("p2p and near account secret key already exists. Using existing.");
            // TODO(#534): consistent number of keys
            secrets
        } else {
            tracing::debug!("p2p and near account secret key not found. Generating...");
            Self::gen_secrets_and_write_to_disk(home_dir, number_of_responder_keys)?
        };

        if secrets.near_responder_keys.len() != number_of_responder_keys {
            tracing::warn!("Number of responder keys in secrets.json does not match number of responder keys specified.")
        }

        Ok(secrets)
    }
}

const ED25519_PREFIX: &str = "ed25519";

fn serialize_signing_key<S>(key: &SigningKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let bytes = key.to_keypair_bytes(); // e.g., &[u8]
    let str = [ED25519_PREFIX, ":", &bs58::encode(bytes).into_string()].concat();
    serializer.serialize_str(&str)
}

fn deserialize_signing_key<'de, D>(deserializer: D) -> Result<SigningKey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let str: String = serde::Deserialize::deserialize(deserializer)?;
    let Some((ED25519_PREFIX, encoded_key)) = &str.split_once(":") else {
        return Err(serde::de::Error::custom(format!(
            "Key must start with '{ED25519_PREFIX}:' prefix"
        )));
    };

    let bytes: [u8; 64] = bs58::decode(encoded_key)
        .into_vec()
        .map_err(serde::de::Error::custom)?
        .try_into()
        .map_err(|_| serde::de::Error::custom("Key pair bytes must be 64 bytes."))?;

    SigningKey::from_keypair_bytes(&bytes).map_err(serde::de::Error::custom)
}

pub fn serialize_signing_key_vec<S>(keys: &[SigningKey], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
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

pub fn deserialize_signing_key_vec<'de, D>(deserializer: D) -> Result<Vec<SigningKey>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bs58_strings: Vec<String> = Vec::deserialize(deserializer)?;
    bs58_strings
        .into_iter()
        .map(|bs58_str| {
            let Some((ED25519_PREFIX, encoded_key)) = &bs58_str.split_once(":") else {
                return Err(serde::de::Error::custom(
                    "Key must start with 'ed25519:' prefix",
                ));
            };

            let bytes: [u8; 64] = bs58::decode(encoded_key)
                .into_vec()
                .map_err(serde::de::Error::custom)?
                .try_into()
                .map_err(|_| serde::de::Error::custom("Key pair bytes must be 64 bytes."))?;

            SigningKey::from_keypair_bytes(&bytes).map_err(serde::de::Error::custom)
        })
        .collect()
}

/// Credentials of the near account used to submit signature responses.
/// It is recommended to use a separate dedicated account for this purpose.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RespondConfig {
    /// It can be an arbitrary id because respond calls are not authenticated.
    /// The account should have sufficient NEAR to pay for the function calls.
    pub account_id: AccountId,
    /// In production it is recommended to provide 50+ distinct access keys
    /// to minimize incidence of nonce conflicts under heavy load.
    pub access_keys: Vec<SigningKey>,
}

impl RespondConfig {
    pub fn from_parts(config: &ConfigFile, secrets: &PersistentSecrets) -> Self {
        // TODO(#1296): Decide if the MPC responder account is actually needed
        // updated as part PR #1270 as temporary solution.
        // using main account for responding.
        Self {
            account_id: config.my_near_account_id.clone(),
            access_keys: vec![secrets.near_signer_key.clone()],
        }
    }
}

#[cfg(feature = "network-hardship-simulation")]
pub fn load_listening_blocks_file(home_dir: &Path) -> anyhow::Result<bool> {
    let listen_blocks_file = home_dir.join("listen_blocks.flag");
    match fs::read_to_string(&listen_blocks_file) {
        Ok(content) => {
            let new_val = content.trim().eq_ignore_ascii_case("true");
            tracing::info!("flag file found, setting to {}", new_val);
            Ok(new_val)
        }
        Err(err) => Err(anyhow::anyhow!(
            "Could not find file {:?}: {}",
            &listen_blocks_file,
            err
        )),
    }
}

fn default_pprof_bind_address() -> SocketAddr {
    (Ipv4Addr::UNSPECIFIED, DEFAULT_PPROF_PORT).into()
}

fn deserialize_to_socket_addr<'de, D>(deserializer: D) -> Result<SocketAddr, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let either: Either<SocketAddr, WebUIConfig> =
        either::serde_untagged::deserialize(deserializer)?;
    match either {
        Either::Left(addr) => Ok(addr),
        Either::Right(WebUIConfig { host, port }) => format!("{host}:{port}")
            .to_socket_addrs()
            .map_err(serde::de::Error::custom)?
            .next()
            .ok_or_else(|| serde::de::Error::custom("could not resolve host")),
    }
}

#[cfg(test)]
pub mod tests {
    use assert_matches::assert_matches;
    use mpc_contract::primitives::test_utils::bogus_ed25519_near_public_key;
    use rand::{
        distributions::{Alphanumeric, Uniform},
        rngs::OsRng,
        Rng, RngCore,
    };

    use crate::providers::PublicKeyConversion;
    use tempfile::TempDir;

    use super::*;
    #[test]
    fn test_secret_gen() -> anyhow::Result<()> {
        let temp_dir = TempDir::new()?;
        let temp_dir_path = temp_dir.path();

        assert!(PersistentSecrets::maybe_get_existing(temp_dir_path)?.is_none());

        let expected_secrets = PersistentSecrets::generate_or_get_existing(temp_dir_path, 1)?;

        // check that the key will not be overwritten
        let _ = PersistentSecrets::generate_or_get_existing(temp_dir_path, 4242)
            .expect("Existing secrets should be reusable");

        let actual_secrets = PersistentSecrets::generate_or_get_existing(temp_dir_path, 424)?;

        assert_eq!(
            actual_secrets.p2p_private_key,
            expected_secrets.p2p_private_key
        );
        assert_eq!(
            actual_secrets.near_signer_key,
            expected_secrets.near_signer_key
        );

        Ok(())
    }

    pub fn gen_account_id() -> AccountId {
        let lower_case = Uniform::new_inclusive(b'a', b'z');
        let random_string: String = rand::thread_rng()
            .sample_iter(&lower_case)
            .take(12)
            .map(char::from)
            .collect();
        let account_id: String = format!("dummy.account.{}", random_string);
        account_id.parse().unwrap()
    }

    pub fn gen_participant() -> ParticipantInfo {
        let near_account_id = gen_account_id();
        let mut rng = rand::thread_rng();
        let participant_id: u32 = rng.next_u32();
        let address: String = (0..16).map(|_| rng.sample(Alphanumeric) as char).collect();
        let p2p_public_key =
            VerifyingKey::from_near_sdk_public_key(&bogus_ed25519_near_public_key()).unwrap();
        let port: u16 = rng.gen();
        ParticipantInfo {
            id: ParticipantId::from_raw(participant_id),
            address,
            port,
            p2p_public_key,
            near_account_id,
        }
    }

    #[test]
    fn test_participant_status() {
        let participant = gen_participant();
        let non_participant = gen_participant();
        let bogus_config = ParticipantsConfig {
            threshold: 3,
            participants: vec![participant.clone()],
        };
        assert_matches!(
            bogus_config.participant_status(
                &non_participant.near_account_id,
                &participant.p2p_public_key
            ),
            ParticipantStatus::Inactive
        );
        assert_matches!(
            bogus_config
                .participant_status(&participant.near_account_id, &participant.p2p_public_key),
            ParticipantStatus::Active(NodeStatus::Active)
        );
        assert_matches!(
            bogus_config.participant_status(
                &participant.near_account_id,
                &non_participant.p2p_public_key
            ),
            ParticipantStatus::Active(NodeStatus::Idle)
        );
    }

    #[test]
    fn test_permanent_secrets_serialization() {
        let secrets = PersistentSecrets {
            p2p_private_key: SigningKey::generate(&mut OsRng),
            near_signer_key: SigningKey::generate(&mut OsRng),
            near_responder_keys: vec![SigningKey::generate(&mut OsRng); 8],
        };
        let secrets_str = serde_json::to_string(&secrets).unwrap();

        let secrets_copy = serde_json::from_str(&secrets_str).unwrap();

        assert_eq!(secrets, secrets_copy);
    }

    /// A minimal valid ConfigFile YAML string using the current SocketAddr format.
    const CONFIG_EXAMPLE: &str = r#"
my_near_account_id: sam.test.near
near_responder_account_id: sam.test.near
number_of_responder_keys: 1
web_ui: 127.0.0.1:8082
migration_web_ui: 127.0.0.1:8078
pprof_bind_address: 127.0.0.1:34002
triple:
  concurrency: 2
  desired_triples_to_buffer: 128
  timeout_sec: 60
  parallel_triple_generation_stagger_time_sec: 1
presignature:
  concurrency: 4
  desired_presignatures_to_buffer: 64
  timeout_sec: 60
signature:
  timeout_sec: 60
indexer:
  validate_genesis: false
  sync_mode: Latest
  concurrency: 1
  mpc_contract_id: mpc-contract.test.near
  finality: optimistic
ckd:
  timeout_sec: 60
cores: 4
"#;

    #[test]
    fn config_example_is_deserializable() {
        // given
        let config_string = CONFIG_EXAMPLE;

        // when
        let serialized_config: Result<ConfigFile, _> = serde_yaml::from_str(config_string);

        // then
        assert_matches!(serialized_config, Ok(_));
    }

    #[test]
    fn config_from_file_re_serializes_with_updated_fields() {
        // given: config with old WebUIConfig format (host + port as separate fields)
        let old_format_config = r#"
my_near_account_id: sam.test.near
near_responder_account_id: sam.test.near
number_of_responder_keys: 1
web_ui:
  host: 127.0.0.1
  port: 8082
migration_web_ui:
  host: 127.0.0.1
  port: 8078
pprof_bind_address: 127.0.0.1:34002
triple:
  concurrency: 2
  desired_triples_to_buffer: 128
  timeout_sec: 60
  parallel_triple_generation_stagger_time_sec: 1
presignature:
  concurrency: 4
  desired_presignatures_to_buffer: 64
  timeout_sec: 60
signature:
  timeout_sec: 60
indexer:
  validate_genesis: false
  sync_mode: Latest
  concurrency: 1
  mpc_contract_id: mpc-contract.test.near
  finality: optimistic
ckd:
  timeout_sec: 60
cores: 4
"#;

        // when: deserialize and re-serialize
        let config: ConfigFile = serde_yaml::from_str(old_format_config).unwrap();
        let re_serialized = serde_yaml::to_string(&config).unwrap();

        // then: re-serialized config uses the new SocketAddr format (not host+port)
        let re_deserialized: ConfigFile = serde_yaml::from_str(&re_serialized).unwrap();
        assert_eq!(config, re_deserialized);
        // The re-serialized YAML should contain the flat socket address format
        assert!(
            re_serialized.contains("web_ui: 127.0.0.1:8082"),
            "Expected flat SocketAddr format, got:\n{re_serialized}"
        );
        assert!(
            re_serialized.contains("migration_web_ui: 127.0.0.1:8078"),
            "Expected flat SocketAddr format, got:\n{re_serialized}"
        );
    }

    #[test]
    fn old_web_ui_config_format_deserializes_to_socket_addr() {
        // given: config with old WebUIConfig format
        let old_format_config = CONFIG_EXAMPLE.replace(
            "web_ui: 127.0.0.1:8082",
            "web_ui:\n  host: 127.0.0.1\n  port: 8082",
        );

        // when
        let config: ConfigFile = serde_yaml::from_str(&old_format_config).unwrap();

        // then
        assert_eq!(config.web_ui, SocketAddr::from((Ipv4Addr::LOCALHOST, 8082)));
    }

    #[test]
    fn new_socket_addr_format_round_trips() {
        // given
        let config: ConfigFile = serde_yaml::from_str(CONFIG_EXAMPLE).unwrap();

        // when: serialize and deserialize again
        let yaml = serde_yaml::to_string(&config).unwrap();
        let round_tripped: ConfigFile = serde_yaml::from_str(&yaml).unwrap();

        // then
        assert_eq!(config, round_tripped);
    }

    #[test]
    fn socket_addr_fields_parse_correctly() {
        // given
        let config: ConfigFile = serde_yaml::from_str(CONFIG_EXAMPLE).unwrap();

        // then
        assert_eq!(config.web_ui, SocketAddr::from((Ipv4Addr::LOCALHOST, 8082)));
        assert_eq!(
            config.migration_web_ui,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 8078))
        );
        assert_eq!(
            config.pprof_bind_address,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 34002))
        );
    }

    #[test]
    fn socket_addr_with_ipv4_unspecified() {
        // given: config using 0.0.0.0 addresses
        let config_str = CONFIG_EXAMPLE
            .replace("127.0.0.1:8082", "0.0.0.0:3000")
            .replace("127.0.0.1:8078", "0.0.0.0:3001")
            .replace("127.0.0.1:34002", "0.0.0.0:34002");

        // when
        let config: ConfigFile = serde_yaml::from_str(&config_str).unwrap();

        // then
        assert_eq!(
            config.web_ui,
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 3000))
        );
        assert_eq!(
            config.migration_web_ui,
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 3001))
        );
    }

    #[test]
    fn mixed_old_and_new_format_deserializes() {
        // given: web_ui in new format, migration_web_ui in old format
        let mixed_config = r#"
my_near_account_id: sam.test.near
near_responder_account_id: sam.test.near
number_of_responder_keys: 1
web_ui: 127.0.0.1:8082
migration_web_ui:
  host: 0.0.0.0
  port: 9090
pprof_bind_address: 127.0.0.1:34002
triple:
  concurrency: 2
  desired_triples_to_buffer: 128
  timeout_sec: 60
  parallel_triple_generation_stagger_time_sec: 1
presignature:
  concurrency: 4
  desired_presignatures_to_buffer: 64
  timeout_sec: 60
signature:
  timeout_sec: 60
indexer:
  validate_genesis: false
  sync_mode: Latest
  concurrency: 1
  mpc_contract_id: mpc-contract.test.near
  finality: optimistic
ckd:
  timeout_sec: 60
cores: 4
"#;

        // when
        let config: ConfigFile = serde_yaml::from_str(mixed_config).unwrap();

        // then
        assert_eq!(config.web_ui, SocketAddr::from((Ipv4Addr::LOCALHOST, 8082)));
        assert_eq!(
            config.migration_web_ui,
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 9090))
        );
    }

    #[test]
    fn from_file_does_not_rewrite_when_already_current_format() {
        // given: write a config that is already in the canonical serialized format
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("config.yaml");

        let config: ConfigFile = serde_yaml::from_str(CONFIG_EXAMPLE).unwrap();
        let canonical = serde_yaml::to_string(&config).unwrap();
        fs::write(&path, &canonical).unwrap();

        // when
        let _ = ConfigFile::from_file(&path).unwrap();

        // then: file content is byte-for-byte identical (no rewrite)
        let content_after = fs::read_to_string(&path).unwrap();
        assert_eq!(canonical, content_after);
    }

    #[test]
    fn from_file_rewrites_old_format_atomically() {
        // given: write a config using the old host+port WebUI format
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("config.yaml");

        let old_format = CONFIG_EXAMPLE.replace(
            "web_ui: 127.0.0.1:8082",
            "web_ui:\n  host: 127.0.0.1\n  port: 8082",
        );
        fs::write(&path, &old_format).unwrap();

        // when
        let config = ConfigFile::from_file(&path).unwrap();

        // then: file is rewritten in the new format
        let content_after = fs::read_to_string(&path).unwrap();
        assert!(
            content_after.contains("web_ui: 127.0.0.1:8082"),
            "Expected new SocketAddr format, got:\n{content_after}"
        );
        // no temp file left behind
        assert!(!dir.path().join("config.yaml.tmp").exists());
        // rewritten content round-trips correctly
        let re_read: ConfigFile = serde_yaml::from_str(&content_after).unwrap();
        assert_eq!(config, re_read);
    }
}
