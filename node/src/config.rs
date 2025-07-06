use crate::p2p;
use crate::primitives::ParticipantId;
use anyhow::Context;
use near_crypto::{PublicKey, SecretKey};
use near_indexer_primitives::types::{AccountId, Finality};
use serde::{Deserialize, Serialize};
#[cfg(feature = "network-hardship-simulation")]
use std::fs;

use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TripleConfig {
    pub concurrency: usize,
    pub desired_triples_to_buffer: usize,
    pub timeout_sec: u64,
    /// If we issued a triple generation, wait at least this number of seconds
    /// before issuing another one. This is to avoid thundering herd situations.
    pub parallel_triple_generation_stagger_time_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignatureConfig {
    pub concurrency: usize,
    pub desired_presignatures_to_buffer: usize,
    pub timeout_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureConfig {
    pub timeout_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    ) -> Option<Self> {
        let my_participant_id = participants
            .participants
            .iter()
            .find(|p| &p.near_account_id == my_near_account_id)?
            .id;
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebUIConfig {
    pub host: String,
    pub port: u16,
}

/// Configures behavior of the near indexer.
#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncMode {
    /// continue from the block Indexer was interrupted
    Interruption,
    /// start from the newest block after node finishes syncing
    Latest,
    /// start from specified block height
    Block(BlockArgs),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockArgs {
    /// block height for block sync mode
    pub height: u64,
}

/// The contents of the on-disk config.yaml file. Contains no secrets.
#[derive(Clone, Debug, Serialize, Deserialize)]
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

    pub web_ui: WebUIConfig,
    pub indexer: IndexerConfig,
    pub triple: TripleConfig,
    pub presignature: PresignatureConfig,
    pub signature: SignatureConfig,
    #[serde(default)]
    pub keygen: KeygenConfig,
    /// This value is only considered when the node is run in normal node. It defines the number of
    /// working threads for the runtime.
    pub cores: Option<usize>,
}

impl ConfigFile {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let file = std::fs::read_to_string(path)?;
        let config: Self = serde_yaml::from_str(&file)?;
        Ok(config)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParticipantsConfig {
    /// The threshold for the MPC protocol.
    pub threshold: u64,
    pub participants: Vec<ParticipantInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParticipantInfo {
    pub id: ParticipantId,
    /// Address and port that this participant can be directly reached at.
    /// Used for the P2P communication. Communication happens over TCP.
    pub address: String,
    pub port: u16,
    /// Public key that corresponds to this P2P peer's private key.
    pub p2p_public_key: PublicKey,
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
    pub local_storage_aes_key: [u8; 16],
}

impl SecretsConfig {
    pub fn from_parts(
        local_storage_aes_key_hex: &str,
        persistent_secrets: PersistentSecrets,
    ) -> anyhow::Result<Self> {
        let local_storage_aes_key = hex::decode(local_storage_aes_key_hex)
            .context("Encryption key must be 32 hex characters")?;
        let local_storage_aes_key: [u8; 16] = local_storage_aes_key
            .as_slice()
            .try_into()
            .context("Encryption key must be 16 bytes (32 bytes hex)")?;
        Ok(Self {
            persistent_secrets,
            local_storage_aes_key,
        })
    }
}

/// Secrets that are stored on disk. They are generated on the first run.
/// The idea is when using a TEE, it's safer to generate them inside enclave, rather than provide it
/// from outside.
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
pub struct PersistentSecrets {
    pub p2p_private_key: SecretKey,
    pub near_signer_key: SecretKey,
    pub near_responder_keys: Vec<SecretKey>,
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

        // Generate p2p secret key and public key
        let (secret_key, public_key) = p2p::keygen::generate_keypair()?;
        // The public key is available here, so you can log it immediately.
        tracing::debug!("Generated p2p public key: {:?}", public_key);

        // Store the secret key in SecretKey
        let p2p_secret = SecretKey::ED25519(secret_key);

        // Generate near signer key and public key
        let near_signer_key = SecretKey::from_random(near_crypto::KeyType::ED25519);
        let near_signer_public_key = near_signer_key.public_key();
        tracing::debug!(
            "Generated near signer public key: {:?}",
            near_signer_public_key
        );

        // Generate near responder keys and their public keys
        let near_responder_keys = (0..number_of_responder_keys)
            .map(|_| SecretKey::from_random(near_crypto::KeyType::ED25519))
            .collect::<Vec<_>>();
        let near_responder_public_keys: Vec<_> = near_responder_keys
            .iter()
            .map(|secret_key| secret_key.public_key())
            .collect();
        tracing::debug!(
            "Generated {} near responder public keys",
            near_responder_public_keys.len()
        );

        // Create PersistentSecrets structure
        let secrets = PersistentSecrets {
            p2p_private_key: p2p_secret,
            near_signer_key,
            near_responder_keys,
        };

        // Save secrets to disk
        let path = home_dir.join(Self::SECRETS_FILE_NAME);
        if path.exists() {
            anyhow::bail!("secrets.json already exists. Refusing to overwrite.");
        }
        std::fs::write(&path, serde_json::to_vec(&secrets)?)?;

        tracing::debug!("p2p and near account keys generated in {}", path.display());

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
            secrets
        } else {
            tracing::debug!("p2p and near account secret key not found. Generating...");
            Self::gen_secrets_and_write_to_disk(home_dir, number_of_responder_keys)?
        };
           // Log the public keys directly
        tracing::debug!("Using existing near_signer public key: {:?}", secrets.near_signer_key.public_key());
        tracing::debug!("Using existing p2p public key: {:?}", secrets.p2p_private_key.public_key());

        if secrets.near_responder_keys.len() != number_of_responder_keys {
            tracing::warn!("Number of responder keys in secrets.json does not match number of responder keys specified.")
        }
        anyhow::ensure!(matches!(secrets.p2p_private_key, SecretKey::ED25519(_)));
        anyhow::ensure!(matches!(secrets.near_signer_key, SecretKey::ED25519(_)));
        for key in &secrets.near_responder_keys {
            anyhow::ensure!(matches!(key, SecretKey::ED25519(_)));
        }

        Ok(secrets)
    }
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
    pub access_keys: Vec<SecretKey>,
}

impl RespondConfig {
    pub fn from_parts(config: &ConfigFile, secrets: &PersistentSecrets) -> Self {
        Self {
            account_id: config.near_responder_account_id.clone(),
            access_keys: secrets.near_responder_keys.clone(),
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

#[test]
fn test_secret_gen() -> anyhow::Result<()> {
    use tempfile::TempDir;
    let temp_dir = TempDir::new()?;
    let home_dir = temp_dir.path();

    assert!(PersistentSecrets::maybe_get_existing(home_dir)?.is_none());

    let expected_secrets = PersistentSecrets::generate_or_get_existing(home_dir, 1)?;

    // check that the key will not be overwritten
    assert!(PersistentSecrets::generate_or_get_existing(home_dir, 4242).is_ok());

    let actual_secrets = PersistentSecrets::generate_or_get_existing(home_dir, 424)?;

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
