use crate::{
    config::{
        load_config_file, BlockArgs, CKDConfig, ConfigFile, IndexerConfig, KeygenConfig,
        PersistentSecrets, PresignatureConfig, RespondConfig, SecretsConfig, SignatureConfig,
        SyncMode, TripleConfig, WebUIConfig,
    },
    coordinator::Coordinator,
    db::SecretDB,
    indexer::{real::spawn_real_indexer, tx_sender::TransactionSender, IndexerAPI},
    keyshare::{
        compat::legacy_ecdsa_key_from_keyshares,
        local::LocalPermanentKeyStorageBackend,
        permanent::{PermanentKeyStorage, PermanentKeyStorageBackend, PermanentKeyshareData},
        GcpPermanentKeyStorageConfig, KeyStorageConfig, KeyshareStorage,
    },
    migration_service::spawn_recovery_server_and_run_onboarding,
    p2p::testing::{generate_test_p2p_configs, PortSeed},
    tracking::{self, start_root_task},
    web::{start_web_server, static_web_data, DebugRequest},
};
use anyhow::{anyhow, Context};
use attestation::{attestation::Attestation, report_data::ReportData};
use clap::{Args, Parser, Subcommand, ValueEnum};
use hex::FromHex;
use mpc_contract::state::ProtocolContractState;
use near_indexer_primitives::types::Finality;
use near_sdk::AccountId;
use near_time::Clock;
use std::collections::BTreeMap;
use std::{
    path::PathBuf,
    sync::OnceLock,
    sync::{Arc, Mutex},
    time::Duration,
};
use tee_authority::tee_authority::{
    DstackTeeAuthorityConfig, LocalTeeAuthorityConfig, TeeAuthority, DEFAULT_DSTACK_ENDPOINT,
    DEFAULT_PHALA_TDX_QUOTE_UPLOAD_URL,
};
use tokio::sync::{broadcast, mpsc, oneshot, watch, RwLock};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::trait_extensions::convert_to_contract_dto::IntoContractInterfaceType;
use {
    crate::tee::{
        monitor_allowed_image_hashes,
        remote_attestation::{
            monitor_attestation_removal, periodic_attestation_submission, submit_remote_attestation,
        },
        AllowedImageHashesFile,
    },
    mpc_contract::tee::proposal::MpcDockerImageHash,
    tracing::info,
};

pub const ATTESTATION_RESUBMISSION_INTERVAL: Duration = Duration::from_secs(10 * 60);

#[derive(Parser, Debug)]
#[command(name = "mpc-node")]
#[command(about = "MPC Node for Near Protocol")]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub struct Cli {
    #[arg(long, value_enum, env("MPC_LOG_FORMAT"), default_value = "plain")]
    pub log_format: LogFormat,
    #[clap(subcommand)]
    pub command: CliCommand,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum LogFormat {
    /// Plaintext logs
    Plain,
    /// JSON logs
    Json,
}

#[derive(Subcommand, Debug)]
pub enum CliCommand {
    Start(StartCmd),
    /// Generates/downloads required files for Near node to run
    Init(InitConfigArgs),
    /// Imports a keyshare from JSON and stores it in the local encrypted storage
    ImportKeyshare(ImportKeyshareCmd),
    /// Exports a keyshare from local encrypted storage and prints it to the console
    ExportKeyshare(ExportKeyshareCmd),
    /// Generates a set of test configurations suitable for running MPC in
    /// an integration test.
    GenerateTestConfigs {
        #[arg(long)]
        output_dir: String,
        #[arg(long, value_delimiter = ',', required = true)]
        /// Near signer account for each participant
        participants: Vec<AccountId>,
        /// Near responder account for each participant. Refer to `indexer/real.rs` for more details.
        #[arg(long, value_delimiter = ',')]
        responders: Vec<AccountId>,
        #[arg(long)]
        threshold: usize,
        #[arg(long, default_value = "65536")]
        desired_triples_to_buffer: usize,
        #[arg(long, default_value = "8192")]
        desired_presignatures_to_buffer: usize,
        #[arg(long, default_value = "1")]
        desired_responder_keys_per_participant: usize,
    },
}

#[derive(Args, Debug)]
pub struct InitConfigArgs {
    #[arg(long, env("MPC_HOME_DIR"))]
    pub dir: std::path::PathBuf,
    /// chain/network id (localnet, testnet, devnet, betanet)
    #[arg(long)]
    pub chain_id: Option<String>,
    /// Genesis file to use when initialize testnet (including downloading)
    #[arg(long)]
    pub genesis: Option<String>,
    /// Download the verified NEAR config file automatically.
    #[arg(long)]
    pub download_config: bool,
    #[arg(long)]
    pub download_config_url: Option<String>,
    /// Download the verified NEAR genesis file automatically.
    #[arg(long)]
    pub download_genesis: bool,
    /// Specify a custom download URL for the genesis-file.
    #[arg(long)]
    pub download_genesis_url: Option<String>,
    #[arg(long)]
    pub download_genesis_records_url: Option<String>,
    #[arg(long)]
    pub boot_nodes: Option<String>,
}

#[derive(Args, Debug)]
pub struct StartCmd {
    #[arg(long, env("MPC_HOME_DIR"))]
    pub home_dir: String,
    /// Hex-encoded 16 byte AES key for local storage encryption.
    /// This key should come from a secure secret storage.
    /// TODO(#444): After TEE integration decide on what to do with AES encryption key
    #[arg(env("MPC_SECRET_STORE_KEY"))]
    pub secret_store_key_hex: String,
    /// If provided, the root keyshare is stored on GCP.
    /// This requires GCP_PROJECT_ID to be set as well.
    #[arg(env("GCP_KEYSHARE_SECRET_ID"))]
    pub gcp_keyshare_secret_id: Option<String>,
    #[arg(env("GCP_PROJECT_ID"))]
    pub gcp_project_id: Option<String>,
    /// TEE authority config
    #[command(subcommand)]
    pub tee_authority: TeeAuthorityConfig,
    /// TEE related configuration settings.
    #[command(flatten)]
    pub image_hash_config: MpcImageHashConfig,
    /// Hex-encoded 32 byte AES key for backup encryption.
    #[arg(env("MPC_BACKUP_ENCRYPTION_KEY_HEX"))]
    pub backup_encryption_key_hex: String,
}

#[derive(Subcommand, Debug, Clone)]
pub enum TeeAuthorityConfig {
    Local,
    Dstack {
        #[arg(long, env("DSTACK_ENDPOINT"), default_value = DEFAULT_DSTACK_ENDPOINT)]
        dstack_endpoint: String,
        #[arg(long, env("QUOTE_UPLOAD_URL"), default_value = DEFAULT_PHALA_TDX_QUOTE_UPLOAD_URL)]
        quote_upload_url: Url,
    },
}

impl TryFrom<TeeAuthorityConfig> for TeeAuthority {
    type Error = anyhow::Error;

    fn try_from(cmd: TeeAuthorityConfig) -> Result<Self, Self::Error> {
        let authority_config = match cmd {
            TeeAuthorityConfig::Local => LocalTeeAuthorityConfig::default().into(),
            TeeAuthorityConfig::Dstack {
                dstack_endpoint,
                quote_upload_url,
            } => DstackTeeAuthorityConfig::new(dstack_endpoint, quote_upload_url).into(),
        };

        Ok(authority_config)
    }
}

#[derive(Args, Debug)]
pub struct MpcImageHashConfig {
    #[arg(
        long,
        env("MPC_IMAGE_HASH"),
        help_heading = "Hex representation of the hash of the image running. Only required if running in TEE."
    )]
    pub image_hash: Option<String>,
    #[arg(
        long,
        env("MPC_LATEST_ALLOWED_HASH_FILE"),
        help_heading = "Path to the file which the mpc node will write the latest allowed hash to. If not set, assumes running outside of TEE and skips image hash monitoring."
    )]
    pub latest_allowed_hash_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct ImportKeyshareCmd {
    /// Path to home directory
    #[arg(long, env("MPC_HOME_DIR"))]
    pub home_dir: String,

    /// JSON string containing the keyshare to import
    #[arg(
        help = "JSON string with the keyshare in format: {\"epoch\":1,\"private_share\":\"...\",\"public_key\":\"...\"}"
    )]
    pub keyshare_json: String,

    /// Hex-encoded 16 byte AES key for local storage encryption
    #[arg(help = "Hex-encoded 16 byte AES key for local storage encryption")]
    pub local_encryption_key_hex: String,
}

#[derive(Args, Debug)]
pub struct ExportKeyshareCmd {
    /// Path to home directory
    #[arg(long, env("MPC_HOME_DIR"))]
    pub home_dir: String,

    /// Hex-encoded 16 byte AES key for local storage encryption
    #[arg(help = "Hex-encoded 16 byte AES key for local storage encryption")]
    pub local_encryption_key_hex: String,
}

impl StartCmd {
    async fn run(self) -> anyhow::Result<()> {
        let root_runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()?;

        let _tokio_enter_guard = root_runtime.enter();

        // Load configuration and initialize persistent secrets
        let home_dir = PathBuf::from(self.home_dir.clone());
        let config = load_config_file(&home_dir)?;
        let persistent_secrets = PersistentSecrets::generate_or_get_existing(
            &home_dir,
            config.number_of_responder_keys,
        )?;

        // TODO (#1296)
        let respond_config = RespondConfig::from_parts(&config, &persistent_secrets);

        // Load secrets from configuration and persistent storage
        let secrets = SecretsConfig::from_parts(
            &self.secret_store_key_hex,
            persistent_secrets.clone(),
            &self.backup_encryption_key_hex.clone(),
        )?;

        // Generate attestation
        let tee_authority = TeeAuthority::try_from(self.tee_authority.clone())?;
        let tls_public_key = &secrets.persistent_secrets.p2p_private_key.verifying_key();

        let account_public_key = &secrets.persistent_secrets.near_signer_key.verifying_key();

        let report_data = ReportData::new(
            *tls_public_key.into_contract_interface_type().as_bytes(),
            *account_public_key.into_contract_interface_type().as_bytes(),
        );

        let attestation = tee_authority.generate_attestation(report_data).await?;

        // Create communication channels and runtime
        let (debug_request_sender, _) = tokio::sync::broadcast::channel(10);
        let root_task_handle = Arc::new(OnceLock::new());

        let (protocol_state_sender, protocol_state_receiver) =
            watch::channel(ProtocolContractState::NotInitialized);

        let (migration_state_sender, migration_state_receiver) =
            watch::channel((0, BTreeMap::new()));
        let web_server = root_runtime
            .block_on(start_web_server(
                root_task_handle.clone(),
                debug_request_sender.clone(),
                config.web_ui.clone(),
                static_web_data(&secrets, Some(attestation.clone())),
                protocol_state_receiver,
                migration_state_receiver,
            ))
            .context("Failed to create web server.")?;

        let _web_server_join_handle = root_runtime.spawn(web_server);

        // Create Indexer and wait for indexer to be synced.
        let (indexer_exit_sender, indexer_exit_receiver) = oneshot::channel();
        let indexer_api = spawn_real_indexer(
            home_dir.clone(),
            config.indexer.clone(),
            config.my_near_account_id.clone(),
            persistent_secrets.near_signer_key.clone(),
            respond_config,
            indexer_exit_sender,
            protocol_state_sender,
            migration_state_sender,
            *tls_public_key,
        );

        let (shutdown_signal_sender, mut shutdown_signal_receiver) = mpsc::channel(1);
        let cancellation_token = CancellationToken::new();

        let image_hash_watcher_handle = if let (Some(image_hash), Some(latest_allowed_hash_file)) = (
            &self.image_hash_config.image_hash,
            &self.image_hash_config.latest_allowed_hash_file,
        ) {
            let current_image_hash_bytes: [u8; 32] = hex::decode(image_hash)
                .expect("The currently running image is a hex string.")
                .try_into()
                .expect("The currently running image hash hex representation is 32 bytes.");

            let allowed_hashes_in_contract = indexer_api.allowed_docker_images_receiver.clone();
            let image_hash_storage = AllowedImageHashesFile::from(latest_allowed_hash_file.clone());

            Some(root_runtime.spawn(monitor_allowed_image_hashes(
                cancellation_token.child_token(),
                MpcDockerImageHash::from(current_image_hash_bytes),
                allowed_hashes_in_contract,
                image_hash_storage,
                shutdown_signal_sender,
            )))
        } else {
            tracing::info!(
                "MPC_IMAGE_HASH and/or MPC_LATEST_ALLOWED_HASH_FILE not set, skipping TEE image hash monitoring"
            );
            None
        };

        let root_future = self.create_root_future(
            home_dir.clone(),
            config.clone(),
            secrets.clone(),
            indexer_api,
            attestation,
            debug_request_sender,
            root_task_handle,
            tee_authority,
        );

        let root_task = root_runtime.spawn(start_root_task("root", root_future).0);

        let exit_reason = tokio::select! {
            root_task_result = root_task => {
                root_task_result?
            }
            indexer_exit_response = indexer_exit_receiver => {
                indexer_exit_response.context("Indexer thread dropped response channel.")?
            }
            Some(()) = shutdown_signal_receiver.recv() => {
                Err(anyhow!("TEE allowed image hashes watcher is sending shutdown signal."))
            }
        };

        // Perform graceful shutdown
        cancellation_token.cancel();

        if let Some(handle) = image_hash_watcher_handle {
            info!("Waiting for image hash watcher to gracefully exit.");
            let exit_result = handle.await;
            info!(?exit_result, "Image hash watcher exited.");
        }

        exit_reason
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_root_future(
        self,
        home_dir: PathBuf,
        config: ConfigFile,
        secrets: SecretsConfig,
        indexer_api: IndexerAPI<impl TransactionSender + 'static>,
        attestation: Attestation,
        debug_request_sender: broadcast::Sender<DebugRequest>,
        // Cloning a OnceLock returns a new cell, which is why we have to wrap it in an arc.
        // Otherwise we would not write to the same cell/lock.
        root_task_handle_once_lock: Arc<OnceLock<Arc<tracking::TaskHandle>>>,
        tee_authority: TeeAuthority,
    ) -> anyhow::Result<()> {
        let root_task_handle = tracking::current_task();

        root_task_handle_once_lock
            .set(root_task_handle.clone())
            .map_err(|_| anyhow!("Root task handle was already set"))?;

        let tls_public_key = secrets.persistent_secrets.p2p_private_key.verifying_key();
        let account_public_key = secrets.persistent_secrets.near_signer_key.verifying_key();

        let secret_db = SecretDB::new(&home_dir.join("assets"), secrets.local_storage_aes_key)?;

        let key_storage_config = KeyStorageConfig {
            home_dir: home_dir.clone(),
            local_encryption_key: secrets.local_storage_aes_key,
            gcp: if let Some(secret_id) = self.gcp_keyshare_secret_id {
                let project_id = self.gcp_project_id.ok_or_else(|| {
                    anyhow::anyhow!(
                        "GCP_PROJECT_ID must be specified to use GCP_KEYSHARE_SECRET_ID"
                    )
                })?;
                Some(GcpPermanentKeyStorageConfig {
                    project_id,
                    secret_id,
                })
            } else {
                None
            },
        };

        submit_remote_attestation(indexer_api.txn_sender.clone(), attestation, tls_public_key)
            .await?;

        // Spawn periodic attestation submission task
        let tx_sender_clone = indexer_api.txn_sender.clone();
        let tee_authority_clone = tee_authority.clone();
        tokio::spawn(async move {
            if let Err(e) = periodic_attestation_submission(
                tee_authority_clone,
                tx_sender_clone,
                tls_public_key,
                account_public_key,
                tokio::time::interval(ATTESTATION_RESUBMISSION_INTERVAL),
            )
            .await
            {
                tracing::error!(
                    error = ?e,
                    "periodic attestation submission task failed"
                );
            }
        });

        // Spawn TEE attestation monitoring task
        let tx_sender_clone = indexer_api.txn_sender.clone();
        let tee_accounts_receiver = indexer_api.attested_nodes_receiver.clone();
        let account_id_clone = config.my_near_account_id.clone();

        tokio::spawn(async move {
            if let Err(e) = monitor_attestation_removal(
                account_id_clone,
                tee_authority,
                tx_sender_clone,
                tls_public_key,
                account_public_key,
                tee_accounts_receiver,
            )
            .await
            {
                tracing::error!(
                    error = ?e,
                    "attestation removal monitoring task failed"
                );
            }
        });

        let keyshare_storage: Arc<RwLock<KeyshareStorage>> =
            RwLock::new(key_storage_config.create().await?).into();

        spawn_recovery_server_and_run_onboarding(
            config.migration_web_ui.clone(),
            (&secrets).into(),
            config.my_near_account_id.clone(),
            keyshare_storage.clone(),
            indexer_api.my_migration_info_receiver.clone(),
            indexer_api.contract_state_receiver.clone(),
            indexer_api.txn_sender.clone(),
        )
        .await?;

        let coordinator = Coordinator {
            clock: Clock::real(),
            config_file: config,
            secrets,
            secret_db,
            keyshare_storage,
            indexer: indexer_api,
            currently_running_job_name: Arc::new(Mutex::new(String::new())),
            debug_request_sender,
        };
        coordinator.run().await
    }
}

impl Cli {
    pub async fn run(self) -> anyhow::Result<()> {
        match self.command {
            CliCommand::Start(start) => start.run().await,
            CliCommand::Init(config) => {
                let (download_config_type, download_config_url) = if config.download_config {
                    (
                        Some(near_config_utils::DownloadConfigType::RPC),
                        config.download_config_url.as_ref().map(AsRef::as_ref),
                    )
                } else {
                    (None, None)
                };
                near_indexer::init_configs(
                    &config.dir,
                    config.chain_id,
                    None,
                    None,
                    1,
                    false,
                    config.genesis.as_ref().map(AsRef::as_ref),
                    config.download_genesis,
                    config.download_genesis_url.as_ref().map(AsRef::as_ref),
                    config
                        .download_genesis_records_url
                        .as_ref()
                        .map(AsRef::as_ref),
                    download_config_type,
                    download_config_url,
                    config.boot_nodes.as_ref().map(AsRef::as_ref),
                    None,
                )
            }
            CliCommand::ImportKeyshare(cmd) => cmd.run().await,
            CliCommand::ExportKeyshare(cmd) => cmd.run().await,
            CliCommand::GenerateTestConfigs {
                ref output_dir,
                ref participants,
                ref responders,
                threshold,
                desired_triples_to_buffer,
                desired_presignatures_to_buffer,
                desired_responder_keys_per_participant,
            } => {
                anyhow::ensure!(
                    participants.len() == responders.len(),
                    "Number of participants must match number of responders"
                );
                self.run_generate_test_configs(
                    output_dir,
                    participants,
                    responders,
                    threshold,
                    desired_triples_to_buffer,
                    desired_presignatures_to_buffer,
                    desired_responder_keys_per_participant,
                )
                .await
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_generate_test_configs(
        &self,
        output_dir: &str,
        participants: &[AccountId],
        responders: &[AccountId],
        threshold: usize,
        desired_triples_to_buffer: usize,
        desired_presignatures_to_buffer: usize,
        desired_responder_keys_per_participant: usize,
    ) -> anyhow::Result<()> {
        let p2p_key_pairs = participants
            .iter()
            .enumerate()
            .map(|(idx, _account_id)| {
                let subdir = PathBuf::from(output_dir).join(idx.to_string());
                PersistentSecrets::generate_or_get_existing(
                    &subdir,
                    desired_responder_keys_per_participant,
                )
                .map(|secret| secret.p2p_private_key)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let configs = generate_test_p2p_configs(
            participants,
            threshold,
            PortSeed::CLI_FOR_PYTEST,
            Some(p2p_key_pairs),
        )?;
        let participants_config = configs[0].0.participants.clone();
        for (i, (_config, _p2p_private_key)) in configs.into_iter().enumerate() {
            let subdir = format!("{}/{}", output_dir, i);
            std::fs::create_dir_all(&subdir)?;
            let file_config = self.create_file_config(
                &participants[i],
                &responders[i],
                i,
                desired_triples_to_buffer,
                desired_presignatures_to_buffer,
            )?;
            std::fs::write(
                format!("{}/config.yaml", subdir),
                serde_yaml::to_string(&file_config)?,
            )?;
        }
        std::fs::write(
            format!("{}/participants.json", output_dir),
            serde_json::to_string(&participants_config)?,
        )?;
        Ok(())
    }

    fn create_file_config(
        &self,
        participant: &AccountId,
        responder: &AccountId,
        index: usize,
        desired_triples_to_buffer: usize,
        desired_presignatures_to_buffer: usize,
    ) -> anyhow::Result<ConfigFile> {
        Ok(ConfigFile {
            my_near_account_id: participant.clone(),
            near_responder_account_id: responder.clone(),
            number_of_responder_keys: 1,
            web_ui: WebUIConfig {
                host: "127.0.0.1".to_owned(),
                port: PortSeed::CLI_FOR_PYTEST.web_port(index),
            },
            migration_web_ui: WebUIConfig {
                host: "127.0.0.1".to_owned(),
                port: PortSeed::CLI_FOR_PYTEST.migration_web_port(index),
            },
            indexer: IndexerConfig {
                validate_genesis: true,
                sync_mode: SyncMode::Block(BlockArgs { height: 0 }),
                concurrency: 1.try_into().unwrap(),
                mpc_contract_id: "test0".parse().unwrap(),
                finality: Finality::None,
                port_override: None,
            },
            triple: TripleConfig {
                concurrency: 2,
                desired_triples_to_buffer,
                timeout_sec: 60,
                parallel_triple_generation_stagger_time_sec: 1,
            },
            presignature: PresignatureConfig {
                concurrency: 2,
                desired_presignatures_to_buffer,
                timeout_sec: 60,
            },
            signature: SignatureConfig { timeout_sec: 60 },
            ckd: CKDConfig { timeout_sec: 60 },
            keygen: KeygenConfig { timeout_sec: 60 },
            cores: Some(4),
        })
    }
}

impl ImportKeyshareCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async {
            println!("Importing keyshare to local storage...");

            // Parse the encryption key
            let encryption_key_bytes = <[u8; 16]>::from_hex(&self.local_encryption_key_hex)
                .map_err(|_| {
                    anyhow::anyhow!("Invalid encryption key: must be 32 hex characters (16 bytes)")
                })?;

            let keyshare: PermanentKeyshareData = serde_json::from_str(&self.keyshare_json)
                .map_err(|e| anyhow::anyhow!("Failed to parse keyshare JSON: {}", e))?;

            println!("Parsed keyshare for epoch {}", keyshare.epoch_id);

            // Create the local storage and store the keyshare
            let home_dir = PathBuf::from(&self.home_dir);

            // Ensure the directory exists
            if !home_dir.exists() {
                std::fs::create_dir_all(&home_dir).map_err(|e| {
                    anyhow::anyhow!("Failed to create directory {}: {}", home_dir.display(), e)
                })?;
            }

            let storage =
                LocalPermanentKeyStorageBackend::new(home_dir.clone(), encryption_key_bytes)
                    .await?;

            // Check for existing keyshare
            if storage.load().await?.is_some() {
                anyhow::bail!("Refusing to overwrite existing local keyshare");
            }

            // Store the keyshare
            storage
                .store(&serde_json::to_vec(&keyshare)?, "imported")
                .await?;
            println!("Successfully imported keyshare to {}", home_dir.display());

            Ok(())
        })
    }
}

impl ExportKeyshareCmd {
    pub async fn run(&self) -> anyhow::Result<()> {
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async {
            println!("Exporting keyshare from local storage...");

            let encryption_key_bytes = <[u8; 16]>::from_hex(&self.local_encryption_key_hex)
                .map_err(|_| {
                    anyhow::anyhow!("Invalid encryption key: must be 32 hex characters (16 bytes)")
                })?;

            // Create the local storage
            let home_dir = PathBuf::from(&self.home_dir);

            // Check if directory exists
            if !home_dir.exists() {
                return Err(anyhow::anyhow!(
                    "Directory {} does not exist",
                    home_dir.display()
                ));
            }

            let storage = PermanentKeyStorage::new(Box::new(
                LocalPermanentKeyStorageBackend::new(home_dir.clone(), encryption_key_bytes)
                    .await?,
            ))
            .await?;

            // Load the keyshare
            let keyshare = storage
                .load()
                .await?
                .ok_or_else(|| anyhow::anyhow!("No keyshare found in {}", home_dir.display()))?;
            let keyshare = legacy_ecdsa_key_from_keyshares(&keyshare.keyshares)?;

            // Print the keyshare to console
            let json = serde_json::to_string_pretty(&keyshare)
                .map_err(|e| anyhow::anyhow!("Failed to serialize keyshare: {}", e))?;

            println!("{}", json);
            println!(
                "\nKeyshare for epoch {} successfully exported.",
                keyshare.epoch
            );

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyshare::permanent::LegacyRootKeyshareData;
    use k256::{AffinePoint, Scalar};
    use mpc_contract::primitives::key_state::EpochId;
    use tempfile::TempDir;

    // Mock keyshare data for testing
    fn create_test_keyshare() -> PermanentKeyshareData {
        // Create a dummy private key - this is only for testing
        let private_share = Scalar::ONE;
        // Do some computation to get non-identity public key
        let public_key = AffinePoint::GENERATOR * private_share;

        PermanentKeyshareData::from_legacy(&LegacyRootKeyshareData {
            epoch: 1,
            private_share,
            public_key: public_key.to_affine(),
        })
    }

    #[test]
    fn test_keyshare_import_export() {
        // Create a temporary directory for the test
        let temp_dir = TempDir::new().unwrap();
        let home_dir = temp_dir.path().to_string_lossy().to_string();

        // Create test data
        let keyshare = create_test_keyshare();
        let keyshare_json = serde_json::to_string(&keyshare).unwrap();
        let encryption_key = "0123456789ABCDEF0123456789ABCDEF";

        // Test import functionality
        let import_cmd = ImportKeyshareCmd {
            home_dir: home_dir.clone(),
            keyshare_json,
            local_encryption_key_hex: encryption_key.to_string(),
        };

        let result = futures::executor::block_on(import_cmd.run());
        assert!(result.is_ok(), "Import command failed: {:?}", result.err());

        // Test export functionality
        let export_cmd = ExportKeyshareCmd {
            home_dir: home_dir.clone(),
            local_encryption_key_hex: encryption_key.to_string(),
        };

        let result = futures::executor::block_on(export_cmd.run());
        assert!(result.is_ok(), "Export command failed: {:?}", result.err());

        // Verify the exported data matches what we imported
        // For a more thorough test, we could capture stdout and verify the JSON content
    }

    #[test]
    fn test_import_existing_keyshare_with_lower_epoch() {
        // Create a temporary directory for the test
        let temp_dir = TempDir::new().unwrap();
        let home_dir = temp_dir.path().to_string_lossy().to_string();

        // Create two keyshares with different epochs
        let mut keyshare1 = create_test_keyshare();
        keyshare1.epoch_id = EpochId::new(2); // Higher epoch

        let mut keyshare2 = create_test_keyshare();
        keyshare2.epoch_id = EpochId::new(1); // Lower epoch

        let keyshare1_json = serde_json::to_string(&keyshare1).unwrap();
        let keyshare2_json = serde_json::to_string(&keyshare2).unwrap();
        let encryption_key = "0123456789ABCDEF0123456789ABCDEF";

        // Import the first keyshare
        let import_cmd1 = ImportKeyshareCmd {
            home_dir: home_dir.clone(),
            keyshare_json: keyshare1_json,
            local_encryption_key_hex: encryption_key.to_string(),
        };

        let result = futures::executor::block_on(import_cmd1.run());
        assert!(
            result.is_ok(),
            "First import command failed: {:?}",
            result.err()
        );

        // Try to import the second keyshare with lower epoch
        let import_cmd2 = ImportKeyshareCmd {
            home_dir: home_dir.clone(),
            keyshare_json: keyshare2_json,
            local_encryption_key_hex: encryption_key.to_string(),
        };

        let result = futures::executor::block_on(import_cmd2.run());
        assert!(
            result.is_err(),
            "Import command with lower epoch should fail"
        );
    }

    #[test]
    fn test_export_nonexistent_keyshare() {
        // Create a temporary directory for the test
        let temp_dir = TempDir::new().unwrap();
        let home_dir = temp_dir.path().to_string_lossy().to_string();
        let encryption_key = "0123456789ABCDEF0123456789ABCDEF";

        // Parse the export command on an empty directory
        let export_cmd = ExportKeyshareCmd {
            home_dir,
            local_encryption_key_hex: encryption_key.to_string(),
        };

        let result = futures::executor::block_on(export_cmd.run());
        assert!(
            result.is_err(),
            "Export command should fail on nonexistent keyshare"
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No keyshare found"));
    }
}
