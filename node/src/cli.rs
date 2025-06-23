use crate::config::{PersistentSecrets, RespondConfig};
use crate::web::StaticWebData;
use crate::{
    config::{
        load_config_file, BlockArgs, ConfigFile, IndexerConfig, KeygenConfig, PresignatureConfig,
        SecretsConfig, SignatureConfig, SyncMode, TripleConfig, WebUIConfig,
    },
    coordinator::Coordinator,
    db::SecretDB,
    indexer::{real::spawn_real_indexer, IndexerAPI},
    keyshare::{
        compat::legacy_ecdsa_key_from_keyshares,
        local::LocalPermanentKeyStorageBackend,
        permanent::{PermanentKeyStorage, PermanentKeyStorageBackend, PermanentKeyshareData},
        GcpPermanentKeyStorageConfig, KeyStorageConfig,
    },
    p2p::testing::{generate_test_p2p_configs, PortSeed},
    tracking::{self, start_root_task},
    web::start_web_server,
};
use anyhow::{anyhow, Context};
use clap::Parser;
use hex::FromHex;
use mpc_contract::state::ProtocolContractState;
use mpc_contract::tee::tee_participant::TeeParticipantInfo;
use near_indexer_primitives::types::Finality;
use near_sdk::AccountId;
use near_time::Clock;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

#[cfg(feature = "tee")]
use {
    crate::tee::{
        monitor_allowed_image_hashes, remote_attestation::create_remote_attestation_info,
        remote_attestation::submit_remote_attestation, AllowedImageHashesFile,
    },
    mpc_contract::tee::proposal::MpcDockerImageHash,
    tracing::info,
};

#[derive(Parser, Debug)]
pub enum Cli {
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
        #[arg(long, value_delimiter = ',')]
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

#[derive(Parser, Debug)]
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
    pub donwload_genesis_records_url: Option<String>,
}

#[derive(Parser, Debug)]
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
    /// TEE related configuration settings.
    #[command(flatten)]
    #[cfg(feature = "tee")]
    pub tee_config: TeeConfig,
}

#[derive(Parser, Debug)]
#[cfg(feature = "tee")]
pub struct TeeConfig {
    #[arg(
        long,
        env("IMAGE_HASH"),
        help_heading = "hex representation of the hash of the image running."
    )]
    pub image_hash: String,
    #[arg(
        long,
        env("LATEST_ALLOWED_HASH_FILE"),
        help_heading = "Path to the file which the mpc node will write the latest allowed hash to."
    )]
    pub latest_allowed_hash_file: PathBuf,
}

#[derive(Parser, Debug)]
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

#[derive(Parser, Debug)]
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
        let home_dir = PathBuf::from(self.home_dir.clone());

        let config = load_config_file(&home_dir)?;
        let persistent_secrets = PersistentSecrets::generate_or_get_existing(
            &home_dir,
            config.number_of_responder_keys,
        )?;
        let respond_config = RespondConfig::from_parts(&config, &persistent_secrets);

        let (web_contract_sender, web_contract_receiver) =
            tokio::sync::watch::channel(ProtocolContractState::NotInitialized);

        let (indexer_exit_sender, indexer_exit_receiver) = oneshot::channel();
        let indexer_api = spawn_real_indexer(
            home_dir.clone(),
            config.indexer.clone(),
            config.my_near_account_id.clone(),
            persistent_secrets.near_signer_key.clone(),
            respond_config,
            web_contract_sender,
            indexer_exit_sender,
        );

        let root_runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()?;

        // Currently, we only trigger graceful shutdowns from TEE logic,
        // hence we need to disable the `unused_variables` lint when TEE is disabled.
        #[cfg_attr(not(feature = "tee"), allow(unused_variables))]
        let (shutdown_signal_sender, mut shutdown_signal_receiver) = mpsc::channel(1);
        let cancellation_token = CancellationToken::new();

        #[cfg(feature = "tee")]
        let image_hash_watcher_handle = {
            let current_image_hash_bytes: [u8; 32] = hex::decode(self.tee_config.image_hash)
                .expect("The currently running image is a hex string.")
                .try_into()
                .expect("The currently running image hash hex representation is 32 bytes.");

            let allowed_hashes_in_contract = indexer_api.allowed_docker_images_receiver.clone();
            let image_hash_storage =
                AllowedImageHashesFile::new(self.tee_config.latest_allowed_hash_file).await?;

            tokio::spawn(monitor_allowed_image_hashes(
                cancellation_token.child_token(),
                MpcDockerImageHash::from(current_image_hash_bytes),
                allowed_hashes_in_contract,
                image_hash_storage,
                shutdown_signal_sender,
            ))
        };

        let secrets = SecretsConfig::from_parts(&self.secret_store_key_hex, persistent_secrets)?;
        let root_future = Self::create_root_future(
            home_dir.clone(),
            config.clone(),
            secrets.clone(),
            indexer_api,
            self.gcp_keyshare_secret_id.clone(),
            self.gcp_project_id.clone(),
            web_contract_receiver,
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

        #[cfg(feature = "tee")]
        {
            info!("Waiting for image hash watcher to gracefully exit.");
            let exit_result = image_hash_watcher_handle.await;
            info!(?exit_result, "Image hash watcher exited.");
        }

        exit_reason
    }

    async fn create_root_future(
        home_dir: PathBuf,
        config: ConfigFile,
        secrets: SecretsConfig,
        indexer_api: IndexerAPI,
        gcp_keyshare_secret_id: Option<String>,
        gcp_project_id: Option<String>,
        web_contract_receiver: tokio::sync::watch::Receiver<ProtocolContractState>,
    ) -> anyhow::Result<()> {
        let root_task_handle = tracking::current_task();

        let (signature_debug_request_sender, _) = tokio::sync::broadcast::channel(10);

        #[allow(unused_mut, unused_assignments)]
        let mut report_data_contract: Option<TeeParticipantInfo> = None;
        #[cfg(feature = "tee")]
        {
            let tls_public_key = secrets.persistent_secrets.p2p_private_key.public_key();
            let account_public_key = secrets.persistent_secrets.near_signer_key.public_key();
            // create remote attestation:
            let report_data =
                create_remote_attestation_info(&tls_public_key, &account_public_key).await;
            //let report_data_contract: TeeParticipantInfo = report_data.try_into()?;
            report_data_contract = Some(report_data.try_into()?);
        }
        let web_server = start_web_server(
            root_task_handle,
            signature_debug_request_sender.clone(),
            config.web_ui.clone(),
            StaticWebData::new(&secrets, report_data_contract.clone()),
            web_contract_receiver,
        )
        .await?;
        let _web_server = tracking::spawn_checked("web server", web_server);

        let secret_db = SecretDB::new(&home_dir.join("assets"), secrets.local_storage_aes_key)?;

        let key_storage_config = KeyStorageConfig {
            home_dir: home_dir.clone(),
            local_encryption_key: secrets.local_storage_aes_key,
            gcp: if let Some(secret_id) = gcp_keyshare_secret_id {
                let project_id = gcp_project_id.ok_or_else(|| {
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

        // submit remote attestation
        #[cfg(feature = "tee")]
        {
            let account_public_key = secrets.persistent_secrets.near_signer_key.public_key();

            submit_remote_attestation(
                indexer_api.txn_sender.clone(),
                report_data_contract.unwrap(),
                account_public_key,
            )
            .await?;
        }

        let coordinator = Coordinator {
            clock: Clock::real(),
            config_file: config,
            secrets,
            secret_db,
            key_storage_config,
            indexer: indexer_api,
            currently_running_job_name: Arc::new(Mutex::new(String::new())),
            signature_debug_request_sender,
        };
        coordinator.run().await
    }
}

impl Cli {
    pub async fn run(self) -> anyhow::Result<()> {
        match self {
            Cli::Start(start) => start.run().await,
            Cli::Init(config) => near_indexer::init_configs(
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
                    .donwload_genesis_records_url
                    .as_ref()
                    .map(AsRef::as_ref),
                Some(near_config_utils::DownloadConfigType::RPC),
                config.download_config_url.as_ref().map(AsRef::as_ref),
                None,
                None,
            ),
            Cli::ImportKeyshare(cmd) => cmd.run().await,
            Cli::ExportKeyshare(cmd) => cmd.run().await,
            Cli::GenerateTestConfigs {
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
                .map(|secret| {
                    (
                        secret.p2p_private_key.unwrap_as_ed25519().clone(),
                        secret
                            .p2p_private_key
                            .public_key()
                            .unwrap_as_ed25519()
                            .clone(),
                    )
                })
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
