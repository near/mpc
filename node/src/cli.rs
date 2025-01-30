use crate::config::{
    load_config_file, BlockArgs, KeygenConfig, PresignatureConfig, SecretsConfig, SignatureConfig,
    SyncMode, TripleConfig, WebUIConfig,
};
use crate::config::{ConfigFile, IndexerConfig};
use crate::coordinator::Coordinator;
use crate::db::SecretDB;
use crate::indexer::real::spawn_real_indexer;
use crate::keyshare::KeyshareStorageFactory;
use crate::p2p::testing::{generate_test_p2p_configs, PortSeed};
use crate::tracking::{self, start_root_task};
use crate::web::start_web_server;
use clap::Parser;
use near_crypto::SecretKey;
use near_indexer_primitives::types::Finality;
use near_sdk::AccountId;
use near_time::Clock;
use std::path::PathBuf;

#[derive(Parser, Debug)]
pub enum Cli {
    Start(StartCmd),

    /// Generates a set of test configurations suitable for running MPC in
    /// an integration test.
    GenerateTestConfigs {
        #[arg(long)]
        output_dir: String,
        #[arg(long, value_delimiter = ',')]
        participants: Vec<AccountId>,
        #[arg(long)]
        threshold: usize,
    },
}

#[derive(Parser, Debug)]
pub struct StartCmd {
    #[arg(long, env("MPC_HOME_DIR"))]
    pub home_dir: String,
    /// Hex-encoded 16 byte AES key for local storage encryption.
    /// This key should come from a secure secret storage.
    #[arg(env("MPC_SECRET_STORE_KEY"))]
    pub secret_store_key_hex: String,
    /// If provided, the root keyshare is stored on GCP.
    /// This requires GCP_PROJECT_ID to be set as well.
    #[arg(env("GCP_KEYSHARE_SECRET_ID"))]
    pub gcp_keyshare_secret_id: Option<String>,
    #[arg(env("GCP_PROJECT_ID"))]
    pub gcp_project_id: Option<String>,
    /// p2p private key for TLS. It must be in the format of "ed25519:...".
    #[arg(env("MPC_P2P_PRIVATE_KEY"))]
    pub p2p_private_key: SecretKey,
    /// Near account secret key. Must correspond to the my_near_account_id
    /// specified in the config.
    #[arg(env("MPC_ACCOUNT_SK"))]
    pub account_secret_key: SecretKey,
}

impl StartCmd {
    async fn run(self) -> anyhow::Result<()> {
        let home_dir = PathBuf::from(self.home_dir);
        let secrets = SecretsConfig::from_cli(&self.secret_store_key_hex, self.p2p_private_key)?;
        let config = load_config_file(&home_dir)?;

        let (indexer_handle, indexer_api) = spawn_real_indexer(
            home_dir.clone(),
            config.indexer.clone(),
            config.my_near_account_id.clone(),
            self.account_secret_key.clone(),
        );

        let root_future = async move {
            let root_task_handle = tracking::current_task();
            let web_server = start_web_server(root_task_handle, config.web_ui.clone()).await?;
            let _web_server = tracking::spawn_checked("web server", web_server);

            let secret_db = SecretDB::new(&home_dir, secrets.local_storage_aes_key)?;

            let keyshare_storage_factory = if let Some(secret_id) = self.gcp_keyshare_secret_id {
                let Some(project_id) = self.gcp_project_id else {
                    anyhow::bail!("GCP_PROJECT_ID must be specified to use GCP_KEYSHARE_SECRET_ID");
                };
                KeyshareStorageFactory::Gcp {
                    project_id,
                    secret_id,
                }
            } else {
                KeyshareStorageFactory::Local {
                    home_dir: home_dir.clone(),
                    encryption_key: secrets.local_storage_aes_key,
                }
            };

            let coordinator = Coordinator {
                clock: Clock::real(),
                config_file: config,
                secrets,
                secret_db,
                keyshare_storage_factory,
                indexer: indexer_api,
            };
            coordinator.run().await
        };

        // Spawn a one-thread runtime to run the coordinator.
        // TODO(#156): we shouldn't actually need to do this, but for now we
        // do because there is also an std::thread we need to join.
        let root_runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()?;

        let root_task = root_runtime.spawn(start_root_task(root_future).0);
        // TODO(#156): It is not ideal to perform a blocking join here.
        indexer_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Indexer thread panicked!"))?;
        root_task.await??;
        Ok(())
    }
}

impl Cli {
    pub async fn run(self) -> anyhow::Result<()> {
        match self {
            Cli::Start(start) => start.run().await,
            Cli::GenerateTestConfigs {
                output_dir,
                participants,
                threshold,
            } => {
                let configs =
                    generate_test_p2p_configs(&participants, threshold, PortSeed::CLI_FOR_PYTEST)?;
                let participants_config = configs[0].0.participants.clone();
                for (i, (_, p2p_private_key)) in configs.into_iter().enumerate() {
                    let subdir = format!("{}/{}", output_dir, i);
                    std::fs::create_dir_all(&subdir)?;
                    let file_config = ConfigFile {
                        my_near_account_id: participants[i].clone(),
                        web_ui: WebUIConfig {
                            host: "127.0.0.1".to_owned(),
                            port: 21000 + i as u16,
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
                            desired_triples_to_buffer: 65536,
                            timeout_sec: 60,
                            parallel_triple_generation_stagger_time_sec: 1,
                        },
                        presignature: PresignatureConfig {
                            concurrency: 2,
                            desired_presignatures_to_buffer: 8192,
                            timeout_sec: 60,
                        },
                        signature: SignatureConfig { timeout_sec: 60 },
                        keygen: KeygenConfig { timeout_sec: 60 },
                        cores: Some(4),
                    };
                    std::fs::write(
                        format!("{}/p2p_key", subdir),
                        SecretKey::ED25519(p2p_private_key).to_string(),
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
        }
    }
}
