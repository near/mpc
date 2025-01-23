use crate::config::ConfigFile;
use crate::config::SecretsConfig;
use crate::coordinator::Coordinator;
use crate::db::SecretDB;
use crate::indexer::real::spawn_real_indexer;
use crate::keyshare::KeyshareStorageFactory;
use crate::tracking::{self, start_root_task};
use crate::web::start_web_server;
use clap::Parser;
use near_crypto::SecretKey;
use near_time::Clock;
use std::path::PathBuf;

#[derive(Parser, Debug)]
pub enum Cli {
    Start(StartCmd),
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
    /// Near account secret key. Signing transactions will only be posted to the
    /// contract if this is specified.
    #[arg(env("MPC_ACCOUNT_SK"))]
    pub account_secret_key: Option<SecretKey>,
}

impl StartCmd {
    async fn run(self) -> anyhow::Result<()> {
        let home_dir = PathBuf::from(self.home_dir);
        let secrets = SecretsConfig::from_cli(&self.secret_store_key_hex, self.p2p_private_key)?;
        let config = ConfigFile::from_file(&home_dir.join("config.yaml"))?;

        // Start the near indexer
        let (indexer_handle, indexer_api) = spawn_real_indexer(
            home_dir.clone(),
            config.indexer.clone(),
            config.my_near_account_id.clone(),
            self.account_secret_key.clone(),
        );

        let root_future = async move {
            let root_task_handle = tracking::current_task();
            let _web_server = start_web_server(root_task_handle, config.web_ui.clone()).await?;

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

        let root_runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()?;

        let root_task = root_runtime.spawn(start_root_task(root_future).0);
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
        }
    }
}
