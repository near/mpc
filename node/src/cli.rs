use crate::config::{
    load_config, ConfigFile, IndexerConfig, PresignatureConfig, SignatureConfig, SyncMode,
    TripleConfig, WebUIConfig,
};
use crate::db::{DBCol, SecretDB};
use crate::indexer::configs::InitConfigArgs;
use crate::indexer::handler::listen_blocks;
use crate::indexer::response::chain_sender;
use crate::indexer::response::load_near_credentials;
use crate::indexer::stats::{indexer_logger, IndexerStats};
use crate::key_generation::{load_root_keyshare, run_key_generation_client};
use crate::mpc_client::MpcClient;
use crate::network::{run_network_client, MeshNetworkTransportSender};
use crate::p2p::{generate_test_p2p_configs, new_quic_mesh_network};
use crate::sign::PresignatureStorage;
use crate::sign_request::SignRequestStorage;
use crate::tracking;
use crate::triple::TripleStorage;
use crate::web::start_web_server;
use anyhow::Context;
use clap::Parser;
use near_indexer_primitives::types::AccountId;
use std::num::NonZero;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::{Mutex, OnceCell};

#[derive(Parser, Debug)]
pub enum Cli {
    /// Runs the node in normal operating mode. A root keyshare must already
    /// exist on disk.
    Start {
        #[arg(long, env("MPC_HOME_DIR"))]
        home_dir: String,
        /// Hex-encoded 16 byte AES key for local storage encryption.
        /// TODO: What's the right way to pass in secrets?
        #[arg(env("MPC_SECRET_STORE_KEY"))]
        secret_store_key_hex: String,
    },
    /// Generates the root keyshare. This will only succeed if all participants
    /// run this command together, as in, every node will wait for the full set
    /// of participants before generating.
    ///
    /// This command will fail if there is an existing root keyshare on disk.
    GenerateKey {
        #[arg(long, env("MPC_HOME_DIR"))]
        home_dir: String,
        #[arg(env("MPC_SECRET_STORE_KEY"))]
        secret_store_key_hex: String,
    },
    /// Generates a set of test configurations suitable for running MPC in
    /// an integration test.
    GenerateTestConfigs {
        #[arg(long)]
        output_dir: String,
        #[arg(long)]
        num_participants: usize,
        #[arg(long)]
        threshold: usize,
        #[arg(long)]
        seed: Option<u16>,
    },
    GenerateIndexerConfigs(InitConfigArgs),
}

impl Cli {
    pub async fn run(self) -> anyhow::Result<()> {
        match self {
            Cli::Start {
                home_dir,
                secret_store_key_hex,
            } => {
                let secret_store_key = parse_encryption_key(&secret_store_key_hex)?;
                let config = load_config(Path::new(&home_dir), secret_store_key)?;
                let root_keyshare = load_root_keyshare(Path::new(&home_dir), secret_store_key)?;

                let (sign_request_sender, sign_request_receiver) = mpsc::channel(10000);
                let (sign_response_sender, sign_response_receiver) = mpsc::channel(10000);

                // Start the near indexer
                let indexer_handle = config.indexer.clone().map(|indexer_config| {
                    std::thread::spawn(move || {
                        actix::System::new().block_on(async {
                            let near_credentials = load_near_credentials(
                                Path::new(&home_dir),
                                indexer_config.near_credentials_file.clone(),
                            )
                            .expect("Failed to load near credentials");
                            let indexer = near_indexer::Indexer::new(
                                indexer_config.to_near_indexer_config(home_dir.into()),
                            )
                            .expect("Failed to initialize the Indexer");
                            let stream = indexer.streamer();
                            let (view_client, client) = indexer.client_actors();
                            let stats: Arc<Mutex<IndexerStats>> =
                                Arc::new(Mutex::new(IndexerStats::new()));

                            actix::spawn(indexer_logger(Arc::clone(&stats), view_client));
                            actix::spawn(chain_sender(
                                near_credentials,
                                indexer_config.mpc_contract_id.clone(),
                                sign_response_receiver,
                                client,
                            ));
                            listen_blocks(
                                stream,
                                indexer_config.concurrency,
                                Arc::clone(&stats),
                                indexer_config.mpc_contract_id,
                                Arc::new(sign_request_sender),
                            )
                            .await;
                        });
                    })
                });

                // Start the mpc client
                let secret_db = SecretDB::new(
                    &config.secret_storage.data_dir,
                    config.secret_storage.aes_key,
                )?;

                let (root_task, _) = tracking::start_root_task(async move {
                    let root_task_handle = tracking::current_task();

                    let mpc_client_cell = Arc::new(OnceCell::new());
                    let _web_server_handle = tracking::spawn(
                        "web server",
                        start_web_server(
                            root_task_handle,
                            config.web_ui.clone(),
                            Some(mpc_client_cell.clone()),
                        )
                        .await?,
                    );

                    let (sender, receiver) = new_quic_mesh_network(&config.mpc).await?;
                    sender
                        .wait_for_ready(config.mpc.participants.threshold as usize)
                        .await?;
                    let (network_client, channel_receiver, _handle) =
                        run_network_client(Arc::new(sender), Box::new(receiver));

                    let triple_store = Arc::new(TripleStorage::new(
                        secret_db.clone(),
                        DBCol::Triple,
                        network_client.my_participant_id(),
                        &network_client.all_participant_ids(),
                    )?);

                    let presignature_store = Arc::new(PresignatureStorage::new(
                        secret_db.clone(),
                        DBCol::Presignature,
                        network_client.my_participant_id(),
                        &network_client.all_participant_ids(),
                    )?);

                    let sign_request_store = Arc::new(SignRequestStorage::new(secret_db.clone())?);

                    let config = Arc::new(config);
                    let mpc_client = MpcClient::new(
                        config.clone(),
                        network_client,
                        triple_store,
                        presignature_store,
                        sign_request_store,
                        root_keyshare,
                    );
                    mpc_client_cell
                        .set(mpc_client.clone())
                        .map_err(|_| ())
                        .unwrap();
                    mpc_client
                        .clone()
                        .run(
                            channel_receiver,
                            sign_request_receiver,
                            sign_response_sender,
                        )
                        .await?;

                    anyhow::Ok(())
                });

                root_task.await?;
                if let Some(indexer_handle) = indexer_handle {
                    indexer_handle
                        .join()
                        .map_err(|_| anyhow::anyhow!("Indexer thread panicked"))?;
                }

                Ok(())
            }
            Cli::GenerateKey {
                home_dir,
                secret_store_key_hex,
            } => {
                let encryption_key = parse_encryption_key(&secret_store_key_hex)?;
                let config = load_config(Path::new(&home_dir), encryption_key)?;
                let (root_task, _) = tracking::start_root_task(async move {
                    let root_task_handle = tracking::current_task();
                    let _web_server_handle = tracking::spawn_checked(
                        "web server",
                        start_web_server(root_task_handle, config.web_ui.clone(), None).await?,
                    );

                    let (sender, receiver) = new_quic_mesh_network(&config.mpc).await?;
                    // Must wait for all participants to be ready before starting key generation.
                    sender
                        .wait_for_ready(config.mpc.participants.participants.len())
                        .await?;
                    let (network_client, channel_receiver, _handle) =
                        run_network_client(Arc::new(sender), Box::new(receiver));
                    run_key_generation_client(
                        PathBuf::from(home_dir),
                        config.into(),
                        network_client,
                        channel_receiver,
                    )
                    .await?;
                    anyhow::Ok(())
                });
                root_task.await?;
                Ok(())
            }
            Cli::GenerateTestConfigs {
                output_dir,
                num_participants,
                threshold,
                seed,
            } => {
                let configs = generate_test_p2p_configs(
                    num_participants,
                    threshold,
                    seed.unwrap_or_default(),
                )?;
                for (i, config) in configs.into_iter().enumerate() {
                    let subdir = format!("{}/{}", output_dir, i);
                    std::fs::create_dir_all(&subdir)?;
                    let file_config = ConfigFile {
                        my_participant_id: config.my_participant_id,
                        participants: config.participants,
                        p2p_private_key_file: "p2p.pem".to_owned(),
                        web_ui: WebUIConfig {
                            host: "127.0.0.1".to_owned(),
                            port: 20000 + 1000 * seed.unwrap_or_default() + i as u16,
                        },
                        indexer: Some(IndexerConfig {
                            stream_while_syncing: false,
                            validate_genesis: true,
                            sync_mode: SyncMode::Interruption,
                            concurrency: NonZero::new(1).unwrap(),
                            mpc_contract_id: AccountId::from_str("test0").unwrap(),
                            near_credentials_file: "node_key.json".to_owned(),
                        }),
                        triple: TripleConfig {
                            concurrency: 4,
                            desired_triples_to_buffer: 65536,
                            timeout_sec: 60,
                            parallel_triple_generation_stagger_time_sec: 1,
                        },
                        presignature: PresignatureConfig {
                            concurrency: 16,
                            desired_presignatures_to_buffer: 8192,
                            timeout_sec: 60,
                        },
                        signature: SignatureConfig { timeout_sec: 60 },
                    };
                    std::fs::write(
                        format!("{}/p2p.pem", subdir),
                        &config.secrets.p2p_private_key,
                    )?;
                    std::fs::write(
                        format!("{}/config.yaml", subdir),
                        serde_yaml::to_string(&file_config)?,
                    )?;
                }
                Ok(())
            }
            Cli::GenerateIndexerConfigs(config) => {
                // TODO: there is some weird serialization issue which causes configs to be written
                // with human-readable ByteSizes (e.g. '40.0 MB' instead of 40000000), which neard
                // cannot parse.
                near_indexer::indexer_init_configs(&config.home_dir.clone().into(), config.into())?;
                Ok(())
            }
        }
    }
}

/// Parses a hex-encoded 16-byte AES encryption key.
fn parse_encryption_key(s: &str) -> anyhow::Result<[u8; 16]> {
    let key = hex::decode(s).context("Encryption key must be 32 hex characters")?;
    let key: [u8; 16] = key
        .as_slice()
        .try_into()
        .context("Encryption key must be 16 bytes (32 bytes hex)")?;
    Ok(key)
}
