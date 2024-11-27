use crate::config::{
    load_config, ConfigFile, IndexerConfig, KeyGenerationConfig, PresignatureConfig,
    SignatureConfig, SyncMode, TripleConfig, WebUIConfig,
};
use crate::db::{DBCol, SecretDB};
use crate::indexer::configs::InitConfigArgs;
use crate::indexer::handler::listen_blocks;
use crate::indexer::stats::{indexer_logger, IndexerStats};
use crate::key_generation::KeygenStorage;
use crate::mpc_client::MpcClient;
use crate::network::{run_network_client, MeshNetworkTransportSender};
use crate::p2p::{generate_test_p2p_configs, new_quic_mesh_network};
use crate::sign::PresignatureStorage;
use crate::tracking;
use crate::triple::TripleStorage;
use crate::web::run_web_server;
use anyhow::Context;
use clap::Parser;
use std::num::NonZero;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Parser, Debug)]
pub enum Cli {
    Start {
        #[arg(long, env("MPC_HOME_DIR"))]
        home_dir: String,
        /// Hex-encoded 16 byte AES key for local storage encryption.
        /// TODO: What's the right way to pass in secrets?
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
                let secret_store_key =
                    hex::decode(&secret_store_key_hex).context("Secret store key invalid")?;
                let secret_store_key: &[u8; 16] = secret_store_key
                    .as_slice()
                    .try_into()
                    .context("Secret store key must be 16 bytes (32 bytes hex)")?;

                let config = load_config(Path::new(&home_dir), *secret_store_key)?;

                // Start the near indexer
                let indexer_handle = config.indexer.clone().map(|indexer_config| std::thread::spawn(move || {
                        actix::System::new().block_on(async {
                            let indexer = near_indexer::Indexer::new(
                                indexer_config.to_near_indexer_config(home_dir.into()),
                            )
                            .expect("Failed to initialize the Indexer");
                            let stream = indexer.streamer();
                            let view_client = indexer.client_actors().0;
                            let stats: Arc<Mutex<IndexerStats>> =
                                Arc::new(Mutex::new(IndexerStats::new()));

                            actix::spawn(indexer_logger(Arc::clone(&stats), view_client));
                            listen_blocks(stream, indexer_config.concurrency, Arc::clone(&stats))
                                .await;
                        });
                    }));

                // Start the mpc client
                let secret_db = SecretDB::new(
                    &config.secret_storage.data_dir,
                    config.secret_storage.aes_key,
                )?;

                let (root_task, _) = tracking::start_root_task(async move {
                    let root_task_handle = tracking::current_task();

                    let (sender, receiver) = new_quic_mesh_network(&config.mpc).await?;
                    // TODO(#44): Don't need to wait for all; wait for threshold?
                    sender
                        .wait_for_ready(config.mpc.participants.participants.len())
                        .await?;
                    let (network_client, channel_receiver) =
                        run_network_client(Arc::new(sender), Box::new(receiver));

                    let (keygen_store, keygen_needed) = KeygenStorage::new(secret_db.clone())?;
                    let triple_store = Arc::new(TripleStorage::new(
                        secret_db.clone(),
                        DBCol::Triple,
                        network_client.my_participant_id(),
                        network_client.all_participant_ids(),
                    )?);

                    let presignature_store = Arc::new(PresignatureStorage::new(
                        secret_db.clone(),
                        DBCol::Presignature,
                        network_client.my_participant_id(),
                        network_client.all_participant_ids(),
                    )?);

                    let config = Arc::new(config);
                    let mpc_client = MpcClient::new(
                        config.clone(),
                        network_client,
                        triple_store,
                        presignature_store,
                        keygen_store,
                    );

                    tracking::spawn_checked(
                        "web server",
                        run_web_server(root_task_handle, config.web_ui.clone(), mpc_client.clone()),
                    );
                    mpc_client
                        .clone()
                        .run(keygen_needed, channel_receiver)
                        .await?;
                    anyhow::Ok(())
                });

                root_task.await?;
                if let Some(h) = indexer_handle { h.join().unwrap() }

                Ok(())
            }
            Cli::GenerateTestConfigs {
                output_dir,
                num_participants,
                threshold,
            } => {
                let configs = generate_test_p2p_configs(num_participants, threshold)?;
                for (i, config) in configs.into_iter().enumerate() {
                    let subdir = format!("{}/{}", output_dir, i);
                    std::fs::create_dir_all(&subdir)?;
                    let file_config = ConfigFile {
                        my_participant_id: config.my_participant_id,
                        participants: config.participants,
                        p2p_private_key_file: "p2p.pem".to_owned(),
                        web_ui: WebUIConfig {
                            host: "127.0.0.1".to_owned(),
                            port: 20000 + i as u16,
                        },
                        indexer: Some(IndexerConfig {
                            stream_while_syncing: false,
                            validate_genesis: true,
                            sync_mode: SyncMode::SyncFromInterruption,
                            concurrency: NonZero::new(1).unwrap(),
                        }),
                        key_generation: KeyGenerationConfig { timeout_sec: 60 },
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
