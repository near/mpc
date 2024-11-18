use crate::config::{load_config, ConfigFile, IndexerConfig, SyncMode, TripleConfig, WebUIConfig};
use crate::indexer::configs::InitConfigArgs;
use crate::indexer::handler::listen_blocks;
use crate::indexer::stats::{indexer_logger, IndexerStats};
use crate::mpc_client::MpcClient;
use crate::network::{run_network_client, MeshNetworkTransportSender};
use crate::p2p::{generate_test_p2p_configs, new_quic_mesh_network};
use crate::sign::SimplePresignatureStore;
use crate::tracking;
use crate::triple::SimpleTripleStore;
use crate::web::run_web_server;
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
            Cli::Start { home_dir } => {
                let config = load_config(Path::new(&home_dir))?;

                // Start the near indexer
                let indexer_handle = if let Some(indexer_config) = config.indexer {
                    Some(std::thread::spawn(move || {
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
                    }))
                } else {
                    None
                };

                // Start the mpc client
                let (root_task, _) = tracking::start_root_task(async move {
                    let root_task_handle = tracking::current_task();

                    let (sender, receiver) = new_quic_mesh_network(&config.mpc).await?;
                    sender.wait_for_ready().await?;
                    let (network_client, channel_receiver) =
                        run_network_client(Arc::new(sender), Box::new(receiver));

                    let mpc_client = MpcClient::new(
                        config.mpc.into(),
                        config.triple.into(),
                        network_client,
                        Arc::new(SimpleTripleStore::new()),
                        Arc::new(SimplePresignatureStore::new()),
                        Arc::new(tokio::sync::OnceCell::new()),
                    );

                    tracking::spawn_checked(
                        "web server",
                        run_web_server(root_task_handle, config.web_ui, mpc_client.clone()),
                    );
                    mpc_client.clone().run(channel_receiver).await?;
                    anyhow::Ok(())
                });

                root_task.await?;
                indexer_handle.map(|h| h.join().unwrap());

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
                        triple: TripleConfig {
                            concurrency: 4,
                            desired_triples_to_buffer: 65536,
                        },
                        indexer: Some(IndexerConfig {
                            stream_while_syncing: false,
                            validate_genesis: true,
                            sync_mode: SyncMode::SyncFromInterruption,
                            concurrency: NonZero::new(1).unwrap(),
                        }),
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
