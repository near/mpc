use crate::config::{load_config, ConfigFile, TripleConfig, WebUIConfig};
use crate::indexer::{indexer_logger, listen_blocks, IndexerStats};
use crate::mpc_client::run_mpc_client;
use crate::network::{run_network_client, MeshNetworkTransportSender};
use crate::p2p::{generate_test_p2p_configs, new_quic_mesh_network};
use crate::tracking;
use crate::web::run_web_server;
use clap::Parser;
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
}

impl Cli {
    pub async fn run(self) -> anyhow::Result<()> {
        match self {
            Cli::Start { home_dir } => {
                let config = load_config(Path::new(&home_dir))?;

                // Start the mpc client
                let (root_task, _) = tracking::start_root_task(async move {
                    let root_task_handle = tracking::current_task();
                    tracking::spawn(
                        "web server",
                        run_web_server(root_task_handle, config.web_ui),
                    );
                    let (sender, receiver) = new_quic_mesh_network(&config.mpc).await?;
                    sender.wait_for_ready().await?;
                    let (network_client, channel_receiver) =
                        run_network_client(Arc::new(sender), Box::new(receiver));
                    run_mpc_client(
                        config.mpc.into(),
                        config.triple.into(),
                        network_client,
                        channel_receiver,
                    )
                    .await?;
                    anyhow::Ok(())
                });
                root_task.await?;

                // Start the near indexer
                if let Some(indexer_config) = config.indexer {
                    let system = actix::System::new();
                    system.block_on(async move {
                        let indexer = near_indexer::Indexer::new(
                            indexer_config.to_indexer_config(home_dir.into()),
                        )
                        .expect("Failed to initialize the Indexer");
                        let stream = indexer.streamer();
                        let view_client = indexer.client_actors().0;

                        let stats: Arc<Mutex<IndexerStats>> =
                            Arc::new(Mutex::new(IndexerStats::new()));

                        actix::spawn(indexer_logger(Arc::clone(&stats), view_client));

                        listen_blocks(stream, indexer_config.concurrency, Arc::clone(&stats)).await;

                        actix::System::current().stop();
                    });
                    system.run().unwrap();
                }

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
                        triple: TripleConfig { concurrency: 4 },
                        indexer: None,
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
        }
    }
}
