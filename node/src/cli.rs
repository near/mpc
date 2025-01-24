use crate::config::{
    load_config_file, ConfigFile, IndexerConfig, PresignatureConfig, SignatureConfig, SyncMode,
    TripleConfig, WebUIConfig,
};
use crate::config::{BlockArgs, MpcConfig, SecretsConfig};
use crate::db::{DBCol, SecretDB};
use crate::indexer::configs::InitConfigArgs;
use crate::indexer::handler::listen_blocks;
use crate::indexer::participants::read_participants_from_chain;
use crate::indexer::response::handle_sign_responses;
use crate::indexer::stats::{indexer_logger, IndexerStats};
use crate::indexer::transaction::TransactionSigner;
use crate::indexer::IndexerState;
use crate::key_generation::{affine_point_to_public_key, run_key_generation_client};
use crate::keyshare::gcp::GcpKeyshareStorage;
use crate::keyshare::local::LocalKeyshareStorage;
use crate::keyshare::KeyshareStorage;
use crate::mpc_client::MpcClient;
use crate::network::{run_network_client, MeshNetworkTransportSender};
use crate::p2p::{generate_test_p2p_configs, new_tls_mesh_network};
use crate::primitives::HasParticipants;
use crate::sign::PresignatureStorage;
use crate::sign_request::SignRequestStorage;
use crate::tracking::{self, AutoAbortTask};
use crate::triple::TripleStorage;
#[cfg(not(test))]
use crate::web::start_web_server;
#[cfg(test)]
use crate::web_test::start_web_server_testing;
use clap::ArgAction;
use clap::Parser;
use near_crypto::SecretKey;
use near_indexer_primitives::types::{AccountId, Finality};
use near_time::Clock;
use std::num::NonZero;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::thread::JoinHandle;
use tokio::sync::mpsc;
use tokio::sync::{Mutex, OnceCell};

#[derive(Parser, Debug)]
pub enum Cli {
    /// Runs the node in normal operating mode. A root keyshare must already
    /// exist on disk.
    Start(StartCmd),
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
        /// p2p private key for TLS. It must be in the format of "ed25519:...".
        #[arg(env("MPC_P2P_PRIVATE_KEY"))]
        p2p_private_key: SecretKey,
    },
    /// Generates a set of test configurations suitable for running MPC in
    /// an integration test.
    GenerateTestConfigs {
        #[arg(long)]
        output_dir: String,
        #[arg(long, value_delimiter = ',')]
        participants: Vec<AccountId>,
        #[arg(long)]
        threshold: usize,
        #[arg(long)]
        seed: Option<u16>,
        #[arg(long, action = ArgAction::SetTrue)]
        disable_indexer: bool,
    },
    GenerateIndexerConfigs(InitConfigArgs),
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

/// Tokio Runtime cannot be dropped in an asynchronous context (for good reason).
/// However, we need to be able to drop it in two scenarios:
///  - Integration tests, where we want to start up and shut down the CLI
///    multiple times.
///  - When the contract transitions in and out of the Running state (such as
///    for key resharing), we need to tear down the existing tasks (including
///    network) and restart with a new configuration. We need to ensure that
///    all existing tasks have terminated before starting the new configuration.
///    The only way to do that reliably is by dropping the runtime. If we cannot
///    drop the runtime in an async context, we'd have to rely on std::thread,
///    but that itself is difficult to deal with (mostly that we cannot easily
///    abort it and would have to rely on additional notifications).
///
/// Yes, this is an ugly workaround. But in our use case, the async task that
/// would be dropping a runtime is always on a thread that blocks on that task
/// and that task only.
struct AsyncDroppableRuntime(Option<tokio::runtime::Runtime>);

impl AsyncDroppableRuntime {
    fn new(runtime: tokio::runtime::Runtime) -> Self {
        Self(Some(runtime))
    }
}

impl Deref for AsyncDroppableRuntime {
    type Target = tokio::runtime::Runtime;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().unwrap()
    }
}

impl Drop for AsyncDroppableRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            std::thread::scope(|s| {
                s.spawn(|| drop(runtime));
            });
        }
    }
}

async fn make_keyshare_storage(
    home_dir: PathBuf,
    local_encryption_key: [u8; 16],
    secret_id: Option<String>,
    project_id: Option<String>,
) -> anyhow::Result<Box<dyn KeyshareStorage>> {
    match (secret_id, project_id) {
        (Some(secret_id), Some(project_id)) => {
            let storage = GcpKeyshareStorage::new(project_id, secret_id).await?;
            Ok(Box::new(storage))
        }
        (None, None) => {
            let storage = LocalKeyshareStorage::new(home_dir, local_encryption_key);
            Ok(Box::new(storage))
        }
        _ => {
            anyhow::bail!(
                "Both GCP_SECRET_ID and GCP_PROJECT_ID must be set to use GCP secrets storage"
            );
        }
    }
}

struct StartResponse {
    _mpc_runtime: AsyncDroppableRuntime,
    mpc_task: AutoAbortTask<Result<(), anyhow::Error>>,
    indexer_handle: Option<JoinHandle<()>>,
}

impl StartCmd {
    fn run(self) -> anyhow::Result<StartResponse> {
        let home_dir = PathBuf::from(self.home_dir);
        let secrets = SecretsConfig::from_cli(&self.secret_store_key_hex, self.p2p_private_key)?;
        let config = ConfigFile::from_file(&home_dir.join("config.yaml"))?;

        let (chain_config_sender, mut chain_config_receiver) = mpsc::channel(10);
        let (sign_request_sender, sign_request_receiver) = mpsc::channel(10000);
        let (sign_response_sender, sign_response_receiver) = mpsc::channel(10000);

        // Start the near indexer
        let account_secret_key = self.account_secret_key;
        let indexer_handle = config.indexer.clone().map(|indexer_config| {
            let config = config.clone();
            let home_dir = home_dir.clone();
            std::thread::spawn(move || {
                // todo: replace actix with tokio
                actix::System::new().block_on(async {
                    let transaction_signer = account_secret_key.clone().map(|account_secret_key| {
                        Arc::new(TransactionSigner::from_key(
                            config.my_near_account_id.clone(),
                            account_secret_key,
                        ))
                    });
                    let indexer = near_indexer::Indexer::new(
                        indexer_config.to_near_indexer_config(home_dir.clone()),
                    )
                    .expect("Failed to initialize the Indexer");
                    let stream = indexer.streamer();
                    let (view_client, client) = indexer.client_actors();
                    let indexer_state = Arc::new(IndexerState::new(
                        view_client.clone(),
                        client.clone(),
                        indexer_config.mpc_contract_id.clone(),
                    ));
                    // TODO: migrate this into IndexerState
                    let stats: Arc<Mutex<IndexerStats>> = Arc::new(Mutex::new(IndexerStats::new()));

                    actix::spawn(read_participants_from_chain(
                        indexer_config.mpc_contract_id.clone(),
                        indexer_config.port_override,
                        view_client.clone(),
                        client.clone(),
                        chain_config_sender,
                    ));
                    actix::spawn(indexer_logger(Arc::clone(&stats), view_client.clone()));
                    actix::spawn(handle_sign_responses(
                        sign_response_receiver,
                        transaction_signer,
                        indexer_state.clone(),
                    ));
                    listen_blocks(
                        stream,
                        indexer_config.concurrency,
                        Arc::clone(&stats),
                        indexer_config.mpc_contract_id,
                        account_secret_key.map(|key| key.public_key()),
                        sign_request_sender,
                        indexer_state,
                    )
                    .await;
                });
            })
        });

        // Have the MPC tasks be on a separate runtime for two reasons:
        //  - so that we can limit the number of cores used for MPC tasks,
        //    in order to avoid starving the indexer, causing it to fall behind.
        //  - so that we can shut down the MPC tasks without shutting down the
        //    indexer, in order to process key generation or resharing.
        let mpc_runtime = if let Some(n_threads) = config.cores {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(std::cmp::max(n_threads, 1))
                .enable_all()
                .build()?
        } else {
            tokio::runtime::Runtime::new()?
        };
        let mpc_runtime = AsyncDroppableRuntime::new(mpc_runtime);

        let root_mpc_future = async move {
            let root_task_handle = tracking::current_task();

            // Before doing anything, start the web server so we expose metrics and debug info.
            let mpc_client_cell = Arc::new(OnceCell::new());
            #[cfg(test)]
            let web_server = start_web_server_testing(
                root_task_handle,
                config.web_ui.clone(),
                Some(mpc_client_cell.clone()),
            )
            .await?;
            #[cfg(not(test))]
            let web_server = start_web_server(root_task_handle, config.web_ui.clone()).await?;
            let _web_server_handle = tracking::spawn("web server", web_server);

            let keyshare_storage = make_keyshare_storage(
                home_dir.clone(),
                secrets.local_storage_aes_key,
                self.gcp_keyshare_secret_id,
                self.gcp_project_id,
            )
            .await?;
            let root_keyshare = keyshare_storage
                .load()
                .await?
                .ok_or_else(|| anyhow::anyhow!("Root keyshare not found"))?;

            // Replace participants in config with those listed in the smart contract state
            let participants = if config.indexer.is_some() {
                let Some(chain_config) = chain_config_receiver.recv().await else {
                    anyhow::bail!("Participant sender dropped by indexer");
                };
                let chain_config = chain_config?;
                tracing::info!(target: "mpc", "read chain config {:?} from chain", chain_config);
                let public_key_from_keyshare =
                    affine_point_to_public_key(root_keyshare.public_key)?;
                if chain_config.root_public_key != public_key_from_keyshare {
                    anyhow::bail!(
                        "Root public key mismatch: {:?} != {:?}",
                        chain_config.root_public_key,
                        public_key_from_keyshare
                    );
                }
                chain_config.participants
            } else {
                let Some(participants) = config.participants.clone() else {
                    anyhow::bail!("Participants must either be read from on chain or specified statically in the config");
                };
                participants
            };

            let mpc_config = MpcConfig::from_participants_with_near_account_id(
                participants,
                &config.my_near_account_id,
            )?;

            let config = config.into_full_config(mpc_config, secrets);

            // Start the mpc client
            let secret_db = SecretDB::new(
                &home_dir.join("mpc-data"),
                config.secrets.local_storage_aes_key,
            )?;

            let (sender, receiver) =
                new_tls_mesh_network(&config.mpc, &config.secrets.p2p_private_key).await?;
            sender
                .wait_for_ready(config.mpc.participants.threshold as usize)
                .await?;
            let (network_client, channel_receiver, _handle) =
                run_network_client(Arc::new(sender), Box::new(receiver));

            let active_participants_query = {
                let network_client = network_client.clone();
                Arc::new(move || network_client.all_alive_participant_ids())
            };

            let triple_store = Arc::new(TripleStorage::new(
                Clock::real(),
                secret_db.clone(),
                DBCol::Triple,
                network_client.my_participant_id(),
                |participants, pair| pair.is_subset_of_active_participants(participants),
                active_participants_query.clone(),
            )?);

            let presignature_store = Arc::new(PresignatureStorage::new(
                Clock::real(),
                secret_db.clone(),
                DBCol::Presignature,
                network_client.my_participant_id(),
                |participants, presignature| {
                    presignature.is_subset_of_active_participants(participants)
                },
                active_participants_query,
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
        };
        let mpc_task = AutoAbortTask::from(mpc_runtime.spawn(async move {
            let (root_task, _) = tracking::start_root_task(root_mpc_future);
            root_task.await
        }));

        Ok(StartResponse {
            _mpc_runtime: mpc_runtime,
            mpc_task,
            indexer_handle,
        })
    }
}

impl Cli {
    pub async fn run(self) -> anyhow::Result<()> {
        match self {
            Cli::Start(start) => {
                let start_response = start.run()?;
                if let Some(indexer_handle) = start_response.indexer_handle {
                    indexer_handle
                        .join()
                        .map_err(|_| anyhow::anyhow!("Indexer thread panicked!"))?;
                }
                start_response.mpc_task.await??;
                Ok(())
            }
            Cli::GenerateKey {
                home_dir,
                secret_store_key_hex,
                p2p_private_key,
            } => {
                let secrets = SecretsConfig::from_cli(&secret_store_key_hex, p2p_private_key)?;
                let config = load_config_file(Path::new(&home_dir))?;
                // TODO(#43) this will be refactored to be part of the Start command. For now,
                // allow the code to be duplicated.
                let mpc_runtime = if let Some(n_threads) = config.cores {
                    tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(std::cmp::max(n_threads, 1))
                        .enable_all()
                        .build()?
                } else {
                    tokio::runtime::Runtime::new()?
                };
                let mpc_runtime = AsyncDroppableRuntime::new(mpc_runtime);
                // TODO(#75): Support reading from smart contract state here as well.
                let mpc_config = MpcConfig::from_participants_with_near_account_id(
                    config
                        .participants
                        .clone()
                        .expect("Static participants config required"),
                    &config.my_near_account_id,
                )?;
                let config = config.into_full_config(mpc_config, secrets);

                mpc_runtime
                    .spawn(async move {
                        let (root_task, _) = tracking::start_root_task(async move {
                            let root_task_handle = tracking::current_task();

                            #[cfg(test)]
                            let web_server = start_web_server_testing(
                                root_task_handle,
                                config.web_ui.clone(),
                                None,
                            )
                            .await?;
                            #[cfg(not(test))]
                            let web_server =
                                start_web_server(root_task_handle, config.web_ui.clone()).await?;
                            let _web_server_handle = tracking::spawn("web server", web_server);

                            let (sender, receiver) =
                                new_tls_mesh_network(&config.mpc, &config.secrets.p2p_private_key)
                                    .await?;
                            // Must wait for all participants to be ready before starting key generation.
                            sender
                                .wait_for_ready(config.mpc.participants.participants.len())
                                .await?;
                            let (network_client, channel_receiver, _handle) =
                                run_network_client(Arc::new(sender), Box::new(receiver));
                            run_key_generation_client(
                                config.mpc.clone().into(),
                                network_client,
                                Box::new(LocalKeyshareStorage::new(
                                    PathBuf::from(home_dir),
                                    config.secrets.local_storage_aes_key,
                                )),
                                channel_receiver,
                            )
                            .await?;
                            anyhow::Ok(())
                        });
                        root_task.await
                    })
                    .await??;
                Ok(())
            }
            Cli::GenerateTestConfigs {
                output_dir,
                participants,
                threshold,
                seed,
                disable_indexer,
            } => {
                let configs =
                    generate_test_p2p_configs(&participants, threshold, seed.unwrap_or_default())?;
                for (i, (mpc_config, p2p_private_key)) in configs.into_iter().enumerate() {
                    let subdir = format!("{}/{}", output_dir, i);
                    std::fs::create_dir_all(&subdir)?;
                    let file_config = ConfigFile {
                        my_near_account_id: participants[i].clone(),
                        participants: Some(mpc_config.participants),
                        web_ui: WebUIConfig {
                            host: "127.0.0.1".to_owned(),
                            port: 20000 + 1000 * seed.unwrap_or_default() + i as u16,
                        },
                        indexer: if disable_indexer {
                            None
                        } else {
                            Some(IndexerConfig {
                                validate_genesis: true,
                                sync_mode: SyncMode::Block(BlockArgs { height: 0 }),
                                concurrency: NonZero::new(1).unwrap(),
                                mpc_contract_id: AccountId::from_str("test0").unwrap(),
                                finality: Finality::None,
                                port_override: None,
                            })
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
                        cores: Some(15),
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
