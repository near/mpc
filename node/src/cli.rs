use crate::config::{
    load_config_file, ConfigFile, IndexerConfig, PresignatureConfig, SignatureConfig, SyncMode,
    TripleConfig, WebUIConfig,
};
use crate::config::{BlockArgs, MpcConfig, SecretsConfig};
use crate::db::{DBCol, SecretDB};
use crate::indexer::handler::listen_blocks;
use crate::indexer::participants::read_participants_from_chain;
use crate::indexer::response::handle_sign_responses;
use crate::indexer::stats::{indexer_logger, IndexerStats};
use crate::indexer::transaction::TransactionSigner;
use crate::indexer::IndexerState;
use crate::key_generation::{
    affine_point_to_public_key, load_root_keyshare, run_key_generation_client,
};
use crate::mpc_client::MpcClient;
use crate::network::{run_network_client, MeshNetworkTransportSender};
use crate::p2p::{generate_test_p2p_configs, new_tls_mesh_network};
use crate::sign::PresignatureStorage;
use crate::sign_request::SignRequestStorage;
use crate::tracking;
use crate::triple::TripleStorage;
#[cfg(not(test))]
use crate::web::start_web_server;
#[cfg(test)]
use crate::web_test::start_web_server_testing;
use clap::ArgAction;
use clap::Parser;
use near_crypto::SecretKey;
use near_indexer_primitives::types::{AccountId, Finality};
use std::num::NonZero;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::thread::JoinHandle;
use tokio::sync::mpsc;
use tokio::sync::{Mutex, Notify, OnceCell};

#[derive(Parser, Debug)]
pub enum Cli {
    /// Runs the node in normal operating mode. A root keyshare must already
    /// exist on disk.
    Start {
        #[arg(long, env("MPC_HOME_DIR"))]
        home_dir: String,
        /// Hex-encoded 16 byte AES key for local storage encryption.
        /// This key should come from a secure secret storage.
        #[arg(env("MPC_SECRET_STORE_KEY"))]
        secret_store_key_hex: String,
        /// Root keyshare, if this is being passed in rather than loaded from disk.
        /// This should be used if the root keyshare is being stored with a secret
        /// manager (such as Google Secret Manager) instead of encrypted on disk.
        /// A bash script should be used to first read the root keyshare from the
        /// secret manager, and then pass it in via this argument.
        /// The root keyshare should be passed in as a JSON string.
        #[arg(env("MPC_ROOT_KEYSHARE"))]
        root_keyshare: Option<String>,
        /// p2p private key for TLS. It must be in the format of "ed25519:...".
        #[arg(env("MPC_P2P_PRIVATE_KEY"))]
        p2p_private_key: SecretKey,
        /// Near account secret key. Signing transactions will only be posted to the
        /// contract if this is specified.
        #[arg(env("MPC_ACCOUNT_SK"))]
        account_secret_key: Option<SecretKey>,
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
        /// p2p private key for TLS. It must be in the format of "ed25519:...".
        #[arg(env("MPC_P2P_PRIVATE_KEY"))]
        p2p_private_key: SecretKey,
    },
    /// Generates/downloads required files for Near node to run
    Init(InitConfigArgs),
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

/// Helper struct to cancel threads.
/// When dropped, this struct calls .notify_one() on cancel and .join() on handle
/// Dropping this struct is blocking until .join() resolves.
pub struct Handle<T> {
    pub handle: Option<JoinHandle<T>>,
    pub cancel: Arc<Notify>,
}

impl<T> Handle<T> {
    pub fn cancel(&self) {
        self.cancel.notify_one();
    }
}

impl<T> Drop for Handle<T> {
    fn drop(&mut self) {
        self.cancel();
        if let Some(join_handle) = self.handle.take() {
            if let Err(e) = join_handle.join() {
                tracing::info!("mpc thread panicked: {:?}", e);
            }
        }
    }
}

pub struct StartResponse {
    pub mpc_handle: Handle<Result<(), anyhow::Error>>,
    pub indexer_handle: Option<JoinHandle<()>>,
}

impl Cli {
    pub fn run(self) -> anyhow::Result<Option<StartResponse>> {
        match self {
            Cli::Start {
                home_dir,
                secret_store_key_hex,
                root_keyshare,
                p2p_private_key,
                account_secret_key,
            } => {
                let home_dir = PathBuf::from(home_dir);
                let secrets = SecretsConfig::from_cli(&secret_store_key_hex, p2p_private_key)?;
                let config = ConfigFile::from_file(&home_dir.join("config.yaml"))?;
                let root_keyshare =
                    load_root_keyshare(&home_dir, secrets.local_storage_aes_key, &root_keyshare)?;

                let (chain_config_sender, mut chain_config_receiver) = mpsc::channel(10);
                let (sign_request_sender, sign_request_receiver) = mpsc::channel(10000);
                let (sign_response_sender, sign_response_receiver) = mpsc::channel(10000);

                // Start the near indexer
                let indexer_handle = config.indexer.clone().map(|indexer_config| {
                    let config = config.clone();
                    let home_dir = home_dir.clone();
                    std::thread::spawn(move || {
                        // todo: replace actix with tokio
                        actix::System::new().block_on(async {
                            let transaction_signer =
                                account_secret_key.clone().map(|account_secret_key| {
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
                            let stats: Arc<Mutex<IndexerStats>> =
                                Arc::new(Mutex::new(IndexerStats::new()));

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

                let cancel_mpc = Arc::new(Notify::new());
                let cancel_mpc_clone = cancel_mpc.clone();
                let n_threads = config.cores;
                let mpc_handle = std::thread::spawn(move || {
                    let rt = if let Some(n_threads) = n_threads {
                        tokio::runtime::Builder::new_multi_thread()
                            .worker_threads(std::cmp::max(n_threads, 1))
                            .enable_all()
                            .build()
                    } else {
                        tokio::runtime::Runtime::new()
                    }
                    .unwrap();

                    // Replace participants in config with those listed in the smart contract state
                    let participants = if config.indexer.is_some() {
                        let Some(chain_config) =
                            rt.block_on(async { chain_config_receiver.recv().await })
                        else {
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

                    rt.block_on(async move {
                        let (root_task, _) = tracking::start_root_task(async move {
                            let _root_task_handle = tracking::current_task();
                            let mpc_client_cell = Arc::new(OnceCell::new());
                            #[cfg(test)]
                            let _web_server_handle = tracking::spawn(
                                "web server",
                                start_web_server_testing(
                                    _root_task_handle,
                                    config.web_ui.clone(),
                                    Some(mpc_client_cell.clone()),
                                )
                                .await?,
                            );
                            #[cfg(not(test))]
                            let _web_server_handle = tracking::spawn(
                                "web server",
                                start_web_server(config.web_ui.clone()).await?,
                            );

                            let (sender, receiver) =
                                new_tls_mesh_network(&config.mpc, &config.secrets.p2p_private_key)
                                    .await?;
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

                            let sign_request_store =
                                Arc::new(SignRequestStorage::new(secret_db.clone())?);

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
                        tokio::select! {
                            x = root_task => {x}
                            _ = cancel_mpc_clone.notified() => {
                                    Ok(())
                            }
                        }
                    })
                });

                let mpc_handle = Handle {
                    handle: Some(mpc_handle),
                    cancel: cancel_mpc,
                };
                Ok(Some(StartResponse {
                    indexer_handle,
                    mpc_handle,
                }))
            }
            Cli::GenerateKey {
                home_dir,
                secret_store_key_hex,
                p2p_private_key,
            } => {
                let secrets = SecretsConfig::from_cli(&secret_store_key_hex, p2p_private_key)?;
                let config = load_config_file(Path::new(&home_dir))?;
                // TODO(#75): Support reading from smart contract state here as well.
                let mpc_config = MpcConfig::from_participants_with_near_account_id(
                    config
                        .participants
                        .clone()
                        .expect("Static participants config required"),
                    &config.my_near_account_id,
                )?;
                let config = config.into_full_config(mpc_config, secrets);
                let rt = tokio::runtime::Runtime::new()?;
                rt.block_on(async {
                    let (root_task, _) = tracking::start_root_task(async move {
                        let _root_task_handle = tracking::current_task();
                        #[cfg(test)]
                        let _web_server_handle = tracking::spawn_checked(
                            "web server",
                            start_web_server_testing(
                                _root_task_handle,
                                config.web_ui.clone(),
                                None,
                            )
                            .await?,
                        );

                        #[cfg(not(test))]
                        let _web_server_handle = tracking::spawn_checked(
                            "web server",
                            start_web_server(config.web_ui.clone()).await?,
                        );
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
                            PathBuf::from(home_dir),
                            config.into(),
                            network_client,
                            channel_receiver,
                        )
                        .await?;
                        anyhow::Ok(())
                    });
                    root_task.await
                })?;
                Ok(None)
            }
            Cli::Init(config) => {
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
                        .donwload_genesis_records_url
                        .as_ref()
                        .map(AsRef::as_ref),
                    Some(near_config_utils::DownloadConfigType::RPC),
                    config.download_config_url.as_ref().map(AsRef::as_ref),
                    None,
                    None,
                )?;
                Ok(None)
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
                Ok(None)
            } // Cli::GenerateIndexerConfigs(config) => {
              //     // TODO: there is some weird serialization issue which causes configs to be written
              //     // with human-readable ByteSizes (e.g. '40.0 MB' instead of 40000000), which neard
              //     // cannot parse.
              //     near_indexer::indexer_init_configs(&config.home_dir.clone().into(), config.into())?;
              //     Ok(None)
              // }
        }
    }
}
