use crate::config::{ConfigFile, MpcConfig, SecretsConfig};
use crate::db::{DBCol, SecretDB};
use crate::indexer::handler::ChainSignatureRequest;
use crate::indexer::participants::{
    ConfigFromChain, InitializingConfigFromChain, ResharingConfigFromChain, RunningConfigFromChain,
};
use crate::indexer::response::{ChainSendTransactionRequest, ChainVotePkArgs};
use crate::indexer::IndexerAPI;
use crate::key_generation::{affine_point_to_public_key, run_key_generation_client};
use crate::keyshare::{KeyshareStorage, KeyshareStorageFactory};
use crate::mpc_client::MpcClient;
use crate::network::{run_network_client, MeshNetworkTransportSender};
use crate::p2p::new_tls_mesh_network;
use crate::primitives::HasParticipants;
use crate::runtime::AsyncDroppableRuntime;
use crate::sign::PresignatureStorage;
use crate::sign_request::SignRequestStorage;
use crate::tracking::{self};
use crate::triple::TripleStorage;
use futures::future::BoxFuture;
use futures::FutureExt;
use near_time::{Clock, Duration};
use std::future::Future;
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct Coordinator {
    pub clock: Clock,
    pub secrets: SecretsConfig,
    pub config_file: ConfigFile,

    /// Storage for triples, presignatures, signing requests.
    pub secret_db: Arc<SecretDB>,
    /// Storage for keyshare.
    pub keyshare_storage_factory: KeyshareStorageFactory,

    /// For interaction with the indexer.
    pub indexer: IndexerAPI,
}

impl Coordinator {
    pub async fn run(mut self) -> anyhow::Result<()> {
        loop {
            let config = self.indexer.contract_state_receiver.borrow().clone();
            let (name, mut fut, stop_fn, mut timeout_fut): (
                &'static str,
                BoxFuture<'static, anyhow::Result<()>>,
                Box<dyn Fn(&ConfigFromChain) -> bool + Send>,
                BoxFuture<'static, ()>,
            ) = match config {
                ConfigFromChain::WaitingForSync => {
                    tracing::info!("Waiting for sync");
                    (
                        "WaitingForSync",
                        futures::future::pending().boxed(),
                        Box::new(|_| true),
                        futures::future::pending().boxed(),
                    )
                }
                ConfigFromChain::Invalid => {
                    tracing::error!("Invalid config from chain, waiting for change");
                    (
                        "Invalid",
                        futures::future::pending().boxed(),
                        Box::new(|_| true),
                        futures::future::pending().boxed(),
                    )
                }
                ConfigFromChain::Initializing(config) => {
                    tracing::info!(
                        "Contract is initializing, performing key generation and voting"
                    );
                    (
                        "Initializing",
                        Self::create_runtime_and_run(
                            "Initializing",
                            self.config_file.cores,
                            Self::run_initialization(
                                self.clock.clone(),
                                self.secrets.clone(),
                                self.config_file.clone(),
                                self.keyshare_storage_factory.create().await?,
                                config.clone(),
                                self.indexer.txn_sender.clone(),
                            ),
                        )?,
                        Box::new(move |new_config| match new_config {
                            ConfigFromChain::Initializing(new_config) => {
                                new_config.participants != config.participants
                            }
                            _ => true,
                        }),
                        sleep(
                            &self.clock,
                            Duration::seconds(self.config_file.keygen.timeout_sec as i64),
                        ),
                    )
                }
                ConfigFromChain::Running(config) => {
                    tracing::info!("Contract is in running state, running MPC node normally");
                    (
                        "Running",
                        Self::create_runtime_and_run(
                            "Running",
                            self.config_file.cores,
                            Self::run_mpc(
                                self.clock.clone(),
                                self.secret_db.clone(),
                                self.secrets.clone(),
                                self.config_file.clone(),
                                self.keyshare_storage_factory.create().await?,
                                config.clone(),
                                self.indexer.txn_sender.clone(),
                                self.indexer
                                    .sign_request_receiver
                                    .clone()
                                    .lock_owned()
                                    .await,
                            ),
                        )?,
                        Box::new(move |new_config| match new_config {
                            ConfigFromChain::Running(new_config) => {
                                new_config.epoch != config.epoch
                            }
                            _ => true,
                        }),
                        futures::future::pending().boxed(),
                    )
                }
                ConfigFromChain::Resharing(config) => {
                    tracing::info!("Contract is in resharing state, running resharing protocol");
                    (
                        "Resharing",
                        Self::create_runtime_and_run(
                            "Resharing",
                            self.config_file.cores,
                            Self::run_key_resharing(
                                self.clock.clone(),
                                self.secret_db.clone(),
                                self.secrets.clone(),
                                self.config_file.clone(),
                                self.keyshare_storage_factory.create().await?,
                                config.clone(),
                                self.indexer.txn_sender.clone(),
                            ),
                        )?,
                        Box::new(move |new_config| match new_config {
                            ConfigFromChain::Resharing(new_config) => {
                                new_config.old_epoch != config.old_epoch
                                    || new_config.new_participants != config.new_participants
                            }
                            _ => true,
                        }),
                        sleep(
                            &self.clock,
                            Duration::seconds(self.config_file.keygen.timeout_sec as i64),
                        ),
                    )
                }
            };
            loop {
                tokio::select! {
                    res = &mut fut => {
                        if let Err(e) = res {
                            tracing::error!("[{}] failed: {:?}", name, e);
                        } else {
                            tracing::info!("[{}] finished successfully", name);
                        }
                    }
                    _ = self.indexer.contract_state_receiver.changed() => {
                        if stop_fn(&self.indexer.contract_state_receiver.borrow()) {
                            tracing::info!("[{}] config changed incompatibility, stopping", name);
                            break;
                        }
                    }
                    _ = &mut timeout_fut => {
                        tracing::error!("[{}] timed out, stopping", name);
                        break;
                    }
                }
            }
        }
    }

    fn create_runtime_and_run(
        description: &str,
        cores: Option<usize>,
        task: impl Future<Output = anyhow::Result<()>> + Send + 'static,
    ) -> anyhow::Result<BoxFuture<'static, anyhow::Result<()>>> {
        let task_handle = tracking::current_task();

        // Have the MPC tasks be on a separate runtime for two reasons:
        //  - so that we can limit the number of cores used for MPC tasks,
        //    in order to avoid starving the indexer, causing it to fall behind.
        //  - so that we can shut down the MPC tasks without shutting down the
        //    indexer, in order to process key generation or resharing.
        let mpc_runtime = if let Some(n_threads) = cores {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(std::cmp::max(n_threads, 1))
                .enable_all()
                .build()?
        } else {
            tokio::runtime::Runtime::new()?
        };
        let mpc_runtime = AsyncDroppableRuntime::new(mpc_runtime);
        let fut = mpc_runtime.spawn(task_handle.scope(description, task));
        Ok(async move {
            let _mpc_runtime = mpc_runtime;
            anyhow::Ok(fut.await??)
        }
        .boxed())
    }

    async fn run_initialization(
        clock: Clock,
        secrets: SecretsConfig,
        config_file: ConfigFile,
        keyshare_storage: Box<dyn KeyshareStorage>,
        contract_config: InitializingConfigFromChain,
        chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
    ) -> anyhow::Result<()> {
        let existing_key = keyshare_storage.load().await?;
        if let Some(existing_key) = existing_key {
            if existing_key.epoch != 0 {
                anyhow::bail!(
                    "Contract is in initialization state. We already have a keyshare, but its epoch is not zero. Refusing to participate in initialization"
                );
            }

            let my_public_key = affine_point_to_public_key(existing_key.public_key)?;
            if let Some(votes) = contract_config.pk_votes.get(&my_public_key) {
                if votes.contains(&config_file.my_near_account_id) {
                    tracing::info!("Initialization: we already voted for our public key; waiting for public key consensus");
                    // Wait; we'll keep trying to run initialization until the consensus is reached on the public key.
                    clock.sleep(Duration::seconds(1)).await;
                    return Ok(());
                }
            }

            tracing::info!("Contract is in initialization state. We have our keyshare. Sending vote_pk to vote for our public key");

            chain_txn_sender
                .send(ChainSendTransactionRequest::VotePk(ChainVotePkArgs {
                    public_key: my_public_key,
                }))
                .await?;
            // Give it plenty of time for the vote transaction to be processed.
            // Don't sleep too little, or else we'd just be voting again and again
            // wastefully.
            clock.sleep(Duration::seconds(5)).await;
            return Ok(());
        }

        let mpc_config = MpcConfig::from_participants_with_near_account_id(
            contract_config.participants,
            &config_file.my_near_account_id,
        )?;
        let (sender, receiver) =
            new_tls_mesh_network(&mpc_config, &secrets.p2p_private_key).await?;

        // Must wait for all participants to be ready before starting key generation.
        sender
            .wait_for_ready(mpc_config.participants.participants.len())
            .await?;
        let (network_client, channel_receiver, _handle) =
            run_network_client(Arc::new(sender), Box::new(receiver));
        run_key_generation_client(
            mpc_config.clone().into(),
            network_client,
            keyshare_storage,
            channel_receiver,
        )
        .await?;
        tracing::info!("Key generation complete");
        anyhow::Ok(())
    }

    async fn run_mpc(
        clock: Clock,
        secret_db: Arc<SecretDB>,
        secrets: SecretsConfig,
        config_file: ConfigFile,
        keyshare_storage: Box<dyn KeyshareStorage>,
        contract_config: RunningConfigFromChain,
        chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
        sign_request_receiver: tokio::sync::OwnedMutexGuard<
            mpsc::UnboundedReceiver<ChainSignatureRequest>,
        >,
    ) -> anyhow::Result<()> {
        let keyshare = keyshare_storage.load().await?;
        let keyshare = match keyshare {
            Some(keyshare) if keyshare.epoch == contract_config.epoch => keyshare,
            _ => {
                // TODO(#150): Implement sending join txn.
                tracing::error!("This node is not a participant in the current epoch. Doing nothing until contract state change.");
                futures::future::pending::<()>().await;
                unreachable!()
            }
        };

        let mpc_config = MpcConfig::from_participants_with_near_account_id(
            contract_config.participants,
            &config_file.my_near_account_id,
        )?;

        let (sender, receiver) =
            new_tls_mesh_network(&mpc_config, &secrets.p2p_private_key).await?;
        sender
            .wait_for_ready(mpc_config.participants.threshold as usize)
            .await?;
        let (network_client, channel_receiver, _handle) =
            run_network_client(Arc::new(sender), Box::new(receiver));

        let active_participants_query = {
            let network_client = network_client.clone();
            Arc::new(move || network_client.all_alive_participant_ids())
        };

        let triple_store = Arc::new(TripleStorage::new(
            clock.clone(),
            secret_db.clone(),
            DBCol::Triple,
            network_client.my_participant_id(),
            |participants, pair| pair.is_subset_of_active_participants(participants),
            active_participants_query.clone(),
        )?);

        let presignature_store = Arc::new(PresignatureStorage::new(
            clock,
            secret_db.clone(),
            DBCol::Presignature,
            network_client.my_participant_id(),
            |participants, presignature| {
                presignature.is_subset_of_active_participants(participants)
            },
            active_participants_query,
        )?);

        let sign_request_store = Arc::new(SignRequestStorage::new(secret_db.clone())?);

        let mpc_client = MpcClient::new(
            config_file.clone().into(),
            mpc_config.clone().into(),
            network_client,
            triple_store,
            presignature_store,
            sign_request_store,
            keyshare,
        );
        mpc_client
            .clone()
            .run(channel_receiver, sign_request_receiver, chain_txn_sender)
            .await?;

        Ok(())
    }

    async fn run_key_resharing(
        _clock: Clock,
        _secret_db: Arc<SecretDB>,
        _secrets: SecretsConfig,
        _config_file: ConfigFile,
        _keyshare_storage: Box<dyn KeyshareStorage>,
        _contract_config: ResharingConfigFromChain,
        _chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
    ) -> anyhow::Result<()> {
        // TODO(#43): Implement key resharing.
        tracing::error!("Key resharing is not implemented yet");
        futures::future::pending::<()>().await;
        unreachable!()
    }
}

fn sleep(clock: &Clock, duration: Duration) -> BoxFuture<'static, ()> {
    let clock = clock.clone();
    async move {
        clock.sleep(duration).await;
    }
    .boxed()
}
