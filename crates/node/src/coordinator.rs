use crate::assets::cleanup::{EpochData, delete_stale_triples_and_presignatures};
use crate::config::{MpcConfig, SecretsConfig};
use crate::db::SecretDB;
use crate::indexer::handler::ChainBlockUpdate;
use crate::indexer::participants::{
    ContractInitializingState, ContractKeyEventInstance, ContractRunningState,
};
use crate::indexer::types::{ChainRegisterForeignChainConfigArgs, ChainSendTransactionRequest};
use crate::indexer::{IndexerAPI, ReadSupportedForeignChain, tx_sender};
use crate::key_events::{
    ResharingArgs, keygen_follower, keygen_leader, resharing_follower, resharing_leader,
};
use crate::keyshare::{Keyshare, KeyshareData, KeyshareStorage};
use crate::metrics;
use crate::metrics::tokio_runtime_metrics::run_monitor_loop;
use crate::migration_service::{
    decide_current_job,
    onboarding::run_onboarding,
    types::{MigrationInfo, NodeJob},
    wait_until_job_changes,
};
use crate::mpc_client::MpcClient;
use crate::network::{
    MeshNetworkClient, MeshNetworkTransportSender, NetworkTaskChannel, run_network_client,
};
use crate::p2p::new_tls_mesh_network;
use crate::primitives::MpcTaskId;
use crate::providers::ckd::CKDProvider;
use crate::providers::eddsa::{EddsaSignatureProvider, EddsaTaskId};
use crate::providers::robust_ecdsa::RobustEcdsaSignatureProvider;
use crate::providers::verify_foreign_tx::VerifyForeignTxProvider;
use crate::providers::{EcdsaSignatureProvider, EcdsaTaskId};
use crate::runtime::{AsyncDroppableRuntime, build_lower_priority_runtime};
use crate::storage::SignRequestStorage;
use crate::storage::{CKDRequestStorage, VerifyForeignTransactionRequestStorage};
use crate::tracking::{self};
use crate::web::DebugRequest;
use anyhow::Context as _;
use futures::FutureExt;
use futures::future::BoxFuture;
use mpc_node_config::ConfigFile;
use mpc_primitives::domain::{Curve, DomainId, Protocol};
use mpc_primitives::ReconstructionThreshold;
use near_time::Clock;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use threshold_signatures::ReconstructionThreshold as TSReconstructionThreshold;
use threshold_signatures::{confidential_key_derivation, ecdsa, frost::eddsa};
use tokio::select;
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::{RwLock, broadcast, mpsc, watch};
use tokio_metrics::RuntimeMonitor;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

/// Main entry point for the MPC node logic.
///
/// `Coordinator::run` is the *only* orchestration loop in the node: it owns
/// the unified `watch::Receiver<NodeJob>` produced by `decide_current_job`
/// and dispatches each role transition to the matching per-arm handler
/// (onboarding, run_initialization, run_mpc, run_key_resharing). Every
/// handler self-terminates when the receiver moves to a different variant,
/// at which point the loop re-classifies and re-enters.
///
/// This replaces the previous design where onboarding and the MPC
/// state-dispatch ran sequentially (no back-migration without restart) or in
/// parallel under a `select!` with cleanup by `Future::drop` (the #3406
/// dispatcher PR).
pub struct Coordinator<TransactionSender, ForeignChainPolicyReader> {
    pub clock: Clock,
    pub secrets: SecretsConfig,
    pub config_file: ConfigFile,

    /// Storage for triples, presignatures, signing requests.
    pub secret_db: Arc<SecretDB>,
    /// Storage for keyshares.
    pub keyshare_storage: Arc<RwLock<KeyshareStorage>>,
    /// For interaction with the indexer.
    pub indexer: IndexerAPI<TransactionSender, ForeignChainPolicyReader>,

    /// For testing, to know what the current state is.
    pub currently_running_job_name: Arc<Mutex<String>>,

    /// For debug UI to send us debug requests.
    pub debug_request_sender: broadcast::Sender<DebugRequest>,

    /// Watch channel for this node's migration record. Consumed by the
    /// onboarding arm and by `decide_current_job` for role classification.
    pub migration_info_receiver: watch::Receiver<MigrationInfo>,

    /// Watch channel fed by the recovery web server (started in `run.rs`);
    /// the onboarding arm reads imported keyshares from it.
    pub import_keyshares_receiver: watch::Receiver<Vec<Keyshare>>,
}

impl<TransactionSender, ForeignChainPolicyReader>
    Coordinator<TransactionSender, ForeignChainPolicyReader>
where
    TransactionSender: tx_sender::TransactionSender + 'static,
    ForeignChainPolicyReader: ReadSupportedForeignChain + Clone + Send + Sync + 'static,
{
    /// The node's single orchestration loop. Classifies the current role via
    /// `decide_current_job` and dispatches each transition to the matching
    /// per-arm handler; on the handler's return, awaits the next role change
    /// and re-dispatches.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let tls_public_key = self.secrets.persistent_secrets.p2p_private_key.verifying_key();
        let (monitor_cancel, mut job_receiver) = decide_current_job(
            self.indexer.contract_state_receiver.clone(),
            self.migration_info_receiver.clone(),
            self.config_file.my_near_account_id.clone(),
            tls_public_key,
        );

        let result: anyhow::Result<()> = async {
            loop {
                let current = job_receiver.borrow_and_update().clone();
                match current {
                    NodeJob::Onboard(keyset) => {
                        tracing::info!("coordinator: onboarding");
                        let _report_guard = ReportCurrentJobGuard::new(
                            "Onboard",
                            self.currently_running_job_name.clone(),
                        );
                        run_onboarding(
                            keyset,
                            job_receiver.clone(),
                            self.keyshare_storage.clone(),
                            self.import_keyshares_receiver.clone(),
                            self.indexer.txn_sender.clone(),
                            self.migration_info_receiver.clone(),
                        )
                        .await?;
                    }
                    NodeJob::WaitForStateChange => {
                        tracing::info!("coordinator: waiting for state change");
                        let _report_guard = ReportCurrentJobGuard::new(
                            "Wait",
                            self.currently_running_job_name.clone(),
                        );
                        // Fall through to .changed() below.
                    }
                    NodeJob::Initialize { state, mpc_config } => {
                        tracing::info!("coordinator: initializing");
                        let _report_guard = ReportCurrentJobGuard::new(
                            "Initializing",
                            self.currently_running_job_name.clone(),
                        );
                        let work = Self::create_runtime_and_run(
                            "Initializing",
                            self.config_file.cores,
                            Self::run_initialization(
                                self.secrets.clone(),
                                self.keyshare_storage.clone(),
                                mpc_config,
                                state,
                                self.indexer.txn_sender.clone(),
                            ),
                        )?;
                        tokio::select! {
                            res = work => { res?; }
                            res = wait_until_job_changes(
                                &mut job_receiver,
                                |j| matches!(j, NodeJob::Initialize { .. }),
                            ) => { res?; }
                        }
                    }
                    NodeJob::Run { state, mpc_config } => {
                        tracing::info!(
                            "coordinator: running (resharing={})",
                            state.resharing_state.is_some(),
                        );
                        let _report_guard = ReportCurrentJobGuard::new(
                            if state.resharing_state.is_some() { "Resharing" } else { "Running" },
                            self.currently_running_job_name.clone(),
                        );
                        let block_update_receiver = self
                            .indexer
                            .block_update_receiver
                            .clone()
                            .lock_owned()
                            .await;
                        let work = Self::create_runtime_and_run(
                            "Running",
                            self.config_file.cores,
                            Self::run_mpc(
                                self.clock.clone(),
                                self.secret_db.clone(),
                                self.secrets.clone(),
                                self.config_file.clone(),
                                self.keyshare_storage.clone(),
                                state,
                                mpc_config,
                                self.indexer.txn_sender.clone(),
                                self.indexer.foreign_chain_policy_reader.clone(),
                                block_update_receiver,
                                self.debug_request_sender.subscribe(),
                            ),
                        )?;
                        tokio::select! {
                            res = work => { res?; }
                            res = wait_until_job_changes(
                                &mut job_receiver,
                                |j| matches!(j, NodeJob::Run { .. }),
                            ) => { res?; }
                        }
                    }
                }
                job_receiver
                    .changed()
                    .await
                    .context("current-job channel closed")?;
            }
        }
        .await;

        monitor_cancel.cancel();
        result
    }

    fn create_runtime_and_run(
        description: &str,
        cores: Option<usize>,
        task: impl Future<Output = anyhow::Result<()>> + Send + 'static,
    ) -> anyhow::Result<BoxFuture<'static, anyhow::Result<()>>> {
        let task_handle = tracking::current_task();

        // Create a separate runtime, as opposed to making a runtime when the
        // binary starts, for these reasons:
        //  - so that we can limit the number of cores used for MPC tasks,
        //    in order to avoid starving the indexer, causing it to fall behind.
        //  - so that we can ensure that all MPC tasks are shut down when we
        //    encounter contract state transitions. By dropping the entire
        //    runtime, we can ensure that all tasks are stopped. Otherwise, it
        //    would be very difficult and error-prone to ensure we don't leave
        //    some long-running task behind.
        let mpc_runtime = if let Some(n_threads) = cores {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(std::cmp::max(n_threads, 1))
                .enable_all()
                .build()?
        } else {
            tokio::runtime::Runtime::new()?
        };
        let runtime_handle = mpc_runtime.handle();
        let runtime_monitor = RuntimeMonitor::new(runtime_handle);

        // run as long as the runtime is alive
        mpc_runtime.spawn(run_monitor_loop("mpc", runtime_monitor));

        let mpc_runtime = AsyncDroppableRuntime::new(mpc_runtime);
        let fut = mpc_runtime.spawn(task_handle.scope(description, task));
        Ok(async move {
            let _mpc_runtime = mpc_runtime;
            anyhow::Ok(fut.await??)
        }
        .boxed())
    }

    /// Builds the lower-priority runtime that CPU-heavy asset generation runs on,
    /// so the OS preempts it whenever signing is ready. Returns the runtime — to
    /// be kept alive for the duration of the run — alongside the handle that
    /// generation tasks spawn on. When disabled there is no separate runtime and
    /// the handle is the current one, so generation shares the MPC runtime. Must
    /// be called from within the MPC runtime so `Handle::current()` resolves to it.
    fn build_gen_runtime(
        config_file: &ConfigFile,
    ) -> anyhow::Result<(Option<AsyncDroppableRuntime>, tokio::runtime::Handle)> {
        let gen_runtime = config_file
            .separate_asset_generation_runtime
            .then(|| {
                let worker_threads = config_file.cores.unwrap_or_else(|| {
                    std::thread::available_parallelism()
                        .map(|n| n.get())
                        .unwrap_or(1)
                });
                build_lower_priority_runtime(worker_threads, "mpc-gen")
                    .map(AsyncDroppableRuntime::new)
            })
            .transpose()?;
        if let Some(runtime) = &gen_runtime {
            // Metrics published under the "gen" runtime label (the MPC runtime
            // uses "mpc"), so the two runtimes stay distinct series.
            runtime.spawn(run_monitor_loop(
                "gen",
                RuntimeMonitor::new(runtime.handle()),
            ));
        }
        let gen_runtime_handle = gen_runtime
            .as_ref()
            .map_or_else(tokio::runtime::Handle::current, |runtime| {
                runtime.handle().clone()
            });
        Ok((gen_runtime, gen_runtime_handle))
    }

    /// Entry point to handle the Initializing state of the contract.
    ///
    /// `mpc_config` is pre-derived by `NodeJob::new` from `state.participants`
    /// — the in-line `MpcConfig::from_participants_with_near_account_id`
    /// re-check + `HaltUntilInterrupted` short-circuit are gone.
    async fn run_initialization(
        secrets: SecretsConfig,
        keyshare_storage: Arc<RwLock<KeyshareStorage>>,
        mpc_config: MpcConfig,
        state: ContractInitializingState,
        chain_txn_sender: TransactionSender,
    ) -> anyhow::Result<()> {
        let p2p_key = &secrets.persistent_secrets.p2p_private_key;
        // Single-value key-event channel for this run. Mid-flight key-event
        // advances are handled by the outer dispatcher loop: when the
        // classifier sees the new key_event, it emits an updated
        // NodeJob::Initialize and the worker is restarted (the work future
        // is dropped via select! and the new arm dispatched). This relies on
        // the predicate in the outer select! distinguishing key_event ids
        // — a follow-up tightens the predicate from `matches!(j,
        // NodeJob::Initialize {..})` to also compare `state.key_event.id`.
        let (_key_event_sender, key_event_receiver) = watch::channel(state.key_event);

        tracking::set_progress(&format!(
            "Generating key(s) as participant {}",
            mpc_config.my_participant_id
        ));

        let (sender, receiver) = new_tls_mesh_network(&mpc_config, p2p_key).await?;
        let (network_client, channel_receiver, _handle) =
            run_network_client(Arc::new(sender), Box::new(receiver));
        let threshold: usize = mpc_config.participants.threshold.try_into()?;
        let threshold = TSReconstructionThreshold::from(threshold);
        if mpc_config.is_leader_for_key_event() {
            keygen_leader(
                network_client,
                keyshare_storage,
                key_event_receiver,
                chain_txn_sender,
                threshold,
            )
            .await?;
        } else {
            keygen_follower(
                channel_receiver,
                keyshare_storage,
                key_event_receiver,
                chain_txn_sender,
                threshold,
            )
            .await?;
        }
        Ok(())
    }

    /// Entry point to handle the Running state of the contract.
    /// In this state, we generate triples and presignatures, and listen to
    /// signature requests and submit signature responses.
    ///
    /// `mpc_config` is the pre-derived outer config (for the new participants
    /// during resharing, the running participants otherwise) — same as what
    /// `NodeJob::new` computes. The in-line outer
    /// `MpcConfig::from_participants_with_near_account_id` + `HaltUntilInterrupted`
    /// check is gone. The inner `running_mpc_config` re-derivation (for the
    /// post-resharing running-participants subset) still happens inside; a
    /// follow-up would carry that subset in the `NodeJob::Run` arm too.
    #[expect(clippy::too_many_arguments)]
    async fn run_mpc(
        clock: Clock,
        secret_db: Arc<SecretDB>,
        secrets: SecretsConfig,
        config_file: ConfigFile,
        keyshare_storage: Arc<RwLock<KeyshareStorage>>,
        running_state: ContractRunningState,
        mpc_config: MpcConfig,
        chain_txn_sender: TransactionSender,
        foreign_chain_policy_reader: ForeignChainPolicyReader,
        block_update_receiver: tokio::sync::OwnedMutexGuard<
            mpsc::UnboundedReceiver<ChainBlockUpdate>,
        >,
        debug_request_receiver: broadcast::Receiver<DebugRequest>,
    ) -> anyhow::Result<()> {
        // Derive the key-event receiver for the resharing sub-mode from
        // `running_state`. Mid-flight resharing-event advances rely on the
        // outer dispatcher's classifier re-emitting `NodeJob::Run` (follow-up:
        // tighten the predicate to compare resharing_state.key_event.id).
        let resharing_state_receiver = running_state
            .resharing_state
            .as_ref()
            .map(|rs| watch::channel(rs.key_event.clone()).1);
        tracing::info!("Entering running state.");

        // `_gen_runtime` is kept alive for the lifetime of `run` below;
        // `AsyncDroppableRuntime` lets it be dropped from this async context on
        // teardown.
        let (_gen_runtime, gen_runtime_handle) = Self::build_gen_runtime(&config_file)?;

        let my_participant_id = running_state
            .participants
            .get_participant_id(&config_file.my_near_account_id);
        if let Some(my_participant_id) = my_participant_id {
            let current_participants_config = running_state.participants.clone();
            let current_epoch_id = running_state.keyset.epoch_id;
            let all_domains: Vec<_> = running_state.keyset.get_domain_ids();
            let current_epoch_data = EpochData {
                epoch_id: current_epoch_id,
                participants: current_participants_config,
            };
            // TODO(#3164): once each domain may declare its own
            // `reconstruction_threshold`, collect the distinct `t`s across all
            // CaitSith domains here instead of just the network-wide threshold.
            let triple_thresholds = vec![ReconstructionThreshold::new(
                running_state.participants.threshold,
            )];
            delete_stale_triples_and_presignatures(
                &secret_db,
                current_epoch_data,
                my_participant_id,
                all_domains,
                triple_thresholds,
            )?;
        }
        let mut running_participants = running_state.participants.clone();
        let participants_config = match &running_state.resharing_state {
            Some(resharing_state) => resharing_state.new_participants.clone(),
            None => running_participants.clone(),
        };
        // Only consider the running participants that are also members of the new resharing state.
        running_participants
            .participants
            .retain(|p| participants_config.participants.contains(p));

        let p2p_key = &secrets.persistent_secrets.p2p_private_key;
        // `mpc_config` is the pre-derived outer config from NodeJob::Run; the
        // assertion below mirrors the participants set the deleted in-line
        // `from_participants_with_near_account_id` call would have used.
        debug_assert_eq!(mpc_config.participants, participants_config);

        // Register locally supported foreign chains with the contract.
        let foreign_chain_configuration = config_file.foreign_chains.configured_chains();
        if let Err(err) = chain_txn_sender
            .send(ChainSendTransactionRequest::RegisterForeignChainConfig(
                ChainRegisterForeignChainConfigArgs {
                    foreign_chain_configuration,
                },
            ))
            .await
        {
            tracing::warn!(error = ?err, "failed to send register supported foreign chains transaction");
        }

        tracing::info!("Creating tls mesh");
        let (sender, receiver) = new_tls_mesh_network(&mpc_config, p2p_key).await?;
        let sender = Arc::new(sender);

        tracing::info!("Creating network client.");
        let (network_client, mut channel_receiver, _handle) =
            run_network_client(sender.clone(), Box::new(receiver));

        let cancellation_token = CancellationToken::new();
        let cancellation_token_child = cancellation_token.child_token();
        let _drop_guard = cancellation_token.drop_guard();

        let (running_network_receiver, resharing_network_receiver) = {
            let (running_sender, running_receiver) = unbounded_channel();
            let (resharing_sender, resharing_receiver) = unbounded_channel();

            let _multiplexer_handle = tokio::spawn(async move {
                loop {
                    select! {
                        network_channel = channel_receiver.recv()  => {
                            let Some(network_channel) = network_channel else {
                                tracing::info!("Network channel dropped.");
                                break;
                            };

                            let is_resharing_message = matches!(
                                network_channel.task_id(),
                                MpcTaskId::EcdsaTaskId(EcdsaTaskId::KeyResharing { .. })
                                    | MpcTaskId::EddsaTaskId(EddsaTaskId::KeyResharing { .. })
                            );

                            if is_resharing_message {
                                let send_result = resharing_sender.send(network_channel);
                                if send_result.is_err() {
                                    error!("resharing receiver dropped.");
                                }
                            } else {
                                let send_result = running_sender.send(network_channel);
                                if send_result.is_err() {
                                    error!("running receiver dropped.");
                                }
                            }
                        }

                        _ = cancellation_token_child.cancelled() => {
                            info!("Network multiplexer cancelled.");
                            break;
                        }

                    }
                }
                info!("Exiting network multiplexer.");
            });

            (running_receiver, resharing_receiver)
        };

        // This handle must be alive, otherwise the AutoAbortTask will get cancelled on drop.
        let resharing_handle = resharing_state_receiver.map(|resharing_state_receiver| {
            let config_file = config_file.clone();
            let running_state = running_state.clone();
            let keyshare_storage = keyshare_storage.clone();
            let chain_txn_sender = chain_txn_sender.clone();
            let network_client = network_client.clone();
            let mpc_config = mpc_config.clone();

            tracking::spawn_checked("key resharing", async move {
                Self::run_key_resharing(
                    &config_file,
                    keyshare_storage.clone(),
                    running_state.clone(),
                    &mpc_config,
                    network_client,
                    resharing_network_receiver,
                    chain_txn_sender,
                    resharing_state_receiver,
                )
                .await
            })
        });
        let p2p_public_key = p2p_key.verifying_key();

        let running_handle = tracking::spawn::<_, anyhow::Result<()>>(
            "running mpc job",
            async move {
                // Inner running-participants subset: during resharing, this is
                // the intersection of last-epoch and new participants (so a
                // node that's only in `new_participants` won't be in this set
                // yet). Follow-up: carry this in NodeJob::Run too and remove
                // the re-derivation.
                let Some(running_mpc_config) = MpcConfig::from_participants_with_near_account_id(
                    running_participants.clone(),
                    &config_file.my_near_account_id,
                    &p2p_public_key,
                ) else {
                    tracing::info!(
                        "Not in running participants subset; idle until next role change"
                    );
                    return Ok(());
                };

                let keyshares = match keyshare_storage
                    .write()
                    .await
                    .update_permanent_keyshares(&running_state.keyset)
                    .await
                {
                    Ok(keyshares) => keyshares,
                    Err(e) => {
                        tracing::error!(
                            "Failed to load keyshares: {:?}; idle until next role change",
                            e
                        );
                        return Ok(());
                    }
                };

                if keyshares.is_empty() {
                    tracing::info!("No keyshares yet; idle until next role change");
                    return Ok(());
                }

                tracking::set_progress(&format!(
                    "Running epoch {:?} as participant {}",
                    running_state.keyset.epoch_id, running_mpc_config.my_participant_id
                ));

                tracing::info!("wait for ready.");
                let running_participant_ids = running_mpc_config
                    .participants
                    .participants
                    .iter()
                    .map(|p| p.id)
                    .collect::<Vec<_>>();

                sender
                    .wait_for_ready(
                        running_mpc_config.participants.threshold.try_into()?,
                        &running_participant_ids,
                    )
                    .await?;

                let sign_request_store = Arc::new(SignRequestStorage::new(secret_db.clone())?);
                let ckd_request_store = Arc::new(CKDRequestStorage::new(secret_db.clone())?);
                let verify_foreign_tx_request_store = Arc::new(
                    VerifyForeignTransactionRequestStorage::new(secret_db.clone())?,
                );

                let mut ecdsa_keyshares: HashMap<
                    mpc_primitives::domain::DomainId,
                    ecdsa::KeygenOutput,
                > = HashMap::new();
                let mut robust_ecdsa_keyshares: HashMap<
                    mpc_primitives::domain::DomainId,
                    ecdsa::KeygenOutput,
                > = HashMap::new();
                let mut eddsa_keyshares: HashMap<
                    mpc_primitives::domain::DomainId,
                    eddsa::KeygenOutput,
                > = HashMap::new();
                let mut ckd_keyshares: HashMap<
                    mpc_primitives::domain::DomainId,
                    confidential_key_derivation::KeygenOutput,
                > = HashMap::new();
                let domain_to_protocol: HashMap<DomainId, Protocol> = running_state
                    .domains
                    .iter()
                    .map(|d| (d.id, d.protocol))
                    .collect();

                for keyshare in keyshares {
                    let domain_id = keyshare.key_id.domain_id;
                    let Some(protocol) = domain_to_protocol.get(&domain_id).copied() else {
                        anyhow::bail!(
                            "Keyshare references domain {domain_id:?} which is not in the contract registry",
                        );
                    };
                    let expected_curve = Curve::from(protocol);
                    match (expected_curve, keyshare.data) {
                        (Curve::Secp256k1, KeyshareData::Secp256k1(data)) => match protocol {
                            Protocol::CaitSith => {
                                ecdsa_keyshares.insert(domain_id, data);
                            }
                            Protocol::DamgardEtAl => {
                                robust_ecdsa_keyshares.insert(domain_id, data);
                            }
                            other => anyhow::bail!(
                                "Unexpected protocol {other:?} for Secp256k1 keyshare on domain {domain_id:?}",
                            ),
                        },
                        (Curve::Edwards25519, KeyshareData::Ed25519(data)) => {
                            eddsa_keyshares.insert(domain_id, data);
                        }
                        (Curve::Bls12381, KeyshareData::Bls12381(data)) => {
                            ckd_keyshares.insert(domain_id, data);
                        }
                        (expected, data) => anyhow::bail!(
                            "Keyshare data does not match the domain protocol's expected curve: domain_id={:?}, protocol={:?}, expected_curve={:?}, data_kind={:?}",
                            domain_id,
                            protocol,
                            expected,
                            std::mem::discriminant(&data),
                        ),
                    }
                }

                let ecdsa_signature_provider = Arc::new(EcdsaSignatureProvider::new(
                    config_file.clone().into(),
                    running_mpc_config.clone().into(),
                    network_client.clone(),
                    clock.clone(),
                    secret_db.clone(),
                    sign_request_store.clone(),
                    ecdsa_keyshares,
                )?);

                let robust_ecdsa_signature_provider = Arc::new(RobustEcdsaSignatureProvider::new(
                    config_file.clone().into(),
                    running_mpc_config.clone().into(),
                    network_client.clone(),
                    clock,
                    secret_db,
                    sign_request_store.clone(),
                    robust_ecdsa_keyshares,
                )?);

                let eddsa_signature_provider = Arc::new(EddsaSignatureProvider::new(
                    config_file.clone().into(),
                    running_mpc_config.clone().into(),
                    network_client.clone(),
                    sign_request_store.clone(),
                    eddsa_keyshares,
                ));

                let ckd_provider = Arc::new(CKDProvider::new(
                    config_file.clone().into(),
                    running_mpc_config.clone().into(),
                    network_client.clone(),
                    ckd_request_store.clone(),
                    ckd_keyshares,
                ));

                let verify_foreign_tx_provider = Arc::new(VerifyForeignTxProvider::new(
                    config_file.clone().into(),
                    foreign_chain_policy_reader.clone(),
                    verify_foreign_tx_request_store.clone(),
                    ecdsa_signature_provider.clone(),
                )?);

                let mpc_client = Arc::new(MpcClient::new(
                    config_file.into(),
                    network_client,
                    sign_request_store,
                    ckd_request_store,
                    verify_foreign_tx_request_store,
                    ecdsa_signature_provider,
                    robust_ecdsa_signature_provider,
                    eddsa_signature_provider,
                    ckd_provider,
                    verify_foreign_tx_provider,
                    domain_to_protocol,
                    gen_runtime_handle,
                ));

                mpc_client
                    .run(
                        running_network_receiver,
                        block_update_receiver,
                        chain_txn_sender,
                        debug_request_receiver,
                    )
                    .await?;

                Ok(())
            },
        );

        if let Some(resharing_handle) = resharing_handle {
            tracing::info!("Waiting on resharing handle.");
            resharing_handle.await?;
        }
        running_handle.await?
    }

    /// Entry point to handle the Resharing state of the contract.
    #[expect(clippy::too_many_arguments)]
    async fn run_key_resharing(
        config_file: &ConfigFile,
        keyshare_storage: Arc<RwLock<KeyshareStorage>>,
        current_running_state: ContractRunningState,
        mpc_config: &MpcConfig,
        network_client: Arc<MeshNetworkClient>,
        channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
        chain_txn_sender: TransactionSender,
        key_event_receiver: watch::Receiver<ContractKeyEventInstance>,
    ) -> anyhow::Result<()> {
        tracing::info!("Starting key resharing.");

        let previous_keyset = current_running_state.keyset;
        let was_participant_last_epoch = current_running_state
            .participants
            .participants
            .iter()
            .any(|p| p.near_account_id == config_file.my_near_account_id);
        let existing_keyshares = if was_participant_last_epoch {
            let keyshares = match keyshare_storage
                .write()
                .await
                .update_permanent_keyshares(&previous_keyset)
                .await
            {
                Ok(x) => x,
                Err(e) => {
                    tracing::error!(
                        "Failed to load keyshare for epoch {:?}: {:?}; doing nothing until contract state change",
                        previous_keyset.epoch_id,
                        e
                    );
                    return Ok(());
                }
            };
            Some(keyshares)
        } else {
            info!("Not participant in last epoch.");
            if keyshare_storage
                .write()
                .await
                .update_permanent_keyshares(&previous_keyset)
                .await
                .is_ok()
            {
                tracing::warn!(
                    "We should not have the previous keyshares when we were not a participant last epoch"
                );
            }
            None
        };

        let new_threshold: usize = mpc_config.participants.threshold.try_into()?;
        let args = Arc::new(ResharingArgs {
            previous_keyset,
            existing_keyshares,
            new_threshold: TSReconstructionThreshold::from(new_threshold),
            old_participants: current_running_state.participants,
        });

        if mpc_config.is_leader_for_key_event() {
            resharing_leader(
                network_client,
                keyshare_storage,
                key_event_receiver,
                chain_txn_sender,
                args,
            )
            .await?;
        } else {
            resharing_follower(
                channel_receiver,
                keyshare_storage,
                key_event_receiver,
                chain_txn_sender,
                args,
            )
            .await?;
        }
        Ok(())
    }
}

/// Simple RAII to export current job name to metrics and /debug/tasks.
struct ReportCurrentJobGuard {
    name: String,
    currently_running_job_name: Arc<Mutex<String>>,
}

impl ReportCurrentJobGuard {
    fn new(name: &str, currently_running_job_name: Arc<Mutex<String>>) -> Self {
        metrics::MPC_CURRENT_JOB_STATE
            .with_label_values(&[name])
            .inc();
        tracking::set_progress(name);
        *currently_running_job_name.lock().unwrap() = name.to_string();
        Self {
            name: name.to_string(),
            currently_running_job_name,
        }
    }
}

impl Drop for ReportCurrentJobGuard {
    fn drop(&mut self) {
        metrics::MPC_CURRENT_JOB_STATE
            .with_label_values(&[&self.name])
            .dec();
        tracking::set_progress("Transitioning state");
        *self.currently_running_job_name.lock().unwrap() = "".to_string();
    }
}

