use crate::indexer::ReadSupportedForeignChain;
use crate::indexer::handler::ChainBlockUpdate;
use crate::indexer::tx_sender::TransactionSender;
use crate::indexer::types::{
    ChainSendTransactionRequest, SignatureRespondArgsExt, VerifyForeignTransactionRespondArgsExt,
};
use crate::metrics;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::MpcTaskId;
use crate::providers::ckd::CKDProvider;
use crate::providers::ecdsa::EcdsaTaskId;
use crate::providers::eddsa::EddsaSignatureProvider;
use crate::providers::robust_ecdsa::{RobustEcdsaSignatureProvider, RobustEcdsaTaskId};
use crate::providers::verify_foreign_tx::VerifyForeignTxProvider;
use crate::providers::{EcdsaSignatureProvider, SignatureProvider};
use crate::requests::queue::{
    CHECK_EACH_REQUEST_INTERVAL, PendingRequests, REQUEST_EXPIRATION_BLOCKS,
};
use crate::storage::{
    CKDRequestStorage, SignRequestStorage, VerifyForeignTransactionRequestStorage,
};
use crate::tracking::{self, AutoAbortTaskCollection};
use crate::trait_extensions::convert_to_contract_dto::IntoContractInterfaceType;
use crate::types::SignatureRequest;
use crate::types::{CKDRequest, RequestsUpdate, VerifyForeignTxRequest};
use crate::web::{DebugRequest, DebugRequestKind};
use chain_gateway::event_subscriber::recent_blocks_tracker::{AddBlockResult, RecentBlocksTracker};
use mpc_node_config::ConfigFile;
use near_mpc_contract_interface::call_args as contract_args;

use mpc_primitives::domain::{DomainId, Protocol};
use near_mpc_contract_interface::types::CKDResponse;
use near_time::Clock;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

/// A one-time delay before processing requests on startup. This is to prevent the case
/// where we have not yet connected to all participants, and the signature/ckd request processing code thinks
/// that others are offline, leading to requests having multiple leaders and unnecessarily
/// responded to multiple times. It doesn't affect correctness, but can make tests less flaky and
/// production runs experience fewer redundant signatures/ckds.
const INITIAL_STARTUP_PROCESSING_DELAY: Duration = Duration::from_secs(2);

const TEE_CONTRACT_VERIFICATION_INVOCATION_INTERVAL_DURATION: Duration =
    Duration::from_secs(60 * 60 * 24 * 2);

#[derive(Clone)]
pub struct MpcClient<ForeignChainPolicyReader> {
    config: Arc<ConfigFile>,
    client: Arc<MeshNetworkClient>,
    sign_request_store: Arc<SignRequestStorage>,
    ckd_request_store: Arc<CKDRequestStorage>,
    verify_foreign_tx_request_store: Arc<VerifyForeignTransactionRequestStorage>,
    ecdsa_signature_provider: Arc<EcdsaSignatureProvider>,
    robust_ecdsa_signature_provider: Arc<RobustEcdsaSignatureProvider>,
    eddsa_signature_provider: Arc<EddsaSignatureProvider>,
    ckd_provider: Arc<CKDProvider>,
    verify_foreign_tx_provider: Arc<VerifyForeignTxProvider<ForeignChainPolicyReader>>,
    domain_to_protocol: HashMap<DomainId, Protocol>,
    /// Lower-priority runtime for CPU-heavy asset generation.
    gen_runtime_handle: tokio::runtime::Handle,
}

/// Whether a task is CPU-heavy asset generation that should run on the
/// lower-priority gen runtime. Triples and presignatures qualify; signing,
/// keygen, resharing, CKD, and foreign-tx verification stay on the main MPC
/// runtime. Inner matches are exhaustive so a new task kind forces a decision.
fn is_heavy_generation_task(task_id: &MpcTaskId) -> bool {
    match task_id {
        MpcTaskId::EcdsaTaskId(id) => match id {
            EcdsaTaskId::ManyTriples { .. } | EcdsaTaskId::Presignature { .. } => true,
            EcdsaTaskId::KeyGeneration { .. }
            | EcdsaTaskId::KeyResharing { .. }
            | EcdsaTaskId::Signature { .. } => false,
        },
        MpcTaskId::RobustEcdsaTaskId(id) => match id {
            RobustEcdsaTaskId::Presignature { .. } => true,
            RobustEcdsaTaskId::KeyGeneration { .. }
            | RobustEcdsaTaskId::KeyResharing { .. }
            | RobustEcdsaTaskId::Signature { .. } => false,
        },
        MpcTaskId::EddsaTaskId(_)
        | MpcTaskId::CKDTaskId(_)
        | MpcTaskId::VerifyForeignTxTaskId(_) => false,
    }
}

async fn run_led_computation<T>(
    metric: &prometheus::IntCounterVec,
    deadline: Duration,
    computation: impl Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    let (outcome_label, result) = match timeout(deadline, computation).await {
        Ok(Ok(value)) => (metrics::MPC_NUM_COMPUTATIONS_LED_SUCCEEDED_LABEL, Ok(value)),
        Ok(Err(error)) => (metrics::MPC_NUM_COMPUTATIONS_LED_FAILED_LABEL, Err(error)),
        Err(elapsed) => (
            metrics::MPC_NUM_COMPUTATIONS_LED_DEADLINE_EXCEEDED_LABEL,
            Err(elapsed.into()),
        ),
    };
    metric.with_label_values(&[outcome_label]).inc();
    metric
        .with_label_values(&[metrics::MPC_NUM_COMPUTATIONS_LED_TOTAL_LABEL])
        .inc();
    result
}

impl<ForeignChainPolicyReader> MpcClient<ForeignChainPolicyReader>
where
    ForeignChainPolicyReader: ReadSupportedForeignChain + 'static,
{
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        config: Arc<ConfigFile>,
        client: Arc<MeshNetworkClient>,
        sign_request_store: Arc<SignRequestStorage>,
        ckd_request_store: Arc<CKDRequestStorage>,
        verify_foreign_tx_request_store: Arc<VerifyForeignTransactionRequestStorage>,
        ecdsa_signature_provider: Arc<EcdsaSignatureProvider>,
        robust_ecdsa_signature_provider: Arc<RobustEcdsaSignatureProvider>,
        eddsa_signature_provider: Arc<EddsaSignatureProvider>,
        ckd_provider: Arc<CKDProvider>,
        verify_foreign_tx_provider: Arc<VerifyForeignTxProvider<ForeignChainPolicyReader>>,
        domain_to_protocol: HashMap<DomainId, Protocol>,
        gen_runtime_handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            config,
            client,
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
        }
    }

    /// Main entry point for the MPC node. Runs all the business logic for doing
    /// multiparty computation.
    pub async fn run(
        self: &Arc<Self>,
        channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
        block_update_receiver: tokio::sync::OwnedMutexGuard<
            mpsc::UnboundedReceiver<ChainBlockUpdate>,
        >,
        chain_txn_sender: impl TransactionSender + 'static,
        debug_receiver: tokio::sync::broadcast::Receiver<DebugRequest>,
    ) -> anyhow::Result<()> {
        let client = self.client.clone();
        let metrics_emitter = tracking::spawn("periodically emits metrics", async move {
            loop {
                client.emit_metrics();
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });

        let monitor_passive_channels = {
            tracking::spawn(
                "monitor passive channels",
                MpcClient::monitor_passive_channels_inner(channel_receiver, self.clone()),
            )
        };

        let monitor_chain = {
            let chain_txn_sender = chain_txn_sender.clone();
            tracking::spawn(
                "monitor chain",
                self.clone().monitor_block_updates(
                    block_update_receiver,
                    chain_txn_sender,
                    debug_receiver,
                ),
            )
        };

        let tee_verification_handle = {
            let chain_txn_sender = chain_txn_sender.clone();
            tracking::spawn("tee_verification", async move {
                loop {
                    if let Err(e) = chain_txn_sender
                        .send(ChainSendTransactionRequest::VerifyTee())
                        .await
                    {
                        tracing::error!(
                            "Receiver dropped, error sending VerifyTee request: {:?}",
                            e
                        );
                        return;
                    }
                    metrics::VERIFY_TEE_REQUESTS_SENT.inc();
                    sleep(TEE_CONTRACT_VERIFICATION_INVOCATION_INTERVAL_DURATION).await;
                }
            })
        };

        // Background asset generation runs on the lower-priority gen runtime. The
        // inner `tracking::spawn` calls in each provider inherit it via
        // `Handle::current()`.
        let ecdsa_background_tasks = tracking::spawn_on(
            &self.gen_runtime_handle,
            "ecdsa_background_tasks",
            self.ecdsa_signature_provider
                .clone()
                .spawn_background_tasks(),
        );

        let robust_ecdsa_background_tasks = tracking::spawn_on(
            &self.gen_runtime_handle,
            "robust_ecdsa_background_tasks",
            self.robust_ecdsa_signature_provider
                .clone()
                .spawn_background_tasks(),
        );

        let eddsa_background_tasks = tracking::spawn_on(
            &self.gen_runtime_handle,
            "eddsa_background_tasks",
            self.eddsa_signature_provider
                .clone()
                .spawn_background_tasks(),
        );

        let ckd_background_tasks = tracking::spawn_on(
            &self.gen_runtime_handle,
            "ckd_background_tasks",
            self.ckd_provider.clone().spawn_background_tasks(),
        );

        let _ = monitor_passive_channels.await?;
        metrics_emitter.await?;
        monitor_chain.await?;
        let _ = robust_ecdsa_background_tasks.await?;
        let _ = ecdsa_background_tasks.await?;
        let _ = eddsa_background_tasks.await?;
        let _ = ckd_background_tasks.await?;
        tee_verification_handle.await?;

        Ok(())
    }

    async fn monitor_block_updates(
        self: Arc<Self>,
        mut block_update_receiver: tokio::sync::OwnedMutexGuard<
            mpsc::UnboundedReceiver<ChainBlockUpdate>,
        >,
        chain_txn_sender: impl TransactionSender + 'static,
        mut debug_receiver: tokio::sync::broadcast::Receiver<DebugRequest>,
    ) {
        let mut tasks = AutoAbortTaskCollection::new();
        let mut pending_signatures =
            PendingRequests::<SignatureRequest, contract_args::SignatureRespondArgs>::new(
                Clock::real(),
                self.client.all_participant_ids(),
                self.client.my_participant_id(),
                self.client.clone(),
            );
        let mut pending_ckds = PendingRequests::<CKDRequest, contract_args::CKDRespondArgs>::new(
            Clock::real(),
            self.client.all_participant_ids(),
            self.client.my_participant_id(),
            self.client.clone(),
        );
        let mut pending_verify_foreign_txs = PendingRequests::<
            VerifyForeignTxRequest,
            contract_args::VerifyForeignTransactionRespondArgs,
        >::new(
            Clock::real(),
            self.client.all_participant_ids(),
            self.client.my_participant_id(),
            self.client.clone(),
        );

        let mut recent_blocks = RecentBlocksTracker::new(REQUEST_EXPIRATION_BLOCKS);
        let start_time = Clock::real().now();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(CHECK_EACH_REQUEST_INTERVAL.unsigned_abs()) => {
                }
                block_update = block_update_receiver.recv() => {
                    let Some(block_update) = block_update else {
                        // If this branch hits, it means the channel is closed, meaning the
                        // indexer is being shutdown. So just quit this task.
                        break;
                    };

                    self.client.update_indexer_height(block_update.block.height.into());

                    let AddBlockResult{ block_status } = recent_blocks.add_block(&block_update.block);

                    let signature_requests : RequestsUpdate<SignatureRequest> = RequestsUpdate::from_chain(
                        &block_update.block,
                        block_status.clone(),
                        block_update.signature_requests,
                        block_update.completed_signatures,
                    );

                    // TODO(#3031): add batch request and unify stores
                    for request in &signature_requests.requests {
                        self.sign_request_store.add(request);
                    }

                    // TODO(#3032): remove completed & finalized requests from store
                    pending_signatures.notify_new_block(signature_requests);

                    let ckd_requests: RequestsUpdate<CKDRequest> = RequestsUpdate::from_chain(
                        &block_update.block,
                        block_status.clone(),
                        block_update.ckd_requests,
                        block_update.completed_ckds
                    );
                    for request in &ckd_requests.requests {
                        self.ckd_request_store.add(request);
                    }

                    pending_ckds.notify_new_block(ckd_requests);

                    let verify_foreign_tx_requests : RequestsUpdate<VerifyForeignTxRequest> = RequestsUpdate::from_chain(
                        &block_update.block,
                        block_status,
                        block_update.verify_foreign_tx_requests,
                        block_update.completed_verify_foreign_txs
                    );

                    for request in &verify_foreign_tx_requests.requests {
                        self.verify_foreign_tx_request_store.add(request);
                    }
                    pending_verify_foreign_txs.notify_new_block(verify_foreign_tx_requests);
                }
                debug_request = debug_receiver.recv() => {
                    if let Ok(debug_request) = debug_request {
                        match debug_request.kind {
                            DebugRequestKind::RecentBlocks => {
                                let debug_output = format!("{:?}", recent_blocks);
                                debug_request.respond(debug_output);
                            }
                            DebugRequestKind::RecentSignatures => {
                                let debug_output = format!("{:?}", pending_signatures);
                                debug_request.respond(debug_output);
                            }
                            DebugRequestKind::RecentCKDs => {
                                let debug_output = format!("{:?}", pending_ckds);
                                debug_request.respond(debug_output);
                            }
                            DebugRequestKind::RecentVerifyForeignTxs => {
                                let debug_output = format!("{:?}", pending_verify_foreign_txs);
                                debug_request.respond(debug_output);
                            }
                        }
                    }
                }
            }

            if start_time.elapsed() < INITIAL_STARTUP_PROCESSING_DELAY {
                continue;
            }
            let signature_attempts = pending_signatures.get_requests_to_attempt();

            for signature_attempt in signature_attempts {
                let this = self.clone();
                let chain_txn_sender_signature = chain_txn_sender.clone();
                tasks.spawn_checked(
                    &format!(
                        "leader for signature request {:?}",
                        signature_attempt.request.id
                    ),
                    async move {
                        // Only issue a MPC signature computation if we haven't computed it
                        // in a previous attempt.
                        let existing_response = signature_attempt
                            .computation_progress
                            .lock()
                            .unwrap()
                            .computed_response
                            .clone();
                        let response = match existing_response {
                            None => {
                                let response = run_led_computation(
                                    &metrics::MPC_NUM_SIGNATURE_COMPUTATIONS_LED,
                                    Duration::from_secs(this.config.signature.timeout_sec),
                                    this.compute_signature_response(&signature_attempt.request),
                                )
                                .await?;

                                signature_attempt
                                    .computation_progress
                                    .lock()
                                    .unwrap()
                                    .computed_response = Some(response.clone());
                                response
                            }
                            Some(response) => response,
                        };
                        let _ = chain_txn_sender_signature
                            .send(ChainSendTransactionRequest::Respond(response))
                            .await;
                        signature_attempt
                            .computation_progress
                            .lock()
                            .unwrap()
                            .last_response_submission = Some(Clock::real().now());

                        anyhow::Ok(())
                    },
                );
            }
            let ckd_attempts = pending_ckds.get_requests_to_attempt();

            for ckd_attempt in ckd_attempts {
                let this = self.clone();
                let chain_txn_sender_ckd = chain_txn_sender.clone();
                tasks.spawn_checked(
                    &format!("leader for ckd request {:?}", ckd_attempt.request.id),
                    async move {
                        // Only issue an MPC ckd computation if we haven't computed it
                        // in a previous attempt.
                        let existing_response = ckd_attempt
                            .computation_progress
                            .lock()
                            .unwrap()
                            .computed_response
                            .clone();
                        let response = match existing_response {
                            None => {
                                let response = run_led_computation(
                                    &metrics::MPC_NUM_CKD_COMPUTATIONS_LED,
                                    Duration::from_secs(this.config.ckd.timeout_sec),
                                    this.compute_ckd_response(&ckd_attempt.request),
                                )
                                .await?;

                                ckd_attempt
                                    .computation_progress
                                    .lock()
                                    .unwrap()
                                    .computed_response = Some(response.clone());
                                response
                            }
                            Some(response) => response,
                        };
                        let _ = chain_txn_sender_ckd
                            .send(ChainSendTransactionRequest::CKDRespond(response))
                            .await;
                        ckd_attempt
                            .computation_progress
                            .lock()
                            .unwrap()
                            .last_response_submission = Some(Clock::real().now());

                        anyhow::Ok(())
                    },
                );
            }

            let verify_foreign_tx_attempts = pending_verify_foreign_txs.get_requests_to_attempt();

            for verify_foreign_tx_attempt in verify_foreign_tx_attempts {
                let this = self.clone();
                let chain_txn_sender_verify_foreign_tx = chain_txn_sender.clone();
                tasks.spawn_checked(
                    &format!(
                        "leader for verify_foreign_tx request {:?}",
                        verify_foreign_tx_attempt.request.id
                    ),
                    async move {
                        // Only issue an MPC verify_foreign_tx computation if we haven't computed it
                        // in a previous attempt.
                        let existing_response = verify_foreign_tx_attempt
                            .computation_progress
                            .lock()
                            .unwrap()
                            .computed_response
                            .clone();
                        let response = match existing_response {
                            None => {
                                let response = run_led_computation(
                                    &metrics::MPC_NUM_VERIFY_FOREIGN_TX_COMPUTATIONS_LED,
                                    Duration::from_secs(this.config.signature.timeout_sec),
                                    this.compute_verify_foreign_tx_response(
                                        &verify_foreign_tx_attempt.request,
                                    ),
                                )
                                .await?;

                                verify_foreign_tx_attempt
                                    .computation_progress
                                    .lock()
                                    .unwrap()
                                    .computed_response = Some(response.clone());
                                response
                            }
                            Some(response) => response,
                        };
                        let _ = chain_txn_sender_verify_foreign_tx
                            .send(
                                ChainSendTransactionRequest::VerifyForeignTransactionRespond(
                                    response,
                                ),
                            )
                            .await;
                        verify_foreign_tx_attempt
                            .computation_progress
                            .lock()
                            .unwrap()
                            .last_response_submission = Some(Clock::real().now());

                        anyhow::Ok(())
                    },
                );
            }
        }
    }

    async fn compute_signature_response(
        &self,
        request: &SignatureRequest,
    ) -> anyhow::Result<contract_args::SignatureRespondArgs> {
        match self.domain_to_protocol.get(&request.domain) {
            Some(Protocol::CaitSith) => {
                let (signature, public_key) = self
                    .ecdsa_signature_provider
                    .clone()
                    .make_signature(request.id)
                    .await?;

                let response = contract_args::SignatureRespondArgs::from_ecdsa(
                    request,
                    &signature,
                    &public_key,
                )?;

                Ok(response)
            }
            Some(Protocol::Frost) => {
                let (signature, _) = self
                    .eddsa_signature_provider
                    .clone()
                    .make_signature(request.id)
                    .await?;

                let response =
                    contract_args::SignatureRespondArgs::from_eddsa(request, &signature)?;

                Ok(response)
            }
            Some(Protocol::ConfidentialKeyDerivation) => Err(anyhow::anyhow!(
                "Incorrect protocol for domain: {:?}",
                request.domain.clone()
            )),
            Some(Protocol::DamgardEtAl) => {
                let (signature, public_key) = self
                    .robust_ecdsa_signature_provider
                    .clone()
                    .make_signature(request.id)
                    .await?;

                let response = contract_args::SignatureRespondArgs::from_ecdsa(
                    request,
                    &signature,
                    &public_key,
                )?;

                Ok(response)
            }
            None => Err(anyhow::anyhow!(
                "Signature scheme is not found for domain: {:?}",
                request.domain.clone()
            )),
        }
    }

    async fn compute_ckd_response(
        &self,
        request: &CKDRequest,
    ) -> anyhow::Result<contract_args::CKDRespondArgs> {
        match self.domain_to_protocol.get(&request.domain_id) {
            Some(Protocol::ConfidentialKeyDerivation) => {
                let response = self.ckd_provider.clone().make_signature(request.id).await?;

                let response = contract_args::CKDRespondArgs::new(
                    request.into_contract_interface_type(),
                    CKDResponse {
                        big_y: (&response.0.0).into(),
                        big_c: (&response.0.1).into(),
                    },
                );

                Ok(response)
            }
            Some(Protocol::CaitSith) | Some(Protocol::DamgardEtAl) | Some(Protocol::Frost) => {
                Err(anyhow::anyhow!(
                    "Signature scheme is not allowed for domain: {:?}",
                    request.domain_id.clone()
                ))
            }
            None => Err(anyhow::anyhow!(
                "Signature scheme is not found for domain: {:?}",
                request.domain_id.clone()
            )),
        }
    }

    async fn compute_verify_foreign_tx_response(
        &self,
        request: &VerifyForeignTxRequest,
    ) -> anyhow::Result<contract_args::VerifyForeignTransactionRespondArgs> {
        match self.domain_to_protocol.get(&request.domain_id) {
            Some(Protocol::CaitSith) => {
                let response = self
                    .verify_foreign_tx_provider
                    .make_verify_foreign_tx_leader(request.id)
                    .await?;

                let payload_hash = response.0.0.compute_msg_hash()?;
                let response = contract_args::VerifyForeignTransactionRespondArgs::from_signature(
                    request.clone(),
                    payload_hash,
                    response.0.1,
                    response.1,
                )?;

                Ok(response)
            }
            Some(Protocol::ConfidentialKeyDerivation)
            | Some(Protocol::DamgardEtAl)
            | Some(Protocol::Frost) => Err(anyhow::anyhow!(
                "Signature scheme is not allowed for domain: {:?}",
                request.domain_id.clone()
            )),
            None => Err(anyhow::anyhow!(
                "Signature scheme is not found for domain: {:?}",
                request.domain_id.clone()
            )),
        }
    }

    async fn monitor_passive_channels_inner(
        mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
        mpc_client: Arc<MpcClient<ForeignChainPolicyReader>>,
    ) -> anyhow::Result<()> {
        let mut tasks = AutoAbortTaskCollection::new();
        while let Some(channel) = channel_receiver.recv().await {
            let mpc_clone = mpc_client.clone();
            let task_id = channel.task_id();
            let description = format!("passive task; task_id: {task_id:?}");
            let task = async move { mpc_clone.process_channel_task(channel).await };
            if is_heavy_generation_task(&task_id) {
                tasks.spawn_checked_on(&mpc_client.gen_runtime_handle, &description, task);
            } else {
                tasks.spawn_checked(&description, task);
            }
        }

        const EXIT_MESSAGE: &str =
            "Network task channel receiver is closed. Exiting monitor_passive_channels_inner.";

        tracing::info!(EXIT_MESSAGE);
        anyhow::bail!(EXIT_MESSAGE)
    }

    async fn process_channel_task(
        self: Arc<Self>,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<()> {
        match channel.task_id() {
            MpcTaskId::EcdsaTaskId(_) => {
                self.ecdsa_signature_provider
                    .clone()
                    .process_channel(channel)
                    .await?
            }
            MpcTaskId::EddsaTaskId(_) => {
                self.eddsa_signature_provider
                    .clone()
                    .process_channel(channel)
                    .await?
            }
            MpcTaskId::CKDTaskId(_) => self.ckd_provider.clone().process_channel(channel).await?,
            MpcTaskId::RobustEcdsaTaskId(_) => {
                self.robust_ecdsa_signature_provider
                    .clone()
                    .process_channel(channel)
                    .await?
            }
            MpcTaskId::VerifyForeignTxTaskId(_) => {
                self.verify_foreign_tx_provider
                    .clone()
                    .process_channel(channel)
                    .await?
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{ParticipantId, UniqueId};
    use crate::providers::ckd::CKDTaskId;
    use crate::providers::eddsa::EddsaTaskId;
    use crate::providers::verify_foreign_tx::VerifyForeignTxTaskId;
    use mpc_primitives::{AttemptId, EpochId, KeyEventId};
    use near_indexer_primitives::CryptoHash;

    fn uid() -> UniqueId {
        UniqueId::new(ParticipantId::from_raw(0), 1, 0)
    }

    fn key_event() -> KeyEventId {
        KeyEventId::new(EpochId::new(0), DomainId(0), AttemptId(0))
    }

    #[test]
    #[expect(non_snake_case)]
    fn is_heavy_generation_task__should_classify_generation_vs_other_tasks() {
        // Given every task kind paired with whether it is CPU-heavy asset
        // generation that must run on the lower-priority gen runtime.
        let cases: [(MpcTaskId, bool); 12] = [
            // ECDSA: triples and presignatures are heavy generation.
            (
                EcdsaTaskId::ManyTriples {
                    start: uid(),
                    count: 64,
                }
                .into(),
                true,
            ),
            (
                EcdsaTaskId::Presignature {
                    id: uid(),
                    domain_id: DomainId(0),
                    paired_triple_id: uid(),
                }
                .into(),
                true,
            ),
            // ECDSA: signing and key events stay on the main runtime.
            (
                EcdsaTaskId::Signature {
                    id: CryptoHash::default(),
                    presignature_id: uid(),
                }
                .into(),
                false,
            ),
            (
                EcdsaTaskId::KeyGeneration {
                    key_event: key_event(),
                }
                .into(),
                false,
            ),
            (
                EcdsaTaskId::KeyResharing {
                    key_event: key_event(),
                }
                .into(),
                false,
            ),
            // RobustEcdsa: presignatures are heavy; signing and key events are not.
            (
                RobustEcdsaTaskId::Presignature {
                    id: uid(),
                    domain_id: DomainId(0),
                }
                .into(),
                true,
            ),
            (
                RobustEcdsaTaskId::Signature {
                    id: CryptoHash::default(),
                    presignature_id: uid(),
                }
                .into(),
                false,
            ),
            (
                RobustEcdsaTaskId::KeyGeneration {
                    key_event: key_event(),
                }
                .into(),
                false,
            ),
            (
                RobustEcdsaTaskId::KeyResharing {
                    key_event: key_event(),
                }
                .into(),
                false,
            ),
            // EdDSA, CKD, and foreign-tx verification have no background generation.
            (
                EddsaTaskId::Signature {
                    id: CryptoHash::default(),
                }
                .into(),
                false,
            ),
            (
                CKDTaskId::Ckd {
                    id: CryptoHash::default(),
                }
                .into(),
                false,
            ),
            (
                VerifyForeignTxTaskId::VerifyForeignTx {
                    id: CryptoHash::default(),
                    presignature_id: uid(),
                }
                .into(),
                false,
            ),
        ];

        for (task_id, expected) in cases {
            // When / Then
            assert_eq!(
                is_heavy_generation_task(&task_id),
                expected,
                "unexpected classification for {task_id:?}",
            );
        }
    }
}
