use crate::config::{ConfigFile, MpcConfig};
use crate::hkdf::derive_tweak;
use crate::indexer::handler::{ChainBlockUpdate, SignatureRequestFromChain};
use crate::indexer::types::{ChainRespondArgs, ChainSendTransactionRequest};
use crate::keyshare::RootKeyshareData;
use crate::metrics;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::MpcTaskId;
use crate::sign::{
    run_background_presignature_generation, FollowerPresignComputation, FollowerSignComputation,
    PresignatureStorage, SignComputation,
};
use crate::sign_request::{SignRequestStorage, SignatureId, SignatureRequest};
use crate::signing::queue::{PendingSignatureRequests, CHECK_EACH_SIGNATURE_REQUEST_INTERVAL};
use crate::tracking::{self, AutoAbortTaskCollection};
use crate::triple::{
    run_background_triple_generation, FollowerManyTripleGenerationComputation, TripleStorage,
    SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE,
};
use crate::web::{SignatureDebugRequest, SignatureDebugRequestKind};
use cait_sith::FullSignature;
use k256::{AffinePoint, Secp256k1};
use near_time::Clock;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// A one-time delay before processing signature requests on startup. This is to prevent the case
/// where we have not yet connected to all participants, and the signature processing code thinks
/// that others are offline, leading to signature requests having multiple leaders and unnecessarily
/// responded to multiple times. It doesn't affect correctness, but can make tests less flaky and
/// production runs experience fewer redundant signatures.
const INITIAL_STARTUP_SIGNATURE_PROCESSING_DELAY: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct MpcClient {
    config: Arc<ConfigFile>,
    mpc_config: Arc<MpcConfig>,
    client: Arc<MeshNetworkClient>,
    triple_store: Arc<TripleStorage>,
    presignature_store: Arc<PresignatureStorage>,
    sign_request_store: Arc<SignRequestStorage>,
    root_keyshare: RootKeyshareData,
}

impl MpcClient {
    pub fn new(
        config: Arc<ConfigFile>,
        mpc_config: Arc<MpcConfig>,
        client: Arc<MeshNetworkClient>,
        triple_store: Arc<TripleStorage>,
        presignature_store: Arc<PresignatureStorage>,
        sign_request_store: Arc<SignRequestStorage>,
        root_keyshare: RootKeyshareData,
    ) -> Self {
        Self {
            config,
            mpc_config,
            client,
            triple_store,
            presignature_store,
            sign_request_store,
            root_keyshare,
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
        chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
        signature_debug_receiver: tokio::sync::broadcast::Receiver<SignatureDebugRequest>,
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
            tracking::spawn(
                "monitor chain",
                self.clone().monitor_block_updates(
                    block_update_receiver,
                    chain_txn_sender,
                    signature_debug_receiver,
                ),
            )
        };

        let generate_triples = tracking::spawn(
            "generate triples",
            run_background_triple_generation(
                self.client.clone(),
                self.mpc_config.participants.threshold as usize,
                self.config.triple.clone().into(),
                self.triple_store.clone(),
            ),
        );

        let generate_presignatures = tracking::spawn(
            "generate presignatures",
            run_background_presignature_generation(
                self.client.clone(),
                self.mpc_config.participants.threshold as usize,
                self.config.presignature.clone().into(),
                self.triple_store.clone(),
                self.presignature_store.clone(),
                self.root_keyshare.keygen_output(),
            ),
        );

        let _ = monitor_passive_channels.await?;
        metrics_emitter.await?;
        monitor_chain.await?;
        generate_triples.await??;
        generate_presignatures.await??;

        Ok(())
    }

    async fn monitor_block_updates(
        self: Arc<Self>,
        mut block_update_receiver: tokio::sync::OwnedMutexGuard<
            mpsc::UnboundedReceiver<ChainBlockUpdate>,
        >,
        chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
        mut signature_debug_receiver: tokio::sync::broadcast::Receiver<SignatureDebugRequest>,
    ) {
        let mut tasks = AutoAbortTaskCollection::new();
        let mut pending_signatures = PendingSignatureRequests::new(
            Clock::real(),
            self.client.all_participant_ids(),
            self.client.my_participant_id(),
            self.client.clone(),
        );

        let start_time = Clock::real().now();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(CHECK_EACH_SIGNATURE_REQUEST_INTERVAL.unsigned_abs()) => {
                }
                block_update = block_update_receiver.recv() => {
                    let Some(block_update) = block_update else {
                        // If this branch hits, it means the channel is closed, meaning the
                        // indexer is being shutdown. So just quit this task.
                        break;
                    };
                    self.client.update_indexer_height(block_update.block.height);
                    let signature_requests = block_update
                        .signature_requests
                        .into_iter()
                        .map(|signature_request| {
                            let SignatureRequestFromChain {
                                signature_id,
                                receipt_id,
                                request,
                                predecessor_id,
                                entropy,
                                timestamp_nanosec,
                            } = signature_request;
                            SignatureRequest {
                                id: signature_id,
                                receipt_id,
                                msg_hash: request.payload,
                                tweak: derive_tweak(&predecessor_id, &request.path),
                                entropy,
                                timestamp_nanosec,
                            }
                        })
                        .collect::<Vec<_>>();

                    // Index the signature requests as soon as we see them. We'll decide
                    // whether to *process* them after.
                    for signature_request in &signature_requests {
                        self.sign_request_store.add(signature_request);
                    }
                    pending_signatures.notify_new_block(
                        signature_requests,
                        block_update.completed_signatures,
                        &block_update.block,
                    );
                }
                debug_request = signature_debug_receiver.recv() => {
                    if let Ok(debug_request) = debug_request {
                        match debug_request.kind {
                            SignatureDebugRequestKind::RecentBlocks => {
                                let debug_output = pending_signatures.debug_print_recent_blocks();
                                debug_request.respond(debug_output);
                            }
                            SignatureDebugRequestKind::RecentSignatures => {
                                let debug_output = format!("{:?}", pending_signatures);
                                debug_request.respond(debug_output);
                            }
                        }
                    }
                }
            }

            if start_time.elapsed() < INITIAL_STARTUP_SIGNATURE_PROCESSING_DELAY {
                continue;
            }
            let signature_attempts = pending_signatures.get_signatures_to_attempt();

            for signature_attempt in signature_attempts {
                let this = self.clone();
                let chain_txn_sender = chain_txn_sender.clone();
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
                                metrics::MPC_NUM_SIGNATURE_COMPUTATIONS_LED
                                    .with_label_values(&["total"])
                                    .inc();

                                let (signature, public_key) = timeout(
                                    Duration::from_secs(this.config.signature.timeout_sec),
                                    this.clone().make_signature(signature_attempt.request.id),
                                )
                                .await??;

                                metrics::MPC_NUM_SIGNATURE_COMPUTATIONS_LED
                                    .with_label_values(&["succeeded"])
                                    .inc();

                                let response = ChainRespondArgs::new(
                                    &signature_attempt.request,
                                    &signature,
                                    &public_key,
                                )?;
                                signature_attempt
                                    .computation_progress
                                    .lock()
                                    .unwrap()
                                    .computed_response = Some(response.clone());
                                response
                            }
                            Some(response) => response,
                        };
                        let _ = chain_txn_sender
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
        }
    }

    async fn monitor_passive_channels_inner(
        mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
        mpc_client: Arc<MpcClient>,
    ) -> anyhow::Result<()> {
        let mut tasks = AutoAbortTaskCollection::new();
        loop {
            let channel = channel_receiver.recv().await.unwrap();
            let mpc_clone = mpc_client.clone();
            tasks.spawn_checked(
                &format!("passive task {:?}", channel.task_id()),
                async move { mpc_clone.process_channel_task(channel).await },
            );
        }
    }

    async fn process_channel_task(
        self: Arc<Self>,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<()> {
        match channel.task_id() {
            MpcTaskId::KeyGeneration => {
                anyhow::bail!("Key generation rejected in normal node operation");
            }
            MpcTaskId::KeyResharing { .. } => {
                anyhow::bail!("Key resharing rejected in normal node operation");
            }
            MpcTaskId::ManyTriples { start, count } => {
                if count as usize != SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE {
                    return Err(anyhow::anyhow!(
                        "Unsupported batch size for triple generation"
                    ));
                }
                FollowerManyTripleGenerationComputation::<SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE> {
                    threshold: self.mpc_config.participants.threshold as usize,
                    out_triple_id_start: start,
                    out_triple_store: self.triple_store.clone(),
                }
                .perform_leader_centric_computation(
                    channel,
                    Duration::from_secs(self.config.triple.timeout_sec),
                )
                .await?;
            }
            MpcTaskId::Presignature {
                id,
                paired_triple_id,
            } => {
                FollowerPresignComputation {
                    threshold: self.mpc_config.participants.threshold as usize,
                    keygen_out: self.root_keyshare.keygen_output(),
                    triple_store: self.triple_store.clone(),
                    paired_triple_id,
                    out_presignature_store: self.presignature_store.clone(),
                    out_presignature_id: id,
                }
                .perform_leader_centric_computation(
                    channel,
                    Duration::from_secs(self.config.presignature.timeout_sec),
                )
                .await?;
            }
            MpcTaskId::Signature {
                id,
                presignature_id,
            } => {
                metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_RECEIVED.inc();
                let SignatureRequest {
                    msg_hash,
                    tweak,
                    entropy,
                    ..
                } = timeout(
                    Duration::from_secs(self.config.signature.timeout_sec),
                    self.sign_request_store.get(id),
                )
                .await??;
                metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_LOOKUP_SUCCEEDED.inc();

                FollowerSignComputation {
                    keygen_out: self.root_keyshare.keygen_output(),
                    presignature_store: self.presignature_store.clone(),
                    presignature_id,
                    msg_hash,
                    tweak,
                    entropy,
                }
                .perform_leader_centric_computation(
                    channel,
                    Duration::from_secs(self.config.signature.timeout_sec),
                )
                .await?;
            }
        }

        Ok(())
    }

    pub async fn make_signature(
        self: Arc<Self>,
        id: SignatureId,
    ) -> anyhow::Result<(FullSignature<Secp256k1>, AffinePoint)> {
        let (presignature_id, presignature) = self.presignature_store.take_owned().await;
        let sign_request = self.sign_request_store.get(id).await?;
        let channel = self.client.new_channel_for_task(
            MpcTaskId::Signature {
                id,
                presignature_id,
            },
            presignature.participants,
        )?;
        let keygen_output = self.root_keyshare.keygen_output();
        let (signature, public_key) = SignComputation {
            keygen_out: keygen_output,
            presign_out: presignature.presignature,
            msg_hash: sign_request.msg_hash,
            tweak: sign_request.tweak,
            entropy: sign_request.entropy,
        }
        .perform_leader_centric_computation(
            channel,
            Duration::from_secs(self.config.signature.timeout_sec),
        )
        .await?;

        Ok((signature, public_key))
    }
}
