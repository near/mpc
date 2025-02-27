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
use cait_sith::FullSignature;
use k256::{AffinePoint, Secp256k1};
use near_time::Clock;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

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
        self,
        channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
        mut block_update_receiver: tokio::sync::OwnedMutexGuard<
            mpsc::UnboundedReceiver<ChainBlockUpdate>,
        >,
        chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
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
            let this = Arc::new(self.clone());
            let config = self.config.clone();
            let network_client = self.client.clone();
            tracking::spawn("monitor chain", async move {
                let mut tasks = AutoAbortTaskCollection::new();
                let mut pending_signatures = PendingSignatureRequests::new(
                    Clock::real(),
                    network_client.all_participant_ids(),
                    network_client.my_participant_id(),
                    network_client.clone(),
                );

                loop {
                    let this = this.clone();
                    let config = config.clone();
                    let sign_request_store = self.sign_request_store.clone();
                    let chain_tx_sender = chain_txn_sender.clone();

                    match tokio::time::timeout(
                        CHECK_EACH_SIGNATURE_REQUEST_INTERVAL.unsigned_abs(),
                        block_update_receiver.recv(),
                    )
                    .await
                    {
                        Ok(Some(block_update)) => {
                            network_client.update_indexer_height(block_update.block.height);
                            let signature_requests = block_update
                                .signature_requests
                                .into_iter()
                                .map(|signature_request| {
                                    let SignatureRequestFromChain {
                                        request_id,
                                        request,
                                        predecessor_id,
                                        entropy,
                                        timestamp_nanosec,
                                    } = signature_request;
                                    SignatureRequest {
                                        id: request_id,
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
                                sign_request_store.add(signature_request);
                            }
                            pending_signatures.notify_new_block(
                                signature_requests,
                                block_update.completed_signatures,
                                &block_update.block,
                            );
                        }
                        Ok(None) => {
                            // If this branch hits, it means the channel is closed, meaning the
                            // indexer is being shutdown. So just quit this task.
                            break;
                        }
                        Err(_) => {
                            // Timeout; just continue the iteration.
                        }
                    }

                    let signature_attempts = pending_signatures.get_signatures_to_attempt();

                    for signature_attempt in signature_attempts {
                        let this = this.clone();
                        let config = config.clone();
                        let chain_tx_sender = chain_tx_sender.clone();
                        tasks.spawn_checked(
                            &format!(
                                "leader for signature request {:?}",
                                signature_attempt.request.id
                            ),
                            async move {
                                metrics::MPC_NUM_SIGN_REQUESTS_LEADER
                                    .with_label_values(&["total"])
                                    .inc();

                                let (signature, public_key) = timeout(
                                    Duration::from_secs(config.signature.timeout_sec),
                                    this.clone().make_signature(signature_attempt.request.id),
                                )
                                .await??;

                                metrics::MPC_NUM_SIGN_REQUESTS_LEADER
                                    .with_label_values(&["succeeded"])
                                    .inc();

                                let response = ChainRespondArgs::new(
                                    &signature_attempt.request,
                                    &signature,
                                    &public_key,
                                )?;
                                let _ = chain_tx_sender
                                    .send(ChainSendTransactionRequest::Respond(response))
                                    .await;

                                anyhow::Ok(())
                            },
                        );
                    }
                }
            })
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

    async fn monitor_passive_channels_inner(
        mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
        mpc_client: MpcClient,
    ) -> anyhow::Result<()> {
        let mut tasks = AutoAbortTaskCollection::new();
        loop {
            let channel = channel_receiver.recv().await.unwrap();
            let mpc_clone = mpc_client.clone();
            tasks.spawn_checked(
                &format!("passive task {:?}", channel.task_id()),
                async move { MpcClient::process_channel_task(channel, mpc_clone).await },
            );
        }
    }

    async fn process_channel_task(
        channel: NetworkTaskChannel,
        mpc_client: MpcClient,
    ) -> anyhow::Result<()> {
        let MpcClient {
            config,
            mpc_config,
            triple_store,
            presignature_store,
            root_keyshare,
            sign_request_store,
            ..
        } = mpc_client;
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
                    threshold: mpc_config.participants.threshold as usize,
                    out_triple_id_start: start,
                    out_triple_store: triple_store.clone(),
                }
                .perform_leader_centric_computation(
                    channel,
                    Duration::from_secs(config.triple.timeout_sec),
                )
                .await?;
            }
            MpcTaskId::Presignature {
                id,
                paired_triple_id,
            } => {
                FollowerPresignComputation {
                    threshold: mpc_config.participants.threshold as usize,
                    keygen_out: root_keyshare.keygen_output(),
                    triple_store: triple_store.clone(),
                    paired_triple_id,
                    out_presignature_store: presignature_store.clone(),
                    out_presignature_id: id,
                }
                .perform_leader_centric_computation(
                    channel,
                    Duration::from_secs(config.presignature.timeout_sec),
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
                    Duration::from_secs(config.signature.timeout_sec),
                    sign_request_store.get(id),
                )
                .await??;
                metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_LOOKUP_SUCCEEDED.inc();

                FollowerSignComputation {
                    keygen_out: root_keyshare.keygen_output(),
                    presignature_store: presignature_store.clone(),
                    presignature_id,
                    msg_hash,
                    tweak,
                    entropy,
                }
                .perform_leader_centric_computation(
                    channel,
                    Duration::from_secs(config.signature.timeout_sec),
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
