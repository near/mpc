use crate::config::ConfigFile;
use crate::indexer::handler::{
    CKDRequestFromChain, ChainBlockUpdate, SignatureRequestFromChain,
    VerifyForeignTxRequestFromChain,
};
use crate::indexer::tx_sender::TransactionSender;
use crate::indexer::types::{
    ChainCKDRespondArgs, ChainSendTransactionRequest, ChainSignatureRespondArgs,
    ChainVerifyForeignTransactionRespondArgs,
};
use crate::metrics;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::MpcTaskId;
use crate::providers::ckd::CKDProvider;
use crate::providers::eddsa::EddsaSignatureProvider;
use crate::providers::robust_ecdsa::RobustEcdsaSignatureProvider;
use crate::providers::verify_foreign_tx::VerifyForeignTxProvider;
use crate::providers::{EcdsaSignatureProvider, SignatureProvider};
use crate::requests::queue::{PendingRequests, CHECK_EACH_REQUEST_INTERVAL};
use crate::storage::{
    CKDRequestStorage, SignRequestStorage, VerifyForeignTransactionRequestStorage,
};
use crate::tracking::{self, AutoAbortTaskCollection};
use crate::trait_extensions::convert_to_contract_dto::IntoContractInterfaceType;
use crate::types::SignatureRequest;
use crate::types::{CKDRequest, VerifyForeignTxRequest};
use crate::web::{DebugRequest, DebugRequestKind};

use mpc_contract::crypto_shared::{derive_foreign_tx_tweak, derive_tweak, CKDResponse};
use mpc_contract::primitives::domain::{DomainId, SignatureScheme};
use near_time::Clock;
use std::collections::HashMap;
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
pub struct MpcClient {
    config: Arc<ConfigFile>,
    client: Arc<MeshNetworkClient>,
    sign_request_store: Arc<SignRequestStorage>,
    ckd_request_store: Arc<CKDRequestStorage>,
    verify_foreign_tx_request_store: Arc<VerifyForeignTransactionRequestStorage>,
    ecdsa_signature_provider: Arc<EcdsaSignatureProvider>,
    robust_ecdsa_signature_provider: Arc<RobustEcdsaSignatureProvider>,
    eddsa_signature_provider: Arc<EddsaSignatureProvider>,
    ckd_provider: Arc<CKDProvider>,
    verify_foreign_tx_provider: Arc<VerifyForeignTxProvider>,
    domain_to_scheme: HashMap<DomainId, SignatureScheme>,
}

impl MpcClient {
    #[allow(clippy::too_many_arguments)]
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
        verify_foreign_tx_provider: Arc<VerifyForeignTxProvider>,
        domain_to_scheme: HashMap<DomainId, SignatureScheme>,
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
            domain_to_scheme,
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

        let ecdsa_background_tasks = tracking::spawn(
            "ecdsa_background_tasks",
            self.ecdsa_signature_provider
                .clone()
                .spawn_background_tasks(),
        );

        let robust_ecdsa_background_tasks = tracking::spawn(
            "robust_ecdsa_background_tasks",
            self.robust_ecdsa_signature_provider
                .clone()
                .spawn_background_tasks(),
        );

        let eddsa_background_tasks = tracking::spawn(
            "eddsa_background_tasks",
            self.eddsa_signature_provider
                .clone()
                .spawn_background_tasks(),
        );

        let ckd_background_tasks = tracking::spawn(
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
            PendingRequests::<SignatureRequest, ChainSignatureRespondArgs>::new(
                Clock::real(),
                self.client.all_participant_ids(),
                self.client.my_participant_id(),
                self.client.clone(),
            );
        let mut pending_ckds = PendingRequests::<CKDRequest, ChainCKDRespondArgs>::new(
            Clock::real(),
            self.client.all_participant_ids(),
            self.client.my_participant_id(),
            self.client.clone(),
        );
        let mut pending_verify_foreign_txs = PendingRequests::<
            VerifyForeignTxRequest,
            ChainVerifyForeignTransactionRespondArgs,
        >::new(
            Clock::real(),
            self.client.all_participant_ids(),
            self.client.my_participant_id(),
            self.client.clone(),
        );

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
                    self.client.update_indexer_height(block_update.block.height);
                    let signature_requests = block_update
                        .signature_requests
                        .into_iter()
                        .map(|signature_request_from_chain| {
                            let SignatureRequestFromChain {
                                signature_id,
                                receipt_id,
                                request,
                                predecessor_id,
                                entropy,
                                timestamp_nanosec,
                            } = signature_request_from_chain;
                            let signature_request = SignatureRequest {
                                id: signature_id,
                                receipt_id,
                                payload: request.payload,
                                tweak: derive_tweak(&predecessor_id, &request.path),
                                entropy,
                                timestamp_nanosec,
                                domain: request.domain_id,
                            };
                            // Index the signature requests as soon as we see them. We'll decide
                            // whether to *process* them after.
                            self.sign_request_store.add(&signature_request);
                            signature_request
                        })
                        .collect::<Vec<_>>();

                    pending_signatures.notify_new_block(
                        signature_requests,
                        block_update.completed_signatures,
                        &block_update.block,
                    );

                    let ckd_requests = block_update
                        .ckd_requests
                        .into_iter()
                        .map(|ckd_request_from_chain| {
                            let CKDRequestFromChain {
                                ckd_id,
                                receipt_id,
                                request,
                                predecessor_id: _,
                                entropy,
                                timestamp_nanosec,
                            } = ckd_request_from_chain;
                            let ckd_request = CKDRequest {
                                id: ckd_id,
                                receipt_id,
                                app_public_key: request.app_public_key,
                                app_id: request.app_id,
                                entropy,
                                timestamp_nanosec,
                                domain_id: request.domain_id,
                            };
                            // Index the ckd requests as soon as we see them. We'll decide
                            // whether to *process* them after.
                            self.ckd_request_store.add(&ckd_request);
                            ckd_request
                        })
                        .collect::<Vec<_>>();

                    pending_ckds.notify_new_block(
                        ckd_requests,
                        block_update.completed_ckds,
                        &block_update.block,
                    );

                    let verify_foreign_tx_requests = block_update
                        .verify_foreign_tx_requests
                        .into_iter()
                        .map(|verify_foreign_tx_request_from_chain| {
                            let VerifyForeignTxRequestFromChain { verify_foreign_tx_id, receipt_id, request, predecessor_id, entropy, timestamp_nanosec } = verify_foreign_tx_request_from_chain;
                            let verify_foreign_tx_request = VerifyForeignTxRequest {
                                id: verify_foreign_tx_id,
                                receipt_id,
                                domain_id: request.domain_id.0.into(),
                                entropy,
                                payload_version: request.payload_version,
                                request: request.request,
                                timestamp_nanosec,
                                tweak: derive_foreign_tx_tweak(&predecessor_id, &request.derivation_path),
                            };
                            // Index the foreign tx requests as soon as we see them. We'll decide
                            // whether to *process* them after.
                            self.verify_foreign_tx_request_store.add(&verify_foreign_tx_request);
                            verify_foreign_tx_request
                        })
                        .collect::<Vec<_>>();

                    pending_verify_foreign_txs.notify_new_block(
                        verify_foreign_tx_requests,
                        block_update.completed_verify_foreign_txs,
                        &block_update.block,
                    );



                }
                debug_request = debug_receiver.recv() => {
                    if let Ok(debug_request) = debug_request {
                        match debug_request.kind {
                            DebugRequestKind::RecentBlocks => {
                                let debug_output = pending_signatures.debug_print_recent_blocks();
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
                                metrics::MPC_NUM_SIGNATURE_COMPUTATIONS_LED
                                    .with_label_values(&["total"])
                                    .inc();

                                let response = match this
                                    .domain_to_scheme
                                    .get(&signature_attempt.request.domain)
                                {
                                    Some(SignatureScheme::Secp256k1) => {
                                        let (signature, public_key) = timeout(
                                            Duration::from_secs(this.config.signature.timeout_sec),
                                            this.ecdsa_signature_provider
                                                .clone()
                                                .make_signature(signature_attempt.request.id),
                                        )
                                        .await??;

                                        let response = ChainSignatureRespondArgs::new_ecdsa(
                                            &signature_attempt.request,
                                            &signature,
                                            &public_key,
                                        )?;

                                        Ok(response)
                                    }
                                    Some(SignatureScheme::Ed25519) => {
                                        let (signature, _) = timeout(
                                            Duration::from_secs(this.config.signature.timeout_sec),
                                            this.eddsa_signature_provider
                                                .clone()
                                                .make_signature(signature_attempt.request.id),
                                        )
                                        .await??;

                                        let response = ChainSignatureRespondArgs::new_eddsa(
                                            &signature_attempt.request,
                                            &signature,
                                        )?;

                                        Ok(response)
                                    }
                                    Some(SignatureScheme::Bls12381) => Err(anyhow::anyhow!(
                                        "Incorrect protocol for domain: {:?}",
                                        signature_attempt.request.domain.clone()
                                    )),
                                    Some(SignatureScheme::V2Secp256k1) => {
                                        let (signature, public_key) = timeout(
                                            Duration::from_secs(this.config.signature.timeout_sec),
                                            this.robust_ecdsa_signature_provider
                                                .clone()
                                                .make_signature(signature_attempt.request.id),
                                        )
                                        .await??;

                                        let response = ChainSignatureRespondArgs::new_ecdsa(
                                            &signature_attempt.request,
                                            &signature,
                                            &public_key,
                                        )?;

                                        Ok(response)
                                    }
                                    None => Err(anyhow::anyhow!(
                                        "Signature scheme is not found for domain: {:?}",
                                        signature_attempt.request.domain.clone()
                                    )),
                                }?;

                                metrics::MPC_NUM_SIGNATURE_COMPUTATIONS_LED
                                    .with_label_values(&["succeeded"])
                                    .inc();

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
                                metrics::MPC_NUM_CKD_COMPUTATIONS_LED
                                    .with_label_values(&["total"])
                                    .inc();

                                let response = match this
                                    .domain_to_scheme
                                    .get(&ckd_attempt.request.domain_id)
                                {
                                    Some(SignatureScheme::Bls12381) => {
                                        let response = timeout(
                                            Duration::from_secs(this.config.ckd.timeout_sec),
                                            this.ckd_provider
                                                .clone()
                                                .make_signature(ckd_attempt.request.id),
                                        )
                                        .await??;

                                        let response = ChainCKDRespondArgs::new_ckd(
                                            &ckd_attempt.request,
                                            &CKDResponse {
                                                big_y: response.0 .0.into_contract_interface_type(),
                                                big_c: response.0 .1.into_contract_interface_type(),
                                            },
                                        )?;

                                        Ok(response)
                                    }
                                    Some(SignatureScheme::Secp256k1)
                                    | Some(SignatureScheme::V2Secp256k1)
                                    | Some(SignatureScheme::Ed25519) => Err(anyhow::anyhow!(
                                        "Signature scheme is not allowed for domain: {:?}",
                                        ckd_attempt.request.domain_id.clone()
                                    )),
                                    None => Err(anyhow::anyhow!(
                                        "Signature scheme is not found for domain: {:?}",
                                        ckd_attempt.request.domain_id.clone()
                                    )),
                                }?;

                                metrics::MPC_NUM_CKD_COMPUTATIONS_LED
                                    .with_label_values(&["succeeded"])
                                    .inc();

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
        }
    }

    async fn monitor_passive_channels_inner(
        mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
        mpc_client: Arc<MpcClient>,
    ) -> anyhow::Result<()> {
        let mut tasks = AutoAbortTaskCollection::new();
        while let Some(channel) = channel_receiver.recv().await {
            let mpc_clone = mpc_client.clone();
            tasks.spawn_checked(
                &format!("passive task; task_id: {:?}", channel.task_id()),
                async move { mpc_clone.process_channel_task(channel).await },
            );
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
