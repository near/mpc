use super::tx_signer::TransactionSigners;
//use super::tx_signer::{TransactionSigner, TransactionSigners};
use super::{ChainSendTransactionRequest, MpcContractStateViewer};
use crate::config::RespondConfig;
use crate::metrics;
use anyhow::Context;
use chain_gateway::transaction_sender::TransactionSigner;
//use chain_gateway::chain_gateway::SharedContractViewer;
use contract_interface::types::{Attestation, VerifiedAttestation};
use ed25519_dalek::SigningKey;
use mpc_attestation::attestation::DEFAULT_EXPIRATION_DURATION_SECONDS;
use near_account_id::AccountId;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, oneshot};
use tokio::time;

const TRANSACTION_PROCESSOR_CHANNEL_SIZE: usize = 10000;
const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_ATTESTATION_AGE: Duration = Duration::from_secs(60 * 2);

pub trait TransactionSender: Clone + Send + Sync {
    fn send(
        &self,
        transaction: ChainSendTransactionRequest,
    ) -> impl Future<Output = Result<(), TransactionProcessorError>> + Send;

    fn send_and_wait(
        &self,
        transaction: ChainSendTransactionRequest,
    ) -> impl Future<Output = Result<TransactionStatus, TransactionProcessorError>> + Send;
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum TransactionProcessorError {
    #[error("The transaction processor is closed.")]
    ProcessorIsClosed,
}

#[derive(Clone, Debug)]
pub struct TransactionProcessorHandle {
    transaction_sender: mpsc::Sender<TransactionSenderSubmission>,
}

impl TransactionProcessorHandle {
    pub(crate) fn start_transaction_processor(
        owner_account_id: AccountId,
        owner_secret_key: SigningKey,
        config: RespondConfig,
        mpc_contract_id: AccountId,
        mpc_contract_state_viewer: MpcContractStateViewer,
        tx_sender: Arc<chain_gateway::transaction_sender::TransactionSender>,
    ) -> anyhow::Result<impl TransactionSender> {
        let mut signers = TransactionSigners::new(config, owner_account_id, owner_secret_key)
            .context("Failed to initialize transaction signers")?;

        let (transaction_sender, mut transaction_receiver) =
            mpsc::channel::<TransactionSenderSubmission>(TRANSACTION_PROCESSOR_CHANNEL_SIZE);

        tokio::spawn(async move {
            while let Some(transaction_submission) = transaction_receiver.recv().await {
                let tx_request = transaction_submission.transaction;
                let tx_response_channel = transaction_submission.response_sender;

                let tx_signer = signers.signer_for(&tx_request);
                let mpc_contract_state_viewer_clone = mpc_contract_state_viewer.clone();
                let tx_sender_clone = tx_sender.clone();
                let mpc_contract_id_clone = mpc_contract_id.clone();
                tokio::spawn(async move {
                    let Ok(txn_json) = serde_json::to_string(&tx_request) else {
                        tracing::error!(target: "mpc", "Failed to serialize response args");
                        return;
                    };
                    tracing::debug!(target = "mpc", "tx args {:?}", txn_json);
                    let transaction_status = ensure_send_transaction(
                        tx_signer.clone(),
                        tx_sender_clone,
                        mpc_contract_id_clone,
                        tx_request,
                        txn_json,
                        mpc_contract_state_viewer_clone,
                    )
                    .await;

                    if let Some(tx_response_channel) = tx_response_channel {
                        let _ = tx_response_channel.send(transaction_status);
                    }
                });
            }
        });

        Ok(TransactionProcessorHandle { transaction_sender })
    }
}

impl TransactionSender for TransactionProcessorHandle {
    async fn send(
        &self,
        transaction: ChainSendTransactionRequest,
    ) -> Result<(), TransactionProcessorError> {
        self.transaction_sender
            .send(TransactionSenderSubmission {
                transaction,
                response_sender: None,
            })
            .await
            .map_err(|_| TransactionProcessorError::ProcessorIsClosed)
    }

    async fn send_and_wait(
        &self,
        transaction: ChainSendTransactionRequest,
    ) -> Result<TransactionStatus, TransactionProcessorError> {
        let (response_sender, response_receiver) = oneshot::channel();

        self.transaction_sender
            .send(TransactionSenderSubmission {
                transaction,
                response_sender: Some(response_sender),
            })
            .await
            .map_err(|_| TransactionProcessorError::ProcessorIsClosed)?;

        response_receiver
            .await
            .map_err(|_| TransactionProcessorError::ProcessorIsClosed)
    }
}

struct TransactionSenderSubmission {
    transaction: ChainSendTransactionRequest,
    response_sender: Option<oneshot::Sender<TransactionStatus>>,
}

#[derive(Debug)]
pub enum TransactionStatus {
    Executed,
    NotExecuted,
    Unknown,
}

/// Confirms whether the intended effect of the transaction request has been observed on chain.
async fn observe_tx_result(
    mpc_contract: MpcContractStateViewer,
    request: &ChainSendTransactionRequest,
) -> anyhow::Result<TransactionStatus> {
    use ChainSendTransactionRequest::*;

    match request {
        Respond(respond_args) => {
            // Confirm whether the respond call succeeded by checking whether the
            // pending signature request still exists in the contract state
            let pending_request_response = mpc_contract
                .get_pending_request(&respond_args.request)
                .await?;

            let transaction_status = match pending_request_response {
                Some(_) => TransactionStatus::Executed,
                None => TransactionStatus::NotExecuted,
            };

            Ok(transaction_status)
        }
        CKDRespond(respond_args) => {
            // Confirm whether the respond call succeeded by checking whether the
            // pending ckd request still exists in the contract state
            let pending_request_response = mpc_contract
                .get_pending_ckd_request(&respond_args.request)
                .await?;

            let transaction_status = match pending_request_response {
                Some(_) => TransactionStatus::Executed,
                None => TransactionStatus::NotExecuted,
            };

            Ok(transaction_status)
        }
        VerifyForeignTransactionRespond(respond_args) => {
            // Confirm whether the respond call succeeded by checking whether the
            // pending verify foreign tx request still exists in the contract state
            let pending_request_response = mpc_contract
                .get_pending_verify_foreign_tx_request(&respond_args.request)
                .await?;

            let transaction_status = match pending_request_response {
                Some(_) => TransactionStatus::Executed,
                None => TransactionStatus::NotExecuted,
            };

            Ok(transaction_status)
        }
        SubmitParticipantInfo(submit_participant_info_args) => {
            let tls_public_key = &submit_participant_info_args.tls_public_key;

            let attestation_stored_on_contract = mpc_contract
                .get_participant_attestation(tls_public_key)
                .await?;

            let Some(stored_attestation) = attestation_stored_on_contract else {
                return Ok(TransactionStatus::NotExecuted);
            };

            let submitted_attestation =
                &submit_participant_info_args.proposed_participant_attestation;

            let submitted_attestation_is_on_chain =
                match (stored_attestation, submitted_attestation) {
                    (
                        VerifiedAttestation::Dstack(verified_dstack_attestation),
                        Attestation::Dstack(_),
                    ) => {
                        // Check if the attestation stored on chain is fresh by verifying its age
                        // is less than `MAX_ATTESTATION_AGE`
                        //
                        // TODO(#1637): extract expiration timestamp from the certificate itself,
                        // instead of using heuristics.
                        let expiry_timestamp_seconds =
                            verified_dstack_attestation.expiry_timestamp_seconds;

                        let Some(attestation_duration_since_unix_epoch) = expiry_timestamp_seconds
                            .checked_sub(DEFAULT_EXPIRATION_DURATION_SECONDS)
                            .map(Duration::from_secs)
                        else {
                            tracing::error!(
                                ?expiry_timestamp_seconds,
                                "could not calculate attestation storage time"
                            );

                            return Ok(TransactionStatus::NotExecuted);
                        };

                        let timestamp_seconds_now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .context("could not calculate system time")?;

                        let attestation_age =
                            attestation_duration_since_unix_epoch.abs_diff(timestamp_seconds_now);
                        let attestation_is_fresh = attestation_age < MAX_ATTESTATION_AGE;

                        tracing::info!(
                            ?attestation_age,
                            ?attestation_is_fresh,
                            "node found dstack attestation on chain"
                        );

                        attestation_is_fresh
                    }
                    (
                        VerifiedAttestation::Mock(stored_mock_attestation),
                        Attestation::Mock(submitted_mock_attestation),
                    ) => stored_mock_attestation == *submitted_mock_attestation,
                    _ => false,
                };

            if submitted_attestation_is_on_chain {
                Ok(TransactionStatus::Executed)
            } else {
                Ok(TransactionStatus::NotExecuted)
            }
        }
        // We don't care. The contract state change will handle this.
        StartKeygen(_)
        | StartReshare(_)
        | VotePk(_)
        | VoteReshared(_)
        | VoteAbortKeyEventInstance(_)
        | VerifyTee()
        | ConcludeNodeMigration(_)
        | VoteForeignChainPolicy(_) => Ok(TransactionStatus::Unknown),
    }
}

/// Attempts to ensure that a function call with given method and args is included on-chain.
/// If the submitted transaction is not observed by the indexer before the `timeout`, tries again.
/// Will make up to `num_attempts` attempts.
async fn ensure_send_transaction(
    tx_signer: Arc<TransactionSigner>,
    tx_sender: Arc<chain_gateway::transaction_sender::TransactionSender>,
    contract_id: near_account_id::AccountId,
    request: ChainSendTransactionRequest,
    params_ser: String,
    mpc_contract: MpcContractStateViewer,
) -> TransactionStatus {
    if let Err(err) = tx_sender
        .submit_function_call_tx(
            tx_signer.clone(),
            contract_id,
            request.method().to_string(),
            params_ser.into(),
            request.gas_required(),
        )
        .await
    {
        metrics::MPC_OUTGOING_TRANSACTION_OUTCOMES
            .with_label_values(&[request.method(), "local_error"])
            .inc();
        tracing::error!(%err, "Failed to forward transaction {:?}", request);
        return TransactionStatus::NotExecuted;
    };

    // Allow time for the transaction to be included
    time::sleep(TRANSACTION_TIMEOUT).await;

    // Then try to check whether it had the intended effect
    let transaction_status = observe_tx_result(mpc_contract, &request).await;

    match &transaction_status {
        Ok(TransactionStatus::Executed) => {
            metrics::MPC_OUTGOING_TRANSACTION_OUTCOMES
                .with_label_values(&[request.method(), "succeeded"])
                .inc();
        }
        Ok(TransactionStatus::NotExecuted) => {
            metrics::MPC_OUTGOING_TRANSACTION_OUTCOMES
                .with_label_values(&[request.method(), "timed_out"])
                .inc();
        }
        Ok(TransactionStatus::Unknown) => {
            metrics::MPC_OUTGOING_TRANSACTION_OUTCOMES
                .with_label_values(&[request.method(), "unknown"])
                .inc();
        }
        Err(err) => {
            metrics::MPC_OUTGOING_TRANSACTION_OUTCOMES
                .with_label_values(&[request.method(), "unknown_err"])
                .inc();
            tracing::warn!(target:"mpc", %err, "encountered error trying to confirm result of transaction {:?}", request);
        }
    }

    transaction_status.unwrap_or(TransactionStatus::Unknown)
}
