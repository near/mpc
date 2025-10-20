use super::tx_signer::{TransactionSigner, TransactionSigners};
use super::types::ChainGetPendingSignatureRequestArgs;
use super::ChainSendTransactionRequest;
use super::IndexerState;
use crate::config::RespondConfig;
use crate::indexer::types::{ChainGetPendingCKDRequestArgs, GetAttestationArgs};
use crate::metrics;
use anyhow::Context;
use ed25519_dalek::SigningKey;
use mpc_contract::primitives::signature::YieldIndex;
use near_client::Query;
use near_indexer_primitives::types::Gas;
use near_indexer_primitives::types::{BlockReference, Finality};
use near_indexer_primitives::views::{QueryRequest, QueryResponseKind};
use near_o11y::WithSpanContextExt;
use near_sdk::AccountId;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time;

const TRANSACTION_PROCESSOR_CHANNEL_SIZE: usize = 10000;
const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(10);

const GET_TEE_ATTESTATION_METHOD_NAME: &str = "get_attestation";

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
        indexer_state: Arc<IndexerState>,
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
                let indexer_state = indexer_state.clone();
                tokio::spawn(async move {
                    let Ok(txn_json) = serde_json::to_string(&tx_request) else {
                        tracing::error!(target: "mpc", "Failed to serialize response args");
                        return;
                    };
                    tracing::debug!(target = "mpc", "tx args {:?}", txn_json);
                    let transaction_status = ensure_send_transaction(
                        tx_signer.clone(),
                        indexer_state,
                        tx_request,
                        txn_json,
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

/// Creates, signs, and submits a function call with the given method and serialized arguments.
async fn submit_tx(
    tx_signer: Arc<TransactionSigner>,
    indexer_state: Arc<IndexerState>,
    method: String,
    params_ser: String,
    gas: Gas,
) -> anyhow::Result<()> {
    let block = indexer_state
        .view_client
        .send(near_client::GetBlock(BlockReference::Finality(Finality::Final)).with_span_context())
        .await??;

    let transaction = tx_signer.create_and_sign_function_call_tx(
        indexer_state.mpc_contract_id.clone(),
        method,
        params_ser.into(),
        gas,
        block.header.hash,
        block.header.height,
    );

    let tx_hash = transaction.get_hash();
    tracing::info!(
        target = "mpc",
        "sending tx {:?} with ak={:?} nonce={}",
        tx_hash,
        tx_signer.public_key(),
        transaction.transaction.nonce(),
    );

    let response = indexer_state
        .tx_processor
        .send(
            near_client::ProcessTxRequest {
                transaction,
                is_forwarded: false,
                check_only: false,
            }
            .with_span_context(),
        )
        .await?;
    match response {
        // We're not a validator, so we should always be routing the transaction.
        near_client::ProcessTxResponse::RequestRouted => Ok(()),
        _ => {
            anyhow::bail!("unexpected ProcessTxResponse: {:?}", response);
        }
    }
}

/// Confirms whether the intended effect of the transaction request has been observed on chain.
async fn observe_tx_result(
    indexer_state: Arc<IndexerState>,
    request: &ChainSendTransactionRequest,
) -> anyhow::Result<TransactionStatus> {
    use ChainSendTransactionRequest::*;

    match request {
        Respond(respond_args) => {
            // Confirm whether the respond call succeeded by checking whether the
            // pending signature request still exists in the contract state
            let get_pending_request_args: Vec<u8> =
                serde_json::to_string(&ChainGetPendingSignatureRequestArgs {
                    request: respond_args.request.clone(),
                })
                .unwrap()
                .into_bytes();
            let query_response = indexer_state
                .view_client
                .send(
                    Query {
                        block_reference: BlockReference::Finality(Finality::Final),
                        request: QueryRequest::CallFunction {
                            account_id: indexer_state.mpc_contract_id.clone(),
                            method_name: "get_pending_request".to_string(),
                            args: get_pending_request_args.into(),
                        },
                    }
                    .with_span_context(),
                )
                .await??;
            match query_response.kind {
                QueryResponseKind::CallResult(call_result) => {
                    let pending_request =
                        serde_json::from_slice::<Option<YieldIndex>>(&call_result.result)?;
                    Ok(if pending_request.is_none() {
                        TransactionStatus::Executed
                    } else {
                        TransactionStatus::NotExecuted
                    })
                }
                _ => {
                    anyhow::bail!("Unexpected result from a view client function call");
                }
            }
        }
        CKDRespond(respond_args) => {
            // Confirm whether the respond call succeeded by checking whether the
            // pending ckd request still exists in the contract state
            let get_pending_request_args: Vec<u8> =
                serde_json::to_string(&ChainGetPendingCKDRequestArgs {
                    request: respond_args.request.clone(),
                })
                .unwrap()
                .into_bytes();
            let query_response = indexer_state
                .view_client
                .send(
                    Query {
                        block_reference: BlockReference::Finality(Finality::Final),
                        request: QueryRequest::CallFunction {
                            account_id: indexer_state.mpc_contract_id.clone(),
                            method_name: "get_pending_ckd_request".to_string(),
                            args: get_pending_request_args.into(),
                        },
                    }
                    .with_span_context(),
                )
                .await??;
            match query_response.kind {
                QueryResponseKind::CallResult(call_result) => {
                    let pending_request =
                        serde_json::from_slice::<Option<YieldIndex>>(&call_result.result)?;
                    Ok(if pending_request.is_none() {
                        TransactionStatus::Executed
                    } else {
                        TransactionStatus::NotExecuted
                    })
                }
                _ => {
                    anyhow::bail!("Unexpected result from a view client function call");
                }
            }
        }
        SubmitParticipantInfo(submit_participant_info_args) => {
            let get_attestation_args: Vec<u8> = serde_json::to_string(&GetAttestationArgs {
                tls_public_key: submit_participant_info_args.tls_public_key.clone(),
            })
            .unwrap()
            .into_bytes();

            let query_response = indexer_state
                .view_client
                .send(
                    Query {
                        block_reference: BlockReference::Finality(Finality::Final),
                        request: QueryRequest::CallFunction {
                            account_id: indexer_state.mpc_contract_id.clone(),
                            method_name: GET_TEE_ATTESTATION_METHOD_NAME.to_string(),
                            args: get_attestation_args.into(),
                        },
                    }
                    .with_span_context(),
                )
                .await;

            let query_response = match query_response {
                Ok(Ok(query_response)) => query_response,
                error => {
                    tracing::error!(
                        ?error,
                        "failed to query for TEE attestation submission result"
                    );
                    return Ok(TransactionStatus::Unknown);
                }
            };
            let attestation_stored_on_contract: Option<contract_interface::types::Attestation> =
                match query_response.kind {
                    QueryResponseKind::CallResult(result) => serde_json::from_slice(&result.result)
                        .context("Failed to deserialize get_tee_accounts response")?,
                    _ => {
                        anyhow::bail!("got unexpected response querying mpc contract state")
                    }
                };

            let submitted_attestation_is_on_chain =
                attestation_stored_on_contract.is_some_and(|stored_attestation| {
                    stored_attestation
                        == submit_participant_info_args.proposed_participant_attestation
                });

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
        | ConcludeNodeMigration(_) => Ok(TransactionStatus::Unknown),
    }
}

/// Attempts to ensure that a function call with given method and args is included on-chain.
/// If the submitted transaction is not observed by the indexer before the `timeout`, tries again.
/// Will make up to `num_attempts` attempts.
async fn ensure_send_transaction(
    tx_signer: Arc<TransactionSigner>,
    indexer_state: Arc<IndexerState>,
    request: ChainSendTransactionRequest,
    params_ser: String,
) -> TransactionStatus {
    if let Err(err) = submit_tx(
        tx_signer.clone(),
        indexer_state.clone(),
        request.method().to_string(),
        params_ser.clone(),
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
    let transaction_status = observe_tx_result(indexer_state.clone(), &request).await;

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
