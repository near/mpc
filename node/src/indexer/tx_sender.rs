use super::tx_signer::{TransactionSigner, TransactionSigners};
use super::types::ChainGetPendingSignatureRequestArgs;
use super::ChainSendTransactionRequest;
use super::IndexerState;
use crate::config::RespondConfig;
use crate::indexer::types::{ChainGetPendingCKDRequestArgs, GetApprovedAttestationsArgs};
use crate::metrics;
use anyhow::Context;
use ed25519_dalek::SigningKey;
use legacy_mpc_contract;
use near_client::Query;
use near_indexer_primitives::types::Gas;
use near_indexer_primitives::types::{BlockReference, Finality};
use near_indexer_primitives::views::{QueryRequest, QueryResponseKind};
use near_o11y::WithSpanContextExt;
use near_sdk::AccountId;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;

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

enum ChainTransactionState {
    Executed,
    NotExecuted,
    Unknown,
    NotExecutedTransient,
}

/// Confirms whether the intended effect of the transaction request has been observed on chain.
async fn observe_tx_result(
    indexer_state: Arc<IndexerState>,
    request: &ChainSendTransactionRequest,
    owner_account_id: &AccountId,
) -> anyhow::Result<ChainTransactionState> {
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
                    let pending_request = serde_json::from_slice::<
                        Option<legacy_mpc_contract::primitives::YieldIndex>,
                    >(&call_result.result)?;
                    Ok(if pending_request.is_none() {
                        ChainTransactionState::Executed
                    } else {
                        ChainTransactionState::NotExecuted
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
                    let pending_request = serde_json::from_slice::<
                        Option<legacy_mpc_contract::primitives::YieldIndex>,
                    >(&call_result.result)?;
                    Ok(if pending_request.is_none() {
                        ChainTransactionState::Executed
                    } else {
                        ChainTransactionState::NotExecuted
                    })
                }
                _ => {
                    anyhow::bail!("Unexpected result from a view client function call");
                }
            }
        }
        SubmitParticipantInfo(_submit_participant_info_args) => {
            // Confirm whether the attestation submission call succeeded by checking if the local node
            // is in the list of nodes with valid attestations.
            let get_pending_request_args: Vec<u8> =
                serde_json::to_string(&GetApprovedAttestationsArgs)
                    .unwrap()
                    .into_bytes();

            let Ok(Ok(query_response)) = indexer_state
                .view_client
                .send(
                    Query {
                        block_reference: BlockReference::Finality(Finality::Final),
                        request: QueryRequest::CallFunction {
                            account_id: indexer_state.mpc_contract_id.clone(),
                            method_name: "get_tee_accounts".to_string(),
                            args: get_pending_request_args.into(),
                        },
                    }
                    .with_span_context(),
                )
                .await
            else {
                return Ok(ChainTransactionState::NotExecutedTransient);
            };

            let accounts_with_attestations: Vec<AccountId> = match query_response.kind {
                QueryResponseKind::CallResult(result) => serde_json::from_slice(&result.result)
                    .context("Failed to deserialize get_tee_accounts response")?,
                _ => {
                    anyhow::bail!("got unexpected response querying mpc contract state")
                }
            };

            let node_has_valid_attestation = accounts_with_attestations.contains(owner_account_id);

            if node_has_valid_attestation {
                Ok(ChainTransactionState::Executed)
            } else {
                Ok(ChainTransactionState::NotExecutedTransient)
            }
        }

        // We don't care. The contract state change will handle this.
        StartKeygen(_)
        | StartReshare(_)
        | VotePk(_)
        | VoteReshared(_)
        | VoteAbortKeyEventInstance(_)
        | VerifyTee() => Ok(ChainTransactionState::Unknown),
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
    timeout: Duration,
    owner_account_id: AccountId,
) {
    let retry_attempts = match &request {
        // Attestation submissions must be submitted, otherwise the node will be kicked out. For that reason
        // the node will retry submitting attestation indefinitely as they can be missed by the contract for reasons such as:
        // - Operator has not assigned node generated key as an access key.
        // - Contract is initializing
        ChainSendTransactionRequest::SubmitParticipantInfo(_) => NonZeroUsize::MAX,
        // tx results appear useful. We should probably export some metrics from the
        // signature processing pipeline instead, and remove this retry.
        // TODO(#226): We no longer need retries. However, the metrics from querying the
        _ => NonZeroUsize::new(1).unwrap(),
    };

    for _ in 0..retry_attempts.into() {
        if let Err(err) = submit_tx(
            tx_signer.clone(),
            indexer_state.clone(),
            request.method().to_string(),
            params_ser.clone(),
            request.gas_required(),
        )
        .await
        {
            // If the transaction fails to send immediately, wait a short period and try again
            metrics::MPC_OUTGOING_TRANSACTION_OUTCOMES
                .with_label_values(&[request.method(), "local_error"])
                .inc();
            tracing::error!(%err, "Failed to forward transaction {:?}", request);
            time::sleep(Duration::from_secs(1)).await;
            continue;
        };

        // Allow time for the transaction to be included
        time::sleep(timeout).await;
        // Then try to check whether it had the intended effect
        match observe_tx_result(indexer_state.clone(), &request, &owner_account_id).await {
            Ok(ChainTransactionState::Executed) => {
                metrics::MPC_OUTGOING_TRANSACTION_OUTCOMES
                    .with_label_values(&[request.method(), "succeeded"])
                    .inc();
                return;
            }
            Ok(ChainTransactionState::NotExecuted) => {
                metrics::MPC_OUTGOING_TRANSACTION_OUTCOMES
                    .with_label_values(&[request.method(), "timed_out"])
                    .inc();
                continue;
            }
            Ok(ChainTransactionState::Unknown) => {
                metrics::MPC_OUTGOING_TRANSACTION_OUTCOMES
                    .with_label_values(&[request.method(), "unknown"])
                    .inc();
                return;
            }
            Ok(ChainTransactionState::NotExecutedTransient) => {
                continue;
            }
            Err(err) => {
                metrics::MPC_OUTGOING_TRANSACTION_OUTCOMES
                    .with_label_values(&[request.method(), "unknown_err"])
                    .inc();
                tracing::warn!(target:"mpc", %err, "encountered error trying to confirm result of transaction {:?}", request);
                return;
            }
        }
    }
}

pub(crate) async fn handle_txn_requests(
    mut receiver: mpsc::Receiver<ChainSendTransactionRequest>,
    owner_account_id: AccountId,
    owner_secret_key: SigningKey,
    config: RespondConfig,
    indexer_state: Arc<IndexerState>,
) {
    let mut signers = TransactionSigners::new(config, owner_account_id.clone(), owner_secret_key)
        .expect("Failed to initialize transaction signers");

    while let Some(tx_request) = receiver.recv().await {
        let tx_signer = signers.signer_for(&tx_request);
        let indexer_state = indexer_state.clone();
        let owner_account_id = owner_account_id.clone();
        actix::spawn(async move {
            let Ok(txn_json) = serde_json::to_string(&tx_request) else {
                tracing::error!(target: "mpc", "Failed to serialize response args");
                return;
            };
            tracing::debug!(target = "mpc", "tx args {:?}", txn_json);

            ensure_send_transaction(
                tx_signer.clone(),
                indexer_state.clone(),
                tx_request,
                txn_json,
                Duration::from_secs(10),
                owner_account_id,
            )
            .await;
        });
    }
}
