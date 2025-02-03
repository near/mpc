use super::tx_signer::{TransactionSigner, TransactionSigners};
use super::types::ChainGetPendingRequestArgs;
use super::ChainSendTransactionRequest;
use super::IndexerState;
use crate::config::RespondConfigFile;
use crate::metrics;
use mpc_contract::primitives::YieldIndex;
use near_client::Query;
use near_crypto::SecretKey;
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
) -> bool {
    let Ok(Ok(block)) = indexer_state
        .view_client
        .send(near_client::GetBlock(BlockReference::Finality(Finality::Final)).with_span_context())
        .await
    else {
        tracing::warn!(target = "mpc", "failed to get block hash to send tx");
        return false;
    };

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
        "sending tx {:?} with ak={} nonce={}",
        tx_hash,
        tx_signer.public_key(),
        transaction.transaction.nonce(),
    );

    let result = indexer_state
        .client
        .send(
            near_client::ProcessTxRequest {
                transaction,
                is_forwarded: false,
                check_only: false,
            }
            .with_span_context(),
        )
        .await;
    // TODO(#43): Fix the metrics: we no longer send only signature response transactions now.
    match result {
        Ok(response) => match response {
            // We're not a validator, so we should always be routing the transaction.
            near_client::ProcessTxResponse::RequestRouted => {
                metrics::MPC_NUM_SIGN_RESPONSES_SENT.inc();
                true
            }
            _ => {
                metrics::MPC_NUM_SIGN_RESPONSES_FAILED_TO_SEND_IMMEDIATELY.inc();
                tracing::error!(
                    target: "mpc",
                    "Failed to send response tx: unexpected ProcessTxResponse: {:?}",
                    response
                );
                false
            }
        },
        Err(err) => {
            metrics::MPC_NUM_SIGN_RESPONSES_FAILED_TO_SEND_IMMEDIATELY.inc();
            tracing::error!(target: "mpc", "Failed to send response tx: {:?}", err);
            false
        }
    }
}

/// Confirms whether the intended effect of the transaction request has been observed on chain.
/// Used to decide whether to re-submit the transaction.
async fn confirm_tx_result(
    indexer_state: Arc<IndexerState>,
    request: &ChainSendTransactionRequest,
) -> anyhow::Result<bool> {
    match request {
        ChainSendTransactionRequest::Respond(respond_args) => {
            // Confirm whether the respond call succeeded by checking whether the
            // pending signature request still exists in the contract state
            let get_pending_request_args: Vec<u8> =
                serde_json::to_string(&ChainGetPendingRequestArgs {
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
                    let result = serde_json::from_slice::<Option<YieldIndex>>(&call_result.result)?;
                    Ok(result.is_none())
                }
                _ => {
                    anyhow::bail!("Unexpected result from a view client function call");
                }
            }
        }
        ChainSendTransactionRequest::Join(_) => {
            anyhow::bail!("not implemented");
        }
        ChainSendTransactionRequest::VotePk(_) => {
            anyhow::bail!("not implemented");
        }
        ChainSendTransactionRequest::VoteReshared(_) => {
            anyhow::bail!("not implemented");
        }
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
    num_attempts: NonZeroUsize,
) {
    for _ in 0..num_attempts.into() {
        if !submit_tx(
            tx_signer.clone(),
            indexer_state.clone(),
            request.method().to_string(),
            params_ser.clone(),
            request.gas_required(),
        )
        .await
        {
            // If the transaction fails to send immediately, wait a short period and try again
            time::sleep(Duration::from_secs(1)).await;
            continue;
        };

        // Allow time for the transaction to be included
        time::sleep(timeout).await;
        // Then try to check whether it had the intended effect
        match confirm_tx_result(indexer_state.clone(), &request).await {
            Ok(true) => {
                metrics::MPC_NUM_SIGN_RESPONSES_INDEXED.inc();
                return;
            }
            Ok(false) => {
                metrics::MPC_NUM_SIGN_RESPONSES_TIMED_OUT.inc();
                continue;
            }
            Err(err) => {
                tracing::warn!(target:"mpc", %err, "encountered error trying to confirm result of transaction {:?}", request);
                return;
            }
        }
    }
}

pub(crate) async fn handle_txn_requests(
    mut receiver: mpsc::Receiver<ChainSendTransactionRequest>,
    owner_account_id: AccountId,
    owner_secret_key: SecretKey,
    config: RespondConfigFile,
    indexer_state: Arc<IndexerState>,
) {
    let mut signers = TransactionSigners::new(config, owner_account_id, owner_secret_key)
        .expect("Failed to initialize transaction signers");

    while let Some(tx_request) = receiver.recv().await {
        let tx_signer = signers.signer_for(&tx_request);
        let indexer_state = indexer_state.clone();
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
                NonZeroUsize::new(3).unwrap(),
            )
            .await;
        });
    }
}
