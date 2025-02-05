use super::tx_signer::{TransactionSigner, TransactionSigners};
use super::ChainSendTransactionRequest;
use super::IndexerState;
use super::Nonce;
use crate::config::RespondConfigFile;
use crate::metrics;
use near_crypto::SecretKey;
use near_indexer_primitives::types::{BlockReference, Finality};
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
) -> Option<Nonce> {
    let Ok(Ok(block)) = indexer_state
        .view_client
        .send(near_client::GetBlock(BlockReference::Finality(Finality::Final)).with_span_context())
        .await
    else {
        tracing::warn!(target = "mpc", "failed to get block hash to send tx");
        return None;
    };

    let transaction = tx_signer.create_and_sign_function_call_tx(
        indexer_state.mpc_contract_id.clone(),
        method,
        params_ser.into(),
        block.header.hash,
        block.header.height,
    );

    let nonce = transaction.transaction.nonce();
    tracing::info!(
        target = "mpc",
        "sending tx {:?}with ak={} nonce={}",
        transaction.get_hash(),
        tx_signer.public_key(),
        nonce,
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
                Some(nonce)
            }
            _ => {
                metrics::MPC_NUM_SIGN_RESPONSES_FAILED_TO_SEND_IMMEDIATELY.inc();
                tracing::error!(
                    target: "mpc",
                    "Failed to send response tx: unexpected ProcessTxResponse: {:?}",
                    response
                );
                None
            }
        },
        Err(err) => {
            metrics::MPC_NUM_SIGN_RESPONSES_FAILED_TO_SEND_IMMEDIATELY.inc();
            tracing::error!(target: "mpc", "Failed to send response tx: {:?}", err);
            None
        }
    }
}

/// Attempts to ensure that a function call with given method and args is included on-chain.
/// If the submitted transaction is not observed by the indexer before the `timeout`, tries again.
/// Will make up to `num_attempts` attempts.
async fn ensure_send_transaction(
    tx_signer: Arc<TransactionSigner>,
    indexer_state: Arc<IndexerState>,
    method: String,
    params_ser: String,
    timeout: Duration,
    num_attempts: NonZeroUsize,
) {
    for _ in 0..num_attempts.into() {
        let Some(nonce) = submit_tx(
            tx_signer.clone(),
            indexer_state.clone(),
            method.clone(),
            params_ser.clone(),
        )
        .await
        else {
            // If the response fails to send immediately, wait a short period and try again
            time::sleep(Duration::from_secs(1)).await;
            continue;
        };

        // If the transaction is sent, wait the full timeout then check if it got included
        time::sleep(timeout).await;
        if indexer_state.has_nonce(nonce) {
            metrics::MPC_NUM_SIGN_RESPONSES_INDEXED.inc();
            return;
        }
        metrics::MPC_NUM_SIGN_RESPONSES_TIMED_OUT.inc();
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
                tx_request.method().to_string(),
                txn_json,
                Duration::from_secs(10),
                // TODO(#153): until nonce detection is fixed, this *must* be 1
                NonZeroUsize::new(1).unwrap(),
            )
            .await;
        });
    }
}
