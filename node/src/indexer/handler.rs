use crate::indexer::stats::IndexerStats;
use crypto_shared::{derive_epsilon, ScalarExt};
use k256::Scalar;
use near_indexer::IndexerExecutionOutcomeWithReceipt;
use near_indexer_primitives::types::AccountId;
use near_indexer_primitives::views::{
    ActionView, ExecutionOutcomeWithIdView, ExecutionStatusView, ReceiptEnumView, ReceiptView,
};

use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

/// Arguments passed to a `sign` function call on-chain
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
struct UnvalidatedSignArgsInner {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
struct UnvalidatedSignArgs {
    request: UnvalidatedSignArgsInner,
}

/// A validated version of the signature request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SignArgs {
    pub payload: Scalar,
    pub path: String,
    pub key_version: u32,
}

// TODO: currently we never read these fields
#[allow(dead_code)]
pub struct SignatureRequest {
    pub request_id: [u8; 32],
    pub request: SignArgs,
    pub epsilon: Scalar,
    pub entropy: [u8; 32],
    pub time_added: Instant,
}

// The index at which entropy appears in the `sign` function call outcome logs
const ENTROPY_LOG_INDEX: usize = 1;

pub(crate) async fn listen_blocks(
    stream: tokio::sync::mpsc::Receiver<near_indexer_primitives::StreamerMessage>,
    concurrency: std::num::NonZeroU16,
    stats: Arc<Mutex<IndexerStats>>,
    mpc_contract_id: AccountId,
) {
    let mut handle_messages = tokio_stream::wrappers::ReceiverStream::new(stream)
        .map(|streamer_message| {
            handle_message(streamer_message, Arc::clone(&stats), &mpc_contract_id)
        })
        .buffer_unordered(usize::from(concurrency.get()));

    while let Some(_handle_message) = handle_messages.next().await {}
}

async fn handle_message(
    streamer_message: near_indexer_primitives::StreamerMessage,
    stats: Arc<Mutex<IndexerStats>>,
    mpc_contract_id: &AccountId,
) -> anyhow::Result<()> {
    let block_height = streamer_message.block.header.height;
    let mut stats_lock = stats.lock().await;
    stats_lock.block_heights_processing.insert(block_height);
    drop(stats_lock);

    for shard in streamer_message.shards {
        for outcome in shard.receipt_execution_outcomes {
            let IndexerExecutionOutcomeWithReceipt {
                execution_outcome,
                receipt,
            } = outcome;
            if execution_outcome.outcome.executor_id != *mpc_contract_id {
                continue;
            }
            tracing::info!(target: "mpc", "got execution outcome targeting {}", mpc_contract_id);
            if let Some(_request) = maybe_get_signature_request(execution_outcome, receipt) {
                // Pass the request to mpc
            }
        }
    }

    let mut stats_lock = stats.lock().await;
    stats_lock.block_heights_processing.remove(&block_height);
    stats_lock.blocks_processed_count += 1;
    stats_lock.last_processed_block_height = block_height;
    drop(stats_lock);
    Ok(())
}

fn maybe_get_signature_request(
    execution_outcome: ExecutionOutcomeWithIdView,
    receipt: ReceiptView,
) -> Option<SignatureRequest> {
    let outcome = execution_outcome.outcome;
    let ExecutionStatusView::SuccessReceiptId(receipt_id) = outcome.status else {
        return None;
    };
    let ReceiptEnumView::Action { actions, .. } = receipt.receipt else {
        return None;
    };
    if actions.len() != 1 {
        return None;
    }
    let ActionView::FunctionCall {
        ref method_name,
        ref args,
        ..
    } = actions[0]
    else {
        return None;
    };
    if method_name != "sign" {
        return None;
    }
    tracing::debug!(target: "mpc", "found `sign` function call");

    if outcome.logs.is_empty() {
        tracing::warn!(target: "mpc", "`sign` did not produce entropy");
        return None;
    }
    let sign_args = match serde_json::from_slice::<'_, UnvalidatedSignArgs>(&args) {
        Ok(parsed) => parsed,
        Err(err) => {
            tracing::warn!(target: "mpc", %err, "failed to parse `sign` arguments");
            return None;
        }
    };
    let Some(payload) = Scalar::from_bytes(sign_args.request.payload) else {
        tracing::warn!(
            target: "mpc",
            "`sign` did not produce payload correctly: {:?}",
            sign_args.request.payload,
        );
        return None;
    };
    let Ok(entropy) = serde_json::from_str::<'_, [u8; 32]>(&outcome.logs[ENTROPY_LOG_INDEX]) else {
        tracing::warn!(
            target: "mpc",
            "`sign` did not produce entropy correctly: {:?}",
            outcome.logs[ENTROPY_LOG_INDEX]
        );
        return None;
    };
    let epsilon = derive_epsilon(&receipt.predecessor_id, &sign_args.request.path);

    tracing::info!(
        target: "mpc",
        receipt_id = %receipt_id,
        caller_id = receipt.predecessor_id.to_string(),
        payload = hex::encode(sign_args.request.payload),
        key_version = sign_args.request.key_version,
        entropy = hex::encode(entropy),
        "indexed new `sign` function call"
    );
    let request = SignArgs {
        payload,
        path: sign_args.request.path,
        key_version: sign_args.request.key_version,
    };
    Some(SignatureRequest {
        request_id: receipt_id.0,
        request,
        epsilon,
        entropy,
        // TODO: use on-chain timestamp instead
        time_added: Instant::now(),
    })
}
