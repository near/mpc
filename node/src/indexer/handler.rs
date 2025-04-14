use crate::{
    indexer::stats::IndexerStats, metrics, sign_request::SignatureId,
    signing::recent_blocks_tracker::BlockViewLite,
};
use futures::StreamExt;
use mpc_contract::primitives::{
    domain::DomainId,
    signature::{Payload, SignRequest, SignRequestArgs},
};
use near_indexer_primitives::{
    types::AccountId,
    views::{
        ActionView, ExecutionOutcomeWithIdView, ExecutionStatusView, ReceiptEnumView, ReceiptView,
    },
    CryptoHash,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{
    select,
    sync::{
        mpsc::{self, channel, Receiver, Sender},
        Mutex,
    },
};
use tokio_util::{
    sync::CancellationToken,
    time::delay_queue::{self, DelayQueue},
};

const SIGN_REQUEST_DELAY_QUEUE_DURATION_SECS: u64 = 120; // 2 min
const SIGN_REQUEST_DELAY_QUEUE_DURATION: Duration =
    Duration::from_secs(SIGN_REQUEST_DELAY_QUEUE_DURATION_SECS);
const SIGN_REQUEST_DELAY_TRACKER_CHANNEL_BUFFER_SIZE: usize = 1000;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct UnvalidatedSignArgs {
    request: SignRequestArgs,
}

/// A validated version of the signature request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SignArgs {
    pub payload: Payload,
    pub path: String,
    pub domain_id: DomainId,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SignatureRequestFromChain {
    pub signature_id: SignatureId,
    pub receipt_id: CryptoHash,
    pub request: SignArgs,
    pub predecessor_id: AccountId,
    pub entropy: [u8; 32],
    pub timestamp_nanosec: u64,
}

#[derive(Clone)]
pub struct ChainBlockUpdate {
    pub block: BlockViewLite,
    pub signature_requests: Vec<SignatureRequestFromChain>,
    pub completed_signatures: Vec<SignatureId>,
}

pub(crate) async fn listen_blocks(
    stream: tokio::sync::mpsc::Receiver<near_indexer_primitives::StreamerMessage>,
    concurrency: std::num::NonZeroU16,
    stats: Arc<Mutex<IndexerStats>>,
    mpc_contract_id: AccountId,
    block_update_sender: mpsc::UnboundedSender<ChainBlockUpdate>,
) {
    let (sign_request_delay_tracker_sender, sign_request_delay_tracker_receiver) =
        channel(SIGN_REQUEST_DELAY_TRACKER_CHANNEL_BUFFER_SIZE);

    let cancellation_token = CancellationToken::new();
    let child = cancellation_token.child_token();
    let _drop_guard = cancellation_token.drop_guard();

    actix::spawn(monitor_completion_delay(
        sign_request_delay_tracker_receiver,
        SIGN_REQUEST_DELAY_QUEUE_DURATION,
        child,
    ));

    let mut handle_messages = tokio_stream::wrappers::ReceiverStream::new(stream)
        .map(|streamer_message| {
            handle_message(
                streamer_message,
                Arc::clone(&stats),
                &mpc_contract_id,
                block_update_sender.clone(),
                sign_request_delay_tracker_sender.clone(),
            )
        })
        .buffer_unordered(usize::from(concurrency.get()));

    while let Some(_handle_message) = handle_messages.next().await {}
}

async fn handle_message(
    streamer_message: near_indexer_primitives::StreamerMessage,
    stats: Arc<Mutex<IndexerStats>>,
    mpc_contract_id: &AccountId,
    block_update_sender: mpsc::UnboundedSender<ChainBlockUpdate>,
    signature_request_status_sender: Sender<SignatureStatus>,
) -> anyhow::Result<()> {
    let block_height = streamer_message.block.header.height;
    let mut stats_lock = stats.lock().await;
    stats_lock.block_heights_processing.insert(block_height);
    drop(stats_lock);

    let mut signature_requests = vec![];
    let mut completed_signatures = vec![];

    for shard in streamer_message.shards {
        for outcome in shard.receipt_execution_outcomes {
            metrics::MPC_INDEXER_NUM_RECEIPT_EXECUTION_OUTCOMES.inc();
            let receipt = outcome.receipt.clone();
            let execution_outcome = outcome.execution_outcome.clone();
            if let Some((signature_id, sign_args)) =
                maybe_get_sign_args(&receipt, &execution_outcome, mpc_contract_id)
            {
                signature_requests.push(SignatureRequestFromChain {
                    signature_id,
                    receipt_id: receipt.receipt_id,
                    request: sign_args,
                    predecessor_id: receipt.predecessor_id.clone(),
                    entropy: streamer_message.block.header.random_value.into(),
                    timestamp_nanosec: streamer_message.block.header.timestamp_nanosec,
                });
                metrics::MPC_NUM_SIGN_REQUESTS_INDEXED.inc();

                let _ = signature_request_status_sender
                    .try_send(SignatureStatus::IncomingRequest {
                        block_height,
                        signature_id,
                    })
                    .inspect_err(|err| {
                        tracing::info!(
                            "Failed to send status to request status tracker: {:?}.",
                            err
                        )
                    });
            } else if let Some(signature_id) =
                maybe_get_signature_completion(&receipt, mpc_contract_id)
            {
                completed_signatures.push(signature_id);
                metrics::MPC_NUM_SIGN_RESPONSES_INDEXED.inc();

                let _ = signature_request_status_sender
                    .try_send(SignatureStatus::Completion {
                        block_height,
                        signature_id,
                    })
                    .inspect_err(|err| {
                        tracing::info!(
                            "Failed to send status to request status tracker: {:?}.",
                            err
                        )
                    });
            }
        }
    }

    crate::metrics::MPC_INDEXER_LATEST_BLOCK_HEIGHT.set(block_height as i64);

    if let Err(err) = block_update_sender.send(ChainBlockUpdate {
        block: BlockViewLite {
            hash: streamer_message.block.header.hash,
            height: streamer_message.block.header.height,
            prev_hash: streamer_message.block.header.prev_hash,
            last_final_block: streamer_message.block.header.last_final_block,
        },
        signature_requests,
        completed_signatures,
    }) {
        tracing::error!(target: "mpc", %err, "error sending block update to mpc node");
    }

    let mut stats_lock = stats.lock().await;
    stats_lock.block_heights_processing.remove(&block_height);
    stats_lock.blocks_processed_count += 1;
    stats_lock.last_processed_block_height = block_height;
    drop(stats_lock);
    Ok(())
}

fn maybe_get_sign_args(
    receipt: &ReceiptView,
    execution_outcome: &ExecutionOutcomeWithIdView,
    mpc_contract_id: &AccountId,
) -> Option<(SignatureId, SignArgs)> {
    let outcome = &execution_outcome.outcome;
    if &outcome.executor_id != mpc_contract_id {
        return None;
    }
    let ExecutionStatusView::SuccessReceiptId(next_receipt_id) = outcome.status else {
        return None;
    };
    let ReceiptEnumView::Action { ref actions, .. } = receipt.receipt else {
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

    let sign_args = match serde_json::from_slice::<'_, UnvalidatedSignArgs>(args) {
        Ok(parsed) => parsed,
        Err(err) => {
            tracing::warn!(target: "mpc", %err, "failed to parse `sign` arguments");
            return None;
        }
    };

    let sign_request: SignRequest = match sign_args.request.try_into() {
        Ok(request) => request,
        Err(err) => {
            tracing::warn!(target: "mpc", %err, "failed to parse `sign` arguments");
            return None;
        }
    };

    tracing::info!(
        target: "mpc",
        receipt_id = %receipt.receipt_id,
        next_receipt_id = %next_receipt_id,
        caller_id = receipt.predecessor_id.to_string(),
        request = ?sign_request,
        "indexed new `sign` function call"
    );
    Some((
        next_receipt_id,
        SignArgs {
            payload: sign_request.payload,
            path: sign_request.path,
            domain_id: sign_request.domain_id,
        },
    ))
}

fn maybe_get_signature_completion(
    receipt: &ReceiptView,
    mpc_contract_id: &AccountId,
) -> Option<SignatureId> {
    if &receipt.receiver_id != mpc_contract_id {
        return None;
    };
    let ReceiptEnumView::Action { ref actions, .. } = receipt.receipt else {
        return None;
    };
    if actions.len() != 1 {
        return None;
    }
    let ActionView::FunctionCall {
        ref method_name, ..
    } = actions[0]
    else {
        return None;
    };
    if method_name != "return_signature_and_clean_state_on_success" {
        return None;
    }
    tracing::debug!(target: "mpc", "found `return_signature_and_clean_state_on_success` function call");

    Some(receipt.receipt_id)
}

#[derive(Debug)]
enum SignatureStatus {
    IncomingRequest {
        block_height: u64,
        signature_id: SignatureId,
    },
    Completion {
        block_height: u64,
        signature_id: SignatureId,
    },
}

/// Event loop that tracks the number of blocks between a signature request, [`SignatureStatus::IncomingRequest`]
/// and its corresponding response, [`SignatureStatus::Completion`] through the provided [`Receiver`].
///
/// Requests will be tracked for a maximum [`Duration`] of `tracking_duration` before
/// the tracking of it is discarded.
async fn monitor_completion_delay(
    mut signature_update_sender: Receiver<SignatureStatus>,
    tracking_timeout_duration: Duration,
    cancellation_token: CancellationToken,
) {
    let mut delay_queue: DelayQueue<SignatureId> = DelayQueue::new();
    let mut seen_requests_height: HashMap<SignatureId, (delay_queue::Key, u64)> = HashMap::new();

    loop {
        select! {
            Some(expired_signature_id) = delay_queue.next() => {
                seen_requests_height.remove(expired_signature_id.get_ref());
            },
            signature_update = signature_update_sender.recv() => {
                let Some(signature_update) = signature_update else {
                    return;
                };

                match signature_update {
                    SignatureStatus::IncomingRequest { block_height, signature_id } => {
                        let delay_queue_key = delay_queue.insert(signature_id, tracking_timeout_duration);
                        seen_requests_height
                            .entry(signature_id)
                            .or_insert((delay_queue_key, block_height));
                    }
                    SignatureStatus::Completion { block_height, signature_id } => {
                        let Some((delay_queue_key, sign_height)) = seen_requests_height.remove(&signature_id) else {
                            continue;
                        };
                        delay_queue.remove(&delay_queue_key);
                        let response_delay = block_height - sign_height;
                        metrics::SIGNATURE_REQUEST_BLOCK_DELAY.observe(response_delay as f64);
                    }
                }
            }
            _ = cancellation_token.cancelled() => {
                return;
            }
        }
    }
}
