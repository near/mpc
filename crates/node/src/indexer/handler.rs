use crate::indexer::stats::IndexerStats;
use crate::metrics;
use crate::requests::recent_blocks_tracker::BlockViewLite;
use crate::types::CKDId;
use crate::types::SignatureId;
use anyhow::Context;
use contract_interface::types as dtos;
use futures::StreamExt;
use mpc_contract::primitives::ckd::{CKDRequest, CKDRequestArgs};
use mpc_contract::primitives::domain::DomainId;
use mpc_contract::primitives::signature::{Payload, SignRequest, SignRequestArgs};
use near_indexer_primitives::types::AccountId;
use near_indexer_primitives::types::FunctionArgs;
use near_indexer_primitives::views::{
    ActionView, ExecutionOutcomeWithIdView, ExecutionStatusView, ReceiptEnumView, ReceiptView,
};
use near_indexer_primitives::CryptoHash;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct UnvalidatedSignArgs {
    request: SignRequestArgs,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct UnvalidatedCKDArgs {
    request: CKDRequestArgs,
}

/// A validated version of the signature request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SignArgs {
    pub payload: Payload,
    pub path: String,
    pub domain_id: DomainId,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct CKDArgs {
    pub app_public_key: dtos::Bls12381G1PublicKey,
    pub app_id: AccountId,
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

#[derive(Serialize, Deserialize, Clone)]
pub struct CKDRequestFromChain {
    pub ckd_id: CKDId,
    pub receipt_id: CryptoHash,
    pub request: CKDArgs,
    pub predecessor_id: AccountId,
    pub entropy: [u8; 32],
    pub timestamp_nanosec: u64,
}

#[derive(Clone)]

pub struct ChainBlockUpdate {
    pub block: BlockViewLite,
    pub signature_requests: Vec<SignatureRequestFromChain>,
    pub completed_signatures: Vec<SignatureId>,
    pub ckd_requests: Vec<CKDRequestFromChain>,
    pub completed_ckds: Vec<CKDId>,
}

#[cfg(feature = "network-hardship-simulation")]
pub(crate) async fn listen_blocks(
    stream: tokio::sync::mpsc::Receiver<near_indexer_primitives::StreamerMessage>,
    concurrency: std::num::NonZeroU16,
    stats: Arc<Mutex<IndexerStats>>,
    mpc_contract_id: AccountId,
    block_update_sender: mpsc::UnboundedSender<ChainBlockUpdate>,
    mut process_blocks_receiver: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut handle_messages = tokio_stream::wrappers::ReceiverStream::new(stream)
        .map(|streamer_message| {
            handle_message(
                streamer_message,
                Arc::clone(&stats),
                &mpc_contract_id,
                block_update_sender.clone(),
            )
        })
        .buffer_unordered(usize::from(concurrency.get()));

    while let Some(handle_message) = handle_messages.next().await {
        while !*process_blocks_receiver.borrow() {
            process_blocks_receiver.changed().await?;
        }
        handle_message?;
    }
    Ok(())
}

#[cfg(not(feature = "network-hardship-simulation"))]
pub(crate) async fn listen_blocks(
    stream: tokio::sync::mpsc::Receiver<near_indexer_primitives::StreamerMessage>,
    concurrency: std::num::NonZeroU16,
    stats: Arc<Mutex<IndexerStats>>,
    mpc_contract_id: AccountId,
    block_update_sender: mpsc::UnboundedSender<ChainBlockUpdate>,
) -> anyhow::Result<()> {
    let mut handle_messages = tokio_stream::wrappers::ReceiverStream::new(stream)
        .map(|streamer_message| {
            handle_message(
                streamer_message,
                Arc::clone(&stats),
                &mpc_contract_id,
                block_update_sender.clone(),
            )
        })
        .buffer_unordered(usize::from(concurrency.get()));

    while let Some(handle_message) = handle_messages.next().await {
        handle_message?;
    }

    Ok(())
}

async fn handle_message(
    streamer_message: near_indexer_primitives::StreamerMessage,
    stats: Arc<Mutex<IndexerStats>>,
    mpc_contract_id: &AccountId,
    block_update_sender: mpsc::UnboundedSender<ChainBlockUpdate>,
) -> anyhow::Result<()> {
    let block_height = streamer_message.block.header.height;
    let mut stats_lock = stats.lock().await;
    stats_lock.block_heights_processing.insert(block_height);
    drop(stats_lock);

    let mut signature_requests = vec![];
    let mut completed_signatures = vec![];
    let mut ckd_requests = vec![];
    let mut completed_ckds = vec![];

    for shard in streamer_message.shards {
        for outcome in shard.receipt_execution_outcomes {
            metrics::MPC_INDEXER_NUM_RECEIPT_EXECUTION_OUTCOMES.inc();
            let receipt = outcome.receipt.clone();
            let execution_outcome = outcome.execution_outcome.clone();

            // TODO: this should improve once https://github.com/near/mpc/issues/950 is done
            if let Some(next_receipt_id) =
                try_extract_next_receipt_id(&execution_outcome, mpc_contract_id)
            {
                if let Some((args, method_name)) = try_extract_function_call_args(&receipt) {
                    match method_name.as_str() {
                        "sign" => {
                            if let Some((signature_id, sign_args)) =
                                try_get_sign_args(&receipt, next_receipt_id, args, method_name)
                            {
                                signature_requests.push(SignatureRequestFromChain {
                                    signature_id,
                                    receipt_id: receipt.receipt_id,
                                    request: sign_args,
                                    predecessor_id: receipt.predecessor_id.clone(),
                                    entropy: streamer_message.block.header.random_value.into(),
                                    timestamp_nanosec: streamer_message
                                        .block
                                        .header
                                        .timestamp_nanosec,
                                });
                                metrics::MPC_NUM_SIGN_REQUESTS_INDEXED.inc();
                            }
                        }
                        "request_app_private_key" => {
                            if let Some((ckd_id, ckd_args)) =
                                try_get_ckd_args(&receipt, next_receipt_id, args, method_name)
                            {
                                ckd_requests.push(CKDRequestFromChain {
                                    ckd_id,
                                    receipt_id: receipt.receipt_id,
                                    request: ckd_args,
                                    predecessor_id: receipt.predecessor_id.clone(),
                                    entropy: streamer_message.block.header.random_value.into(),
                                    timestamp_nanosec: streamer_message
                                        .block
                                        .header
                                        .timestamp_nanosec,
                                });
                                metrics::MPC_NUM_CKD_REQUESTS_INDEXED.inc();
                            }
                        }
                        _ => {}
                    }
                }
            }

            if let Some(request_id) = try_get_request_completion(&receipt, mpc_contract_id) {
                if let Some((_, method_name)) = try_extract_function_call_args(&receipt) {
                    match method_name.as_str() {
                        "return_signature_and_clean_state_on_success" => {
                            completed_signatures.push(request_id);
                            metrics::MPC_NUM_SIGN_RESPONSES_INDEXED.inc();
                        }
                        "return_ck_and_clean_state_on_success" => {
                            completed_ckds.push(request_id);
                            metrics::MPC_NUM_CKD_RESPONSES_INDEXED.inc();
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    crate::metrics::MPC_INDEXER_LATEST_BLOCK_HEIGHT.set(block_height as i64);

    block_update_sender
        .send(ChainBlockUpdate {
            block: BlockViewLite {
                hash: streamer_message.block.header.hash,
                height: streamer_message.block.header.height,
                prev_hash: streamer_message.block.header.prev_hash,
                last_final_block: streamer_message.block.header.last_final_block,
            },
            signature_requests,
            completed_signatures,
            ckd_requests,
            completed_ckds,
        })
        .inspect_err(|err| {
            tracing::error!(target: "mpc", %err, "error sending block update to mpc node");
        })
        .context("Channel is closed. Could not send block update from indexer to the update.")?;

    let mut stats_lock = stats.lock().await;
    stats_lock.block_heights_processing.remove(&block_height);
    stats_lock.blocks_processed_count += 1;
    stats_lock.last_processed_block_height = block_height;
    drop(stats_lock);
    Ok(())
}

fn try_extract_function_call_args(receipt: &ReceiptView) -> Option<(&FunctionArgs, &String)> {
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

    tracing::debug!(target: "mpc", "found `{}` function call", method_name);

    Some((args, method_name))
}

/// If the executor for `execution_outcome` matches `expected_executor_id`,
/// then return the SuccessReceiptId if existing. Otherwise, return None.
fn try_extract_next_receipt_id(
    execution_outcome: &ExecutionOutcomeWithIdView,
    expected_executor_id: &AccountId,
) -> Option<CryptoHash> {
    let outcome = &execution_outcome.outcome;
    if &outcome.executor_id != expected_executor_id {
        return None;
    }
    let ExecutionStatusView::SuccessReceiptId(next_receipt_id) = outcome.status else {
        return None;
    };
    Some(next_receipt_id)
}

fn try_get_sign_args(
    receipt: &ReceiptView,
    next_receipt_id: CryptoHash,
    args: &FunctionArgs,
    expected_name: &String,
) -> Option<(SignatureId, SignArgs)> {
    let sign_args = match serde_json::from_slice::<'_, UnvalidatedSignArgs>(args) {
        Ok(parsed) => parsed,
        Err(err) => {
            tracing::warn!(target: "mpc", %err, "failed to parse `{}` arguments", expected_name);
            return None;
        }
    };

    let sign_request: SignRequest = match sign_args.request.try_into() {
        Ok(request) => request,
        Err(err) => {
            tracing::warn!(target: "mpc", %err, "failed to parse `{}` arguments", expected_name);
            return None;
        }
    };

    tracing::info!(
        target: "mpc",
        receipt_id = %receipt.receipt_id,
        next_receipt_id = %next_receipt_id,
        caller_id = receipt.predecessor_id.to_string(),
        request = ?sign_request,
        "indexed new `{}` function call", expected_name
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

fn try_get_ckd_args(
    receipt: &ReceiptView,
    next_receipt_id: CryptoHash,
    args: &FunctionArgs,
    expected_name: &String,
) -> Option<(CKDId, CKDArgs)> {
    let ckd_args = match serde_json::from_slice::<'_, UnvalidatedCKDArgs>(args) {
        Ok(parsed) => parsed,
        Err(err) => {
            tracing::warn!(target: "mpc", %err, "failed to parse `{}` arguments", expected_name);
            return None;
        }
    };

    let ckd_request = CKDRequest {
        app_public_key: ckd_args.request.app_public_key,
        app_id: receipt.predecessor_id.clone(),
        domain_id: ckd_args.request.domain_id,
    };

    tracing::info!(
        target: "mpc",
        receipt_id = %receipt.receipt_id,
        next_receipt_id = %next_receipt_id,
        caller_id = receipt.predecessor_id.to_string(),
        request = ?ckd_request,
        "indexed new `{}` function call", expected_name
    );
    Some((
        next_receipt_id,
        CKDArgs {
            app_public_key: ckd_request.app_public_key,
            app_id: ckd_request.app_id,
            domain_id: ckd_request.domain_id,
        },
    ))
}

fn try_get_request_completion(receipt: &ReceiptView, mpc_contract_id: &AccountId) -> Option<CKDId> {
    if &receipt.receiver_id != mpc_contract_id {
        None
    } else {
        Some(receipt.receipt_id)
    }
}
