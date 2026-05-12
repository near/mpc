use crate::indexer::stats::IndexerStats;
use crate::metrics;
use crate::requests::recent_blocks_tracker::BlockViewLite;
use crate::types::CKDId;
use crate::types::SignatureId;
use crate::types::VerifyForeignTxId;
use anyhow::Context;
use futures::StreamExt;
use mpc_primitives::domain::DomainId;
use near_account_id::AccountId;
use near_indexer_primitives::types::FunctionArgs;
use near_indexer_primitives::views::{
    ActionView, ExecutionOutcomeWithIdView, ExecutionStatusView, ReceiptEnumView, ReceiptView,
};
use near_indexer_primitives::CryptoHash;
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::method_names::{
    REQUEST_APP_PRIVATE_KEY, RETURN_CK_AND_CLEAN_STATE_ON_SUCCESS,
    RETURN_CK_AND_CLEAN_STATE_ON_SUCCESS_V2, RETURN_SIGNATURE_AND_CLEAN_STATE_ON_SUCCESS,
    RETURN_SIGNATURE_AND_CLEAN_STATE_ON_SUCCESS_V2,
    RETURN_VERIFY_FOREIGN_TX_AND_CLEAN_STATE_ON_SUCCESS,
    RETURN_VERIFY_FOREIGN_TX_AND_CLEAN_STATE_ON_SUCCESS_V2, SIGN, VERIFY_FOREIGN_TRANSACTION,
};
use near_mpc_contract_interface::types as dtos;
use near_mpc_contract_interface::types::CKDRequestArgs;
use near_mpc_contract_interface::types::Payload;
use near_mpc_contract_interface::types::VerifyForeignTransactionRequestArgs;
use near_mpc_crypto_types::ckd::CKDRequest;
use near_mpc_crypto_types::sign::SignRequestArgs;
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

#[derive(Debug, Serialize, Deserialize, Clone)]
struct UnvalidatedVerifyForeignTxArgs {
    request: VerifyForeignTransactionRequestArgs,
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
    pub app_public_key: dtos::CKDAppPublicKey,
    pub app_id: dtos::CkdAppId,
    pub domain_id: DomainId,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SignatureRequestFromChain {
    pub signature_id: SignatureId,
    pub receipt_id: CryptoHash,
    pub request: SignArgs,
    pub predecessor_id: AccountId,
    /// The yield's runtime-allocated `data_id`, parsed from a
    /// `MPC_REQUEST_ID:<hex>` log on the sign receipt. `None` against contract
    /// versions predating the unique-id rework (#3184); in that case the node
    /// falls back to the legacy `respond(request, response)` shape, so this
    /// field is the upgrade-handshake hint, not a hard requirement.
    pub request_id: Option<CryptoHash>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CKDRequestFromChain {
    pub ckd_id: CKDId,
    pub receipt_id: CryptoHash,
    pub request: CKDArgs,
    pub request_id: Option<CryptoHash>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VerifyForeignTxRequestFromChain {
    pub verify_foreign_tx_id: VerifyForeignTxId,
    pub receipt_id: CryptoHash,
    pub request: VerifyForeignTransactionRequestArgs,
    pub request_id: Option<CryptoHash>,
}

#[derive(Clone)]
pub struct ChainBlockUpdate {
    pub block: BlockViewLite,
    pub signature_requests: Vec<SignatureRequestFromChain>,
    pub completed_signatures: Vec<SignatureId>,
    pub ckd_requests: Vec<CKDRequestFromChain>,
    pub completed_ckds: Vec<CKDId>,
    pub verify_foreign_tx_requests: Vec<VerifyForeignTxRequestFromChain>,
    pub completed_verify_foreign_txs: Vec<VerifyForeignTxId>,
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
    let mut verify_foreign_tx_requests = vec![];
    let mut completed_verify_foreign_txs = vec![];

    for shard in streamer_message.shards {
        for outcome in shard.receipt_execution_outcomes {
            metrics::MPC_INDEXER_NUM_RECEIPT_EXECUTION_OUTCOMES.inc();
            let receipt = outcome.receipt.clone();
            let execution_outcome = outcome.execution_outcome.clone();

            if let Some(next_receipt_id) =
                try_extract_next_receipt_id(&execution_outcome, mpc_contract_id)
            {
                if let Some((args, method_name)) = try_extract_function_call_args(&receipt) {
                    // The contract emits `MPC_REQUEST_ID:<hex>` on every yield
                    // create so the node can route `respond` to the specific
                    // yield (#3184). Old contracts don't emit it, in which
                    // case we leave `request_id = None` and the node sends
                    // the legacy two-arg respond shape.
                    let request_id = try_get_request_id_from_logs(&execution_outcome.outcome.logs);
                    match method_name.as_str() {
                        SIGN => {
                            if let Some((signature_id, sign_args)) =
                                try_get_sign_args(&receipt, next_receipt_id, args, method_name)
                            {
                                signature_requests.push(SignatureRequestFromChain {
                                    signature_id,
                                    receipt_id: receipt.receipt_id,
                                    request: sign_args,
                                    predecessor_id: receipt.predecessor_id.clone(),
                                    request_id,
                                });
                                metrics::MPC_NUM_SIGN_REQUESTS_INDEXED.inc();
                            }
                        }
                        REQUEST_APP_PRIVATE_KEY => {
                            if let Some((ckd_id, ckd_args)) =
                                try_get_ckd_args(&receipt, next_receipt_id, args, method_name)
                            {
                                ckd_requests.push(CKDRequestFromChain {
                                    ckd_id,
                                    receipt_id: receipt.receipt_id,
                                    request: ckd_args,
                                    request_id,
                                });
                                metrics::MPC_NUM_CKD_REQUESTS_INDEXED.inc();
                            }
                        }
                        VERIFY_FOREIGN_TRANSACTION => {
                            if let Some((verify_foreign_tx_id, verify_foreign_tx_args)) =
                                try_get_verify_foreign_tx_args(
                                    &receipt,
                                    next_receipt_id,
                                    args,
                                    method_name,
                                )
                            {
                                verify_foreign_tx_requests.push(VerifyForeignTxRequestFromChain {
                                    verify_foreign_tx_id,
                                    receipt_id: receipt.receipt_id,
                                    request: verify_foreign_tx_args,
                                    request_id,
                                });
                                metrics::MPC_NUM_VERIFY_FOREIGN_TX_REQUESTS_INDEXED.inc();
                            }
                        }
                        _ => {}
                    }
                }
            }

            if let Some(request_id) = try_get_request_completion(&receipt, mpc_contract_id) {
                if let Some((_, method_name)) = try_extract_function_call_args(&receipt) {
                    // Match both the pre-#3184 (1-arg) and post-#3184 (2-arg
                    // `_v2`) callback names. Pre-upgrade yields still resume
                    // through the old name during the legacy window.
                    match method_name.as_str() {
                        RETURN_SIGNATURE_AND_CLEAN_STATE_ON_SUCCESS
                        | RETURN_SIGNATURE_AND_CLEAN_STATE_ON_SUCCESS_V2 => {
                            completed_signatures.push(request_id);
                            metrics::MPC_NUM_SIGN_RESPONSES_INDEXED.inc();
                        }
                        RETURN_CK_AND_CLEAN_STATE_ON_SUCCESS
                        | RETURN_CK_AND_CLEAN_STATE_ON_SUCCESS_V2 => {
                            completed_ckds.push(request_id);
                            metrics::MPC_NUM_CKD_RESPONSES_INDEXED.inc();
                        }
                        RETURN_VERIFY_FOREIGN_TX_AND_CLEAN_STATE_ON_SUCCESS
                        | RETURN_VERIFY_FOREIGN_TX_AND_CLEAN_STATE_ON_SUCCESS_V2 => {
                            completed_verify_foreign_txs.push(request_id);
                            metrics::MPC_NUM_VERIFY_FOREIGN_TX_RESPONSES_INDEXED.inc();
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
                entropy: streamer_message.block.header.random_value.into(),
                timestamp_nanosec: streamer_message.block.header.timestamp_nanosec,
            },
            signature_requests,
            completed_signatures,
            ckd_requests,
            completed_ckds,
            verify_foreign_tx_requests,
            completed_verify_foreign_txs,
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

/// Walks the receipt's log lines looking for the contract's
/// `MPC_REQUEST_ID:<hex>` marker (prefix imported from the contract
/// interface so emitter and parser cannot drift). Returns the parsed
/// 32-byte id, or `None` when the log is absent (old contract) or
/// malformed.
///
/// Today every receipt that emits this prefix emits it exactly once —
/// `enqueue_yield_request` is the only emitter and it's invoked once per
/// user-facing entry point. A second matching line would mean either a
/// future cross-contract path enqueues two yields in the same receipt or
/// the prefix has been overloaded; silently picking one would route
/// responses to the wrong yield. We log loudly and return `None` instead
/// of panicking — panicking here would crash every MPC indexer
/// simultaneously the moment a buggy contract appeared on chain, which is
/// a worse blast radius than dropping a single suspicious receipt and
/// failing the affected request through the usual timeout path.
fn try_get_request_id_from_logs(logs: &[String]) -> Option<CryptoHash> {
    let mut found: Option<CryptoHash> = None;
    for line in logs {
        let Some(hex_str) = line.strip_prefix(method_names::MPC_REQUEST_ID_LOG_PREFIX) else {
            continue;
        };
        let mut buf = [0u8; 32];
        match hex::decode_to_slice(hex_str.trim(), &mut buf) {
            Ok(()) => {
                if let Some(existing) = found {
                    tracing::error!(
                        target: "mpc",
                        first = %hex::encode(existing),
                        extra = %line,
                        prefix = method_names::MPC_REQUEST_ID_LOG_PREFIX,
                        "receipt emitted multiple `{}` log lines; refusing to \
                         route a response to either id. The affected request \
                         will fail through the usual yield-resume timeout.",
                        method_names::MPC_REQUEST_ID_LOG_PREFIX,
                    );
                    return None;
                }
                found = Some(CryptoHash(buf));
            }
            Err(err) => {
                tracing::warn!(
                    target: "mpc",
                    %err,
                    raw = %line,
                    "ignoring malformed MPC_REQUEST_ID log line"
                );
            }
        }
    }
    found
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

    let request = sign_args.request;
    tracing::info!(
        target: "mpc",
        receipt_id = %receipt.receipt_id,
        next_receipt_id = %next_receipt_id,
        caller_id = receipt.predecessor_id.to_string(),
        request = ?request,
        "indexed new `{}` function call", expected_name
    );
    Some((
        next_receipt_id,
        SignArgs {
            payload: request.payload,
            path: request.path,
            domain_id: request.domain_id,
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

    let ckd_request = CKDRequest::new(
        ckd_args.request.app_public_key,
        ckd_args.request.domain_id,
        &receipt.predecessor_id,
        &ckd_args.request.derivation_path,
    );

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

fn try_get_verify_foreign_tx_args(
    receipt: &ReceiptView,
    next_receipt_id: CryptoHash,
    args: &FunctionArgs,
    expected_name: &str,
) -> Option<(VerifyForeignTxId, VerifyForeignTransactionRequestArgs)> {
    let verify_foreign_tx_args = match serde_json::from_slice::<'_, UnvalidatedVerifyForeignTxArgs>(
        args,
    ) {
        Ok(parsed) => parsed,
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
        request = ?verify_foreign_tx_args.request,
        "indexed new `{}` function call", expected_name
    );
    Some((
        next_receipt_id,
        VerifyForeignTransactionRequestArgs {
            request: verify_foreign_tx_args.request.request,
            domain_id: verify_foreign_tx_args.request.domain_id,
            payload_version: verify_foreign_tx_args.request.payload_version,
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
