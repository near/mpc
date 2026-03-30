use crate::indexer::stats::IndexerStats;
use crate::metrics;
use crate::requests::recent_blocks_tracker::BlockViewLite;
use crate::types::CKDId;
use crate::types::SignatureId;
use crate::types::VerifyForeignTxId;
use anyhow::Context;
use chain_gateway::event_subscriber::block_events::BlockEventId;
use chain_gateway::event_subscriber::block_events::BlockUpdate;
use chain_gateway::event_subscriber::block_events::EventData;
use chain_gateway::event_subscriber::block_events::ExecutorFunctionCallSuccessWithPromiseData;
use chain_gateway::event_subscriber::block_events::MatchedEvent;
use chain_gateway::event_subscriber::subscriber::BlockEventFilter;
use chain_gateway::event_subscriber::subscriber::BlockEventSubscriber;
use futures::StreamExt;
use mpc_contract::primitives::ckd::CKDRequest;
use mpc_contract::primitives::domain::DomainId;
use mpc_contract::primitives::signature::{Payload, SignRequest, SignRequestArgs};
use near_account_id::AccountId;
use near_indexer_primitives::types::FunctionArgs;
use near_indexer_primitives::views::{
    ActionView, ExecutionOutcomeWithIdView, ExecutionStatusView, ReceiptEnumView, ReceiptView,
};
use near_indexer_primitives::CryptoHash;
use near_mpc_contract_interface::method_names::{
    REQUEST_APP_PRIVATE_KEY, RETURN_CK_AND_CLEAN_STATE_ON_SUCCESS,
    RETURN_SIGNATURE_AND_CLEAN_STATE_ON_SUCCESS,
    RETURN_VERIFY_FOREIGN_TX_AND_CLEAN_STATE_ON_SUCCESS, SIGN, VERIFY_FOREIGN_TRANSACTION,
};
use near_mpc_contract_interface::types as dtos;
use near_mpc_contract_interface::types::CKDRequestArgs;
use near_mpc_contract_interface::types::VerifyForeignTransactionRequestArgs;
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
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CKDRequestFromChain {
    pub ckd_id: CKDId,
    pub receipt_id: CryptoHash,
    pub request: CKDArgs,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VerifyForeignTxRequestFromChain {
    pub verify_foreign_tx_id: VerifyForeignTxId,
    pub receipt_id: CryptoHash,
    pub request: VerifyForeignTransactionRequestArgs,
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

const DEFAULT_BUFFER_SIZE: usize = 300;


struct EventSubscriptions {
    sign_request: BlockEventId,
    sign_response: BlockEventId,
    ckd_request: BlockEventId,
    ckd_response: BlockEventId,
    verify_foreign_tx_request: BlockEventId,
    verify_foreign_tx_response: BlockEventId,
}

impl EventSubscriptions {
    pub fn new(subscriber: &mut BlockEventSubscriber, mpc_contract_id: &AccountId) -> Self {
        let mut subscriber = chain_gateway::event_subscriber::subscriber::BlockEventSubscriber::new(
            DEFAULT_BUFFER_SIZE,
        );
        let sign_request =
            subscriber.subscribe(BlockEventFilter::ExecutorFunctionCallSuccessWithPromise {
                transaction_outcome_executor_id: mpc_contract_id.clone(),
                method_name: SIGN.into(),
            });
        let sign_response = subscriber.subscribe(BlockEventFilter::ReceiverFunctionCall {
            receipt_receiver_id: mpc_contract_id.clone(),
            method_name: RETURN_SIGNATURE_AND_CLEAN_STATE_ON_SUCCESS.to_string(),
        });
        let ckd_request =
            subscriber.subscribe(BlockEventFilter::ExecutorFunctionCallSuccessWithPromise {
                transaction_outcome_executor_id: mpc_contract_id.clone(),
                method_name: REQUEST_APP_PRIVATE_KEY.into(),
            });
        let ckd_response =
            subscriber.subscribe(BlockEventFilter::ExecutorFunctionCallSuccessWithPromise {
                transaction_outcome_executor_id: mpc_contract_id.clone(),
                method_name: RETURN_CK_AND_CLEAN_STATE_ON_SUCCESS.into(),
            });
        let verify_foreign_tx_request =
            subscriber.subscribe(BlockEventFilter::ExecutorFunctionCallSuccessWithPromise {
                transaction_outcome_executor_id: mpc_contract_id.clone(),
                method_name: VERIFY_FOREIGN_TRANSACTION.into(),
            });

        let verify_foreign_tx_response =
            subscriber.subscribe(BlockEventFilter::ReceiverFunctionCall {
                receipt_receiver_id: mpc_contract_id.clone(),
                method_name: RETURN_VERIFY_FOREIGN_TX_AND_CLEAN_STATE_ON_SUCCESS.to_string(),
            });
        Self {
            sign_request,
            sign_response,
            ckd_request,
            ckd_response,
            verify_foreign_tx_request,
            verify_foreign_tx_response,
        }
    }
    pub fn process(&self, block_update: BlockUpdate) {
        for MatchedEvent { id, event_data } in block_update.events {
            if id == self.sign_request => ...
        }
    }
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
    block: BlockUpdate,
    mpc_contract_id: &AccountId,
    block_update_sender: mpsc::UnboundedSender<ChainBlockUpdate>,
    event_subscriptions: EventSubscriptions,
) -> anyhow::Result<()> {
    let mut signature_requests = vec![];
    let mut completed_signatures = vec![];
    let mut ckd_requests = vec![];
    let mut completed_ckds = vec![];
    let mut verify_foreign_tx_requests = vec![];
    let mut completed_verify_foreign_txs = vec![];

    for event in block.events {
        if event.id == event_subscriptions.sign_request {

                            if let Some((signature_id, sign_args)) =
                                try_get_sign_args(event.event_data)
                            {
                                signature_requests.push(SignatureRequestFromChain {
                                    signature_id,
                                    receipt_id: receipt.receipt_id,
                                    request: sign_args,
                                    predecessor_id: receipt.predecessor_id.clone(),
                                });
                                metrics::MPC_NUM_SIGN_REQUESTS_INDEXED.inc();
                            }
        } else if event.id == event_subscriptions.ckd_request {
                            if let Some((ckd_id, ckd_args)) =
                                try_get_ckd_args(&receipt, next_receipt_id, args, method_name)
                            {
                                ckd_requests.push(CKDRequestFromChain {
                                    ckd_id,
                                    receipt_id: receipt.receipt_id,
                                    request: ckd_args,
                                });
                                metrics::MPC_NUM_CKD_REQUESTS_INDEXED.inc();
                            }
                        } else if event.id == event_subscriptions.verify_foreign_tx_request {
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
                                });
                                metrics::MPC_NUM_VERIFY_FOREIGN_TX_REQUESTS_INDEXED.inc();
                            }
                        } else if event.id == event_subscriptions.sign_response {
                            completed_signatures.push(request_id);
                            metrics::MPC_NUM_SIGN_RESPONSES_INDEXED.inc();
                        } else if event.id == event_subscriptions.ckd_response {
                            completed_ckds.push(request_id);
                            metrics::MPC_NUM_CKD_RESPONSES_INDEXED.inc();
                        } else if event.id == event_subscriptions.verify_foreign_tx_response {
                        // TODO(#1959): add this function to the contract
                            completed_verify_foreign_txs.push(request_id);
                            metrics::MPC_NUM_VERIFY_FOREIGN_TX_RESPONSES_INDEXED.inc();
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
    event_data: EventData,
) -> Option<SignatureRequestFromChain > {
    let EventData::ExecutorFunctionCallSuccessWithPromise(ExecutorFunctionCallSuccessWithPromiseData { receipt_id, predecessor_id, next_receipt_id, args_raw }) = event_data else {
            tracing::warn!(target: "mpc", "expected ExecutorFunctionCallSuccessWithPromiseData for sign args");
        return None};
    let sign_args = match serde_json::from_slice::<'_, UnvalidatedSignArgs>(&args_raw) {
        Ok(parsed) => parsed,
        Err(err) => {
            tracing::warn!(target: "mpc", %err, "failed to parse sign arguments");
            return None;
        }
    };

    let sign_request: SignRequest = match sign_args.request.try_into() {
        Ok(request) => request,
        Err(err) => {
            tracing::warn!(target: "mpc", %err, "failed to parse sign arguments");
            return None;
        }
    };
    tracing::info!(
        target: "mpc",
        receipt_id = %receipt_id,
        next_receipt_id = %next_receipt_id,
        caller_id = predecessor_id.to_string(),
        request = ?sign_request,
        "indexed new sign function call"
    );

        let signature_id = next_receipt_id;
        let sign_args = SignArgs {
            payload: sign_request.payload,
            path: sign_request.path,
            domain_id: sign_request.domain_id,
        };
Some(SignatureRequestFromChain {
                                  signature_id,
                                    receipt_id ,
                                    request: sign_args,
                                    predecessor_id,
                                })
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
        ckd_args.request.domain_id.into(),
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
