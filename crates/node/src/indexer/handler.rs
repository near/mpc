use crate::metrics;
use crate::types::CKDId;
use crate::types::SignatureId;
use crate::types::VerifyForeignTxId;
use anyhow::Context;
use chain_gateway::event_subscriber::block_events::BlockContext;
use chain_gateway::event_subscriber::block_events::BlockEventId;
use chain_gateway::event_subscriber::block_events::BlockUpdate;
use chain_gateway::event_subscriber::block_events::EventData;
use chain_gateway::event_subscriber::block_events::ExecutorFunctionCallSuccessWithPromiseData;
use chain_gateway::event_subscriber::block_events::MatchedEvent;
use chain_gateway::event_subscriber::block_events::ReceiverFunctionCallData;
use chain_gateway::event_subscriber::subscriber::BlockEventFilter;
use chain_gateway::event_subscriber::subscriber::BlockEventSubscriber;
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
use tokio::sync::mpsc;

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

pub struct ChainBlockUpdate {
    pub block: BlockContext,
    pub signature_requests: Vec<SignatureRequestFromChain>,
    pub completed_signatures: Vec<SignatureId>,
    pub ckd_requests: Vec<CKDRequestFromChain>,
    pub completed_ckds: Vec<CKDId>,
    pub verify_foreign_tx_requests: Vec<VerifyForeignTxRequestFromChain>,
    pub completed_verify_foreign_txs: Vec<VerifyForeignTxId>,
}

const DEFAULT_BUFFER_SIZE: usize = 300;

pub struct EventSubscriptions {
    sign_request: BlockEventId,
    sign_response: BlockEventId,
    ckd_request: BlockEventId,
    ckd_response: BlockEventId,
    verify_foreign_tx_request: BlockEventId,
    verify_foreign_tx_response: BlockEventId,
}

impl EventSubscriptions {
    pub fn new(subscriber: &mut BlockEventSubscriber, mpc_contract_id: &AccountId) -> Self {
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
}

#[cfg(feature = "network-hardship-simulation")]
pub(crate) async fn listen_blocks(
    mut stream: tokio::sync::mpsc::Receiver<BlockUpdate>,
    block_update_sender: mpsc::UnboundedSender<ChainBlockUpdate>,
    mut process_blocks_receiver: tokio::sync::watch::Receiver<bool>,
    event_subscriptions: EventSubscriptions,
) -> anyhow::Result<()> {
    loop {
        let Some(block) = stream.recv().await else {
            tracing::info!("stream closed");
            break;
        };
        if !*process_blocks_receiver.borrow() {
            process_blocks_receiver.changed().await?;
        };
        handle_message(block, &block_update_sender, &event_subscriptions).await;
    }
    Ok(())
}

#[cfg(not(feature = "network-hardship-simulation"))]
pub(crate) async fn listen_blocks(
    mut stream: tokio::sync::mpsc::Receiver<BlockUpdate>,
    block_update_sender: mpsc::UnboundedSender<ChainBlockUpdate>,
    event_subscriptions: EventSubscriptions,
) -> anyhow::Result<()> {
    loop {
        let Some(block) = stream.recv().await else {
            tracing::info!("stream closed");
            break;
        };
        handle_message(block, &block_update_sender, &event_subscriptions).await;
    }
    Ok(())
}

async fn handle_message(
    block: BlockUpdate,
    block_update_sender: &mpsc::UnboundedSender<ChainBlockUpdate>,
    event_subscriptions: &EventSubscriptions,
) -> anyhow::Result<()> {
    let mut signature_requests = vec![];
    let mut completed_signatures = vec![];
    let mut ckd_requests = vec![];
    let mut completed_ckds = vec![];
    let mut verify_foreign_tx_requests = vec![];
    let mut completed_verify_foreign_txs = vec![];

    for MatchedEvent { id, event_data } in block.events {
        if id == event_subscriptions.sign_request {
            if let Some(signature_request) = try_get_sign_args(event_data) {
                signature_requests.push(signature_request);
                metrics::MPC_NUM_SIGN_REQUESTS_INDEXED.inc();
            }
        } else if id == event_subscriptions.ckd_request {
            if let Some(ckd_request) = try_get_ckd_args(event_data) {
                ckd_requests.push(ckd_request);
                metrics::MPC_NUM_CKD_REQUESTS_INDEXED.inc();
            }
        } else if id == event_subscriptions.verify_foreign_tx_request {
            if let Some(foreign_tx_request) = try_get_verify_foreign_tx_args(event_data) {
                verify_foreign_tx_requests.push(foreign_tx_request);
                metrics::MPC_NUM_VERIFY_FOREIGN_TX_REQUESTS_INDEXED.inc();
            }
        } else if id == event_subscriptions.sign_response {
            let EventData::ReceiverFunctionCall(ReceiverFunctionCallData {
                receipt_id,
                is_success,
            }) = event_data
            else {
                // log mismatch
                break;
            };
            if is_success {
                completed_signatures.push(receipt_id);
                // todo: distinguish between success and failed response
                metrics::MPC_NUM_SIGN_RESPONSES_INDEXED.inc();
            }
        } else if id == event_subscriptions.ckd_response {
            let EventData::ReceiverFunctionCall(ReceiverFunctionCallData {
                receipt_id,
                is_success,
            }) = event_data
            else {
                // log mismatch
                break;
            };
            if is_success {
                completed_ckds.push(receipt_id);
                // todo: distinguish between success and failed response
                metrics::MPC_NUM_SIGN_RESPONSES_INDEXED.inc();
            }
        } else if id == event_subscriptions.verify_foreign_tx_response {
            // TODO(#1959): add this function to the contract
            let EventData::ReceiverFunctionCall(ReceiverFunctionCallData {
                receipt_id,
                is_success,
            }) = event_data
            else {
                // log mismatch
                break;
            };
            if is_success {
                completed_verify_foreign_txs.push(receipt_id);
                // todo: distinguish between success and failed response
                metrics::MPC_NUM_SIGN_RESPONSES_INDEXED.inc();
            }
        }
    }

    crate::metrics::MPC_INDEXER_LATEST_BLOCK_HEIGHT
        .set(Into::<u64>::into(block.context.height) as i64);

    block_update_sender
        .send(ChainBlockUpdate {
            block: block.context,
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

fn try_get_sign_args(event_data: EventData) -> Option<SignatureRequestFromChain> {
    let EventData::ExecutorFunctionCallSuccessWithPromise(
        ExecutorFunctionCallSuccessWithPromiseData {
            receipt_id,
            predecessor_id,
            next_receipt_id,
            args_raw,
        },
    ) = event_data
    else {
        tracing::warn!(target: "mpc", "expected ExecutorFunctionCallSuccessWithPromiseData for sign args");
        return None;
    };
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
    let request = SignArgs {
        payload: sign_request.payload,
        path: sign_request.path,
        domain_id: sign_request.domain_id,
    };
    Some(SignatureRequestFromChain {
        signature_id,
        receipt_id,
        request,
        predecessor_id,
    })
}

fn try_get_ckd_args(event_data: EventData) -> Option<CKDRequestFromChain> {
    let EventData::ExecutorFunctionCallSuccessWithPromise(
        ExecutorFunctionCallSuccessWithPromiseData {
            receipt_id,
            predecessor_id,
            next_receipt_id,
            args_raw,
        },
    ) = event_data
    else {
        tracing::warn!(target: "mpc", "expected ExecutorFunctionCallSuccessWithPromiseData for ckd request");
        return None;
    };
    let ckd_args = match serde_json::from_slice::<'_, UnvalidatedCKDArgs>(&args_raw) {
        Ok(parsed) => parsed,
        Err(err) => {
            tracing::warn!(target: "mpc", %err, "failed to parse ckd request arguments");
            return None;
        }
    };

    let ckd_request = CKDRequest::new(
        ckd_args.request.app_public_key,
        ckd_args.request.domain_id.into(),
        &predecessor_id,
        &ckd_args.request.derivation_path,
    );

    tracing::info!(
        target: "mpc",
        receipt_id = %receipt_id,
        next_receipt_id = %next_receipt_id,
        caller_id = predecessor_id.to_string(),
        request = ?ckd_request,
        "indexed new  ckd request function call",
    );
    let request = CKDArgs {
        app_public_key: ckd_request.app_public_key,
        app_id: ckd_request.app_id,
        domain_id: ckd_request.domain_id,
    };

    let ckd_id = next_receipt_id;

    Some(CKDRequestFromChain {
        ckd_id,
        receipt_id,
        request,
    })
}

fn try_get_verify_foreign_tx_args(
    event_data: EventData,
) -> Option<VerifyForeignTxRequestFromChain> {
    let EventData::ExecutorFunctionCallSuccessWithPromise(
        ExecutorFunctionCallSuccessWithPromiseData {
            receipt_id,
            predecessor_id,
            next_receipt_id,
            args_raw,
        },
    ) = event_data
    else {
        tracing::warn!(target: "mpc", "expected ExecutorFunctionCallSuccessWithPromiseData for foreign tx request");
        return None;
    };
    let verify_foreign_tx_args =
        match serde_json::from_slice::<'_, UnvalidatedVerifyForeignTxArgs>(&args_raw) {
            Ok(parsed) => parsed,
            Err(err) => {
                tracing::warn!(target: "mpc", %err, "failed to parse foreign tx arguments");
                return None;
            }
        };

    tracing::info!(
        target: "mpc",
        receipt_id = %receipt_id,
        next_receipt_id = %next_receipt_id,
        caller_id = predecessor_id.to_string(),
        request = ?verify_foreign_tx_args.request,
        "indexed new verify foreign tx function call"
    );
    let verify_foreign_tx_id = next_receipt_id;
    let request = VerifyForeignTransactionRequestArgs {
        request: verify_foreign_tx_args.request.request,
        domain_id: verify_foreign_tx_args.request.domain_id,
        payload_version: verify_foreign_tx_args.request.payload_version,
    };
    Some(VerifyForeignTxRequestFromChain {
        verify_foreign_tx_id,
        receipt_id,
        request,
    })
}
