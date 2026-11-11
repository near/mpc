mod verify_foreign_tx_v2;

use crate::indexer::stats::IndexerStats;
use crate::metrics;
use crate::types::CKDId;
use crate::types::SignatureId;
use crate::types::VerifyForeignTxId;
use anyhow::Context;
use chain_gateway::account_id_compat::from_near_internal;
use chain_gateway::event_subscriber::block_events::BlockContext;
use futures::StreamExt;
use mpc_primitives::domain::DomainId;
use near_account_id::AccountId;
use near_contract_transport::BlockHeight;
use near_indexer_primitives::CryptoHash;
use near_indexer_primitives::types::FunctionArgs;
use near_indexer_primitives::views::{
    ActionView, ExecutionOutcomeWithIdView, ExecutionStatusView, ReceiptEnumView, ReceiptView,
};
use near_mpc_contract_interface::method_names::{
    FAIL_ON_TIMEOUT, READ_RPC, REQUEST_APP_PRIVATE_KEY, RETURN_CK_AND_CLEAN_STATE_ON_SUCCESS,
    RETURN_SIGNATURE_AND_CLEAN_STATE_ON_SUCCESS,
    RETURN_VERIFY_FOREIGN_TX_AND_CLEAN_STATE_ON_SUCCESS, SIGN, VERIFY_FOREIGN_TRANSACTION,
};
use near_mpc_contract_interface::types as dtos;
use near_mpc_contract_interface::types::CKDRequestArgs;
use near_mpc_contract_interface::types::Payload;
use near_mpc_contract_interface::types::VerifyForeignTransactionRequestArgs;
use near_mpc_contract_interface::types::{VerifyForeignTransactionRequestV2, YieldId};
use near_mpc_crypto_types::ckd::CKDRequest;
use near_mpc_crypto_types::sign::SignRequestArgs;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

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

/// A request that one executed receipt makes to the MPC contract.
enum IndexedRequest {
    Signature(SignatureRequestFromChain),
    Ckd(CKDRequestFromChain),
    VerifyForeignTx(VerifyForeignTxRequestFromChain),
    VerifyForeignTxV2(VerifyForeignTxRequestV2FromChain),
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

/// A V2 foreign transaction request, with the [`YieldId`] and the block height
/// that the contract stored with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyForeignTxRequestV2FromChain {
    pub verify_foreign_tx_id: VerifyForeignTxId,
    pub receipt_id: CryptoHash,
    pub yield_id: YieldId,
    pub request_block_height: BlockHeight,
    pub request: VerifyForeignTransactionRequestV2,
}

#[derive(Clone)]
pub struct ChainBlockUpdate {
    pub block: BlockContext,
    pub signature_requests: Vec<SignatureRequestFromChain>,
    pub completed_signatures: Vec<SignatureId>,
    pub ckd_requests: Vec<CKDRequestFromChain>,
    pub completed_ckds: Vec<CKDId>,
    pub verify_foreign_tx_requests: Vec<VerifyForeignTxRequestFromChain>,
    pub completed_verify_foreign_txs: Vec<VerifyForeignTxId>,
    // TODO(#5123): queue and answer these requests.
    #[expect(dead_code)]
    pub verify_foreign_tx_v2_requests: Vec<VerifyForeignTxRequestV2FromChain>,
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
    let block_height = BlockHeight::new(streamer_message.block.header.height);
    let mut stats_lock = stats.lock().await;
    stats_lock.block_heights_processing.insert(block_height);
    drop(stats_lock);

    let mut signature_requests = vec![];
    let mut completed_signatures = vec![];
    let mut ckd_requests = vec![];
    let mut completed_ckds = vec![];
    let mut verify_foreign_tx_requests = vec![];
    let mut completed_verify_foreign_txs = vec![];
    let mut verify_foreign_tx_v2_requests = vec![];

    for shard in streamer_message.shards {
        for outcome in shard.receipt_execution_outcomes {
            metrics::MPC_INDEXER_NUM_RECEIPT_EXECUTION_OUTCOMES.inc();
            let receipt = outcome.receipt.clone();
            let execution_outcome = outcome.execution_outcome.clone();

            match try_index_request(&receipt, &execution_outcome, mpc_contract_id, block_height) {
                Some(IndexedRequest::Signature(request)) => {
                    signature_requests.push(request);
                    metrics::MPC_NUM_SIGN_REQUESTS_INDEXED.inc();
                }
                Some(IndexedRequest::Ckd(request)) => {
                    ckd_requests.push(request);
                    metrics::MPC_NUM_CKD_REQUESTS_INDEXED.inc();
                }
                Some(IndexedRequest::VerifyForeignTx(request)) => {
                    verify_foreign_tx_requests.push(request);
                    metrics::MPC_NUM_VERIFY_FOREIGN_TX_REQUESTS_INDEXED.inc();
                }
                Some(IndexedRequest::VerifyForeignTxV2(request)) => {
                    verify_foreign_tx_v2_requests.push(request);
                }
                None => {}
            }

            if let Some(request_id) = try_get_request_completion(&receipt, mpc_contract_id)
                && let Some((_, method_name)) = try_extract_function_call_args(&receipt)
            {
                match method_name.as_str() {
                    RETURN_SIGNATURE_AND_CLEAN_STATE_ON_SUCCESS => {
                        completed_signatures.push(request_id);
                        metrics::MPC_NUM_SIGN_RESPONSES_INDEXED.inc();
                    }
                    RETURN_CK_AND_CLEAN_STATE_ON_SUCCESS => {
                        completed_ckds.push(request_id);
                        metrics::MPC_NUM_CKD_RESPONSES_INDEXED.inc();
                    }
                    RETURN_VERIFY_FOREIGN_TX_AND_CLEAN_STATE_ON_SUCCESS => {
                        completed_verify_foreign_txs.push(request_id);
                        metrics::MPC_NUM_VERIFY_FOREIGN_TX_RESPONSES_INDEXED.inc();
                    }
                    FAIL_ON_TIMEOUT => {
                        metrics::MPC_NUM_TIMEOUTS_INDEXED.inc();
                    }
                    _ => {}
                }
            }
        }
    }

    crate::metrics::MPC_INDEXER_LATEST_BLOCK_HEIGHT.set(u64::from(block_height) as i64);
    crate::metrics::MPC_INDEXER_LATEST_BLOCK_TIMESTAMP_SECONDS.set(
        i64::try_from(streamer_message.block.header.timestamp_nanosec / 1_000_000_000)
            .unwrap_or(i64::MAX),
    );

    block_update_sender
        .send(ChainBlockUpdate {
            block: BlockContext {
                hash: streamer_message.block.header.hash,
                height: streamer_message.block.header.height.into(),
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
            verify_foreign_tx_v2_requests,
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

/// Finds the request that a successful call to the MPC contract makes. A
/// failed receipt makes none, even though its logs persist.
fn try_index_request(
    receipt: &ReceiptView,
    execution_outcome: &ExecutionOutcomeWithIdView,
    mpc_contract_id: &AccountId,
    block_height: BlockHeight,
) -> Option<IndexedRequest> {
    let next_receipt_id = try_extract_next_receipt_id(execution_outcome, mpc_contract_id)?;
    let (args, method_name) = try_extract_function_call_args(receipt)?;
    match method_name.as_str() {
        SIGN => {
            let (signature_id, sign_args) =
                try_get_sign_args(receipt, next_receipt_id, args, method_name)?;
            let predecessor_id = try_convert_predecessor_id(receipt, method_name)?;
            Some(IndexedRequest::Signature(SignatureRequestFromChain {
                signature_id,
                receipt_id: receipt.receipt_id,
                request: sign_args,
                predecessor_id,
            }))
        }
        REQUEST_APP_PRIVATE_KEY => {
            let (ckd_id, ckd_args) = try_get_ckd_args(receipt, next_receipt_id, args, method_name)?;
            Some(IndexedRequest::Ckd(CKDRequestFromChain {
                ckd_id,
                receipt_id: receipt.receipt_id,
                request: ckd_args,
            }))
        }
        VERIFY_FOREIGN_TRANSACTION => {
            let (verify_foreign_tx_id, verify_foreign_tx_args) =
                try_get_verify_foreign_tx_args(receipt, next_receipt_id, args, method_name)?;
            Some(IndexedRequest::VerifyForeignTx(
                VerifyForeignTxRequestFromChain {
                    verify_foreign_tx_id,
                    receipt_id: receipt.receipt_id,
                    request: verify_foreign_tx_args,
                },
            ))
        }
        READ_RPC => verify_foreign_tx_v2::try_get_verify_foreign_tx_v2_request(
            receipt,
            &execution_outcome.outcome.logs,
            next_receipt_id,
            block_height,
            args,
        )
        .map(IndexedRequest::VerifyForeignTxV2),
        _ => None,
    }
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

fn try_convert_predecessor_id(receipt: &ReceiptView, method_name: &str) -> Option<AccountId> {
    match from_near_internal(&receipt.predecessor_id) {
        Ok(account_id) => Some(account_id),
        Err(err) => {
            tracing::error!(
                target: "mpc",
                %err,
                receipt_id = %receipt.receipt_id,
                predecessor_id = %receipt.predecessor_id,
                "skipping `{method_name}`: predecessor is not a valid account ID for this \
                 workspace's `near-account-id`",
            );
            metrics::MPC_INDEXER_NUM_UNCONVERTIBLE_PREDECESSOR_IDS.inc();
            None
        }
    }
}

/// If the executor for `execution_outcome` matches `expected_executor_id`,
/// then return the SuccessReceiptId if existing. Otherwise, return None.
fn try_extract_next_receipt_id(
    execution_outcome: &ExecutionOutcomeWithIdView,
    expected_executor_id: &AccountId,
) -> Option<CryptoHash> {
    let outcome = &execution_outcome.outcome;
    if outcome.executor_id.as_str() != expected_executor_id.as_str() {
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

    let predecessor_id = try_convert_predecessor_id(receipt, expected_name)?;

    let ckd_request = CKDRequest::new(
        ckd_args.request.app_public_key,
        ckd_args.request.domain_id,
        &predecessor_id,
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
            expected_payload_hash: verify_foreign_tx_args.request.expected_payload_hash,
        },
    ))
}

fn try_get_request_completion(receipt: &ReceiptView, mpc_contract_id: &AccountId) -> Option<CKDId> {
    if receipt.receiver_id.as_str() != mpc_contract_id.as_str() {
        None
    } else {
        Some(receipt.receipt_id)
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use near_indexer_primitives::near_primitives::errors::{
        ActionError, ActionErrorKind, FunctionCallError, TxExecutionError,
    };
    use near_indexer_primitives::types::{AccountId as NearAccountId, Balance, Gas};
    use near_indexer_primitives::views::{ExecutionMetadataView, ExecutionOutcomeView};
    use near_mpc_contract_interface::call_args::{
        ReadRpcArgs, RequestAppPrivateKeyArgs, SignArgs as SignCallArgs,
        VerifyForeignTransactionArgs,
    };
    use near_mpc_contract_interface::events::{
        MPC_CONTRACT_EVENT_STANDARD, VerifyForeignTxV2YieldCreated,
    };
    use near_mpc_contract_interface::types::{
        BitcoinExtractedValue, BitcoinExtractor, BitcoinRpcRequest, CKDAppPublicKey,
        ExtractedValue, ForeignChainRpcRequest, ForeignTxPayloadVersion,
    };
    use near_mpc_crypto_types::Bls12381G1PublicKey;
    use serde_json::json;

    const RECEIPT_ID: CryptoHash = CryptoHash([1; 32]);
    const NEXT_RECEIPT_ID: CryptoHash = CryptoHash([2; 32]);
    const BLOCK_HEIGHT: BlockHeight = BlockHeight::new(1234);
    const CALLER: &str = "caller.near";
    const MPC_CONTRACT: &str = "signer.near";

    fn mpc_contract_id() -> AccountId {
        MPC_CONTRACT.parse().unwrap()
    }

    fn function_call_receipt(method_name: &str, args: impl Serialize) -> ReceiptView {
        let caller: NearAccountId = CALLER.parse().unwrap();
        ReceiptView {
            predecessor_id: caller.clone(),
            receiver_id: MPC_CONTRACT.parse().unwrap(),
            receipt_id: RECEIPT_ID,
            receipt: ReceiptEnumView::Action {
                signer_id: caller,
                signer_public_key: "ed25519:11111111111111111111111111111111".parse().unwrap(),
                gas_price: Balance::from_yoctonear(0),
                output_data_receivers: vec![],
                input_data_ids: vec![],
                actions: vec![ActionView::FunctionCall {
                    method_name: method_name.to_string(),
                    args: serde_json::to_vec(&args).unwrap().into(),
                    gas: Gas::from_teragas(15),
                    deposit: Balance::from_yoctonear(1),
                }],
                is_promise_yield: false,
                refund_to: None,
            },
            _priority: 0,
        }
    }

    fn execution_outcome(
        status: ExecutionStatusView,
        logs: Vec<String>,
    ) -> ExecutionOutcomeWithIdView {
        ExecutionOutcomeWithIdView {
            proof: vec![],
            block_hash: CryptoHash::default(),
            id: RECEIPT_ID,
            outcome: ExecutionOutcomeView {
                logs,
                receipt_ids: vec![NEXT_RECEIPT_ID],
                gas_burnt: Gas::from_teragas(5),
                tokens_burnt: Balance::from_yoctonear(0),
                executor_id: MPC_CONTRACT.parse().unwrap(),
                status,
                metadata: ExecutionMetadataView::default(),
            },
        }
    }

    fn succeeded(logs: Vec<String>) -> ExecutionOutcomeWithIdView {
        execution_outcome(ExecutionStatusView::SuccessReceiptId(NEXT_RECEIPT_ID), logs)
    }

    fn panicked(logs: Vec<String>) -> ExecutionOutcomeWithIdView {
        execution_outcome(
            ExecutionStatusView::Failure(TxExecutionError::ActionError(ActionError {
                index: Some(0),
                kind: ActionErrorKind::FunctionCallError(FunctionCallError::ExecutionError(
                    "Smart contract panicked".to_string(),
                )),
            })),
            logs,
        )
    }

    fn bitcoin_request() -> ForeignChainRpcRequest {
        ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
            tx_id: [7; 32].into(),
            confirmations: 2.into(),
            extractors: [BitcoinExtractor::BlockHash].into(),
        })
    }

    fn read_rpc_request() -> VerifyForeignTransactionRequestV2 {
        VerifyForeignTransactionRequestV2 {
            request: bitcoin_request(),
            domain_id: DomainId::default(),
            expected_values: vec![ExtractedValue::BitcoinExtractedValue(
                BitcoinExtractedValue::BlockHash([42; 32].into()),
            )],
        }
    }

    fn yield_created_log(yield_id: YieldId) -> String {
        let event = json!({
            "standard": MPC_CONTRACT_EVENT_STANDARD,
            "version": VerifyForeignTxV2YieldCreated::VERSION,
            "event": VerifyForeignTxV2YieldCreated::EVENT,
            "data": VerifyForeignTxV2YieldCreated { yield_id },
        });
        format!("EVENT_JSON:{event}")
    }

    #[test]
    fn try_index_request__should_index_a_read_rpc_call_with_its_yield_id_and_block_height() {
        // Given
        let yield_id = YieldId([9; 32]);
        let receipt = function_call_receipt(READ_RPC, ReadRpcArgs::new(read_rpc_request()));
        let outcome = succeeded(vec![
            "read_rpc: predecessor=caller.near".to_string(),
            yield_created_log(yield_id),
        ]);

        // When
        let indexed = try_index_request(&receipt, &outcome, &mpc_contract_id(), BLOCK_HEIGHT);

        // Then
        let Some(IndexedRequest::VerifyForeignTxV2(request)) = indexed else {
            panic!("expected a V2 foreign tx request");
        };
        assert_eq!(
            request,
            VerifyForeignTxRequestV2FromChain {
                verify_foreign_tx_id: NEXT_RECEIPT_ID,
                receipt_id: RECEIPT_ID,
                yield_id,
                request_block_height: BLOCK_HEIGHT,
                request: read_rpc_request(),
            }
        );
    }

    #[test]
    fn try_index_request__should_skip_a_read_rpc_call_without_a_yield_created_event() {
        // Given
        let receipt = function_call_receipt(READ_RPC, ReadRpcArgs::new(read_rpc_request()));
        let outcome = succeeded(vec!["read_rpc: predecessor=caller.near".to_string()]);

        // When
        let indexed = try_index_request(&receipt, &outcome, &mpc_contract_id(), BLOCK_HEIGHT);

        // Then
        assert!(indexed.is_none());
    }

    #[test]
    fn try_index_request__should_skip_a_read_rpc_call_with_several_yield_created_events() {
        // Given
        let receipt = function_call_receipt(READ_RPC, ReadRpcArgs::new(read_rpc_request()));
        let outcome = succeeded(vec![
            yield_created_log(YieldId([1; 32])),
            yield_created_log(YieldId([2; 32])),
        ]);

        // When
        let indexed = try_index_request(&receipt, &outcome, &mpc_contract_id(), BLOCK_HEIGHT);

        // Then
        assert!(indexed.is_none());
    }

    #[test]
    fn try_index_request__should_skip_a_failed_read_rpc_call_despite_its_event() {
        // Given
        let receipt = function_call_receipt(READ_RPC, ReadRpcArgs::new(read_rpc_request()));
        let outcome = panicked(vec![yield_created_log(YieldId([9; 32]))]);

        // When
        let indexed = try_index_request(&receipt, &outcome, &mpc_contract_id(), BLOCK_HEIGHT);

        // Then
        assert!(indexed.is_none());
    }

    #[test]
    fn try_index_request__should_skip_a_read_rpc_call_with_unparsable_arguments() {
        // Given
        let receipt = function_call_receipt(READ_RPC, json!({ "request": "not a request" }));
        let outcome = succeeded(vec![yield_created_log(YieldId([9; 32]))]);

        // When
        let indexed = try_index_request(&receipt, &outcome, &mpc_contract_id(), BLOCK_HEIGHT);

        // Then
        assert!(indexed.is_none());
    }

    #[test]
    fn try_index_request__should_index_a_verify_foreign_transaction_call() {
        // Given
        let request_args = VerifyForeignTransactionRequestArgs {
            request: bitcoin_request(),
            domain_id: DomainId::default(),
            payload_version: ForeignTxPayloadVersion::V1,
            expected_payload_hash: None,
        };
        let receipt = function_call_receipt(
            VERIFY_FOREIGN_TRANSACTION,
            VerifyForeignTransactionArgs::new(request_args.clone()),
        );
        let outcome = succeeded(vec![]);

        // When
        let indexed = try_index_request(&receipt, &outcome, &mpc_contract_id(), BLOCK_HEIGHT);

        // Then
        let Some(IndexedRequest::VerifyForeignTx(request)) = indexed else {
            panic!("expected a foreign tx request");
        };
        assert_eq!(request.verify_foreign_tx_id, NEXT_RECEIPT_ID);
        assert_eq!(request.receipt_id, RECEIPT_ID);
        assert_eq!(request.request, request_args);
    }

    #[test]
    fn try_index_request__should_index_a_sign_call() {
        // Given
        let payload = Payload::from_legacy_ecdsa([3; 32]);
        let receipt = function_call_receipt(
            SIGN,
            SignCallArgs::new(SignRequestArgs::new(
                "path".to_string(),
                payload.clone(),
                DomainId::default(),
            )),
        );
        let outcome = succeeded(vec![]);

        // When
        let indexed = try_index_request(&receipt, &outcome, &mpc_contract_id(), BLOCK_HEIGHT);

        // Then
        let Some(IndexedRequest::Signature(request)) = indexed else {
            panic!("expected a signature request");
        };
        assert_eq!(request.signature_id, NEXT_RECEIPT_ID);
        assert_eq!(request.receipt_id, RECEIPT_ID);
        assert_eq!(request.predecessor_id.as_str(), CALLER);
        assert_eq!(
            request.request,
            SignArgs {
                payload,
                path: "path".to_string(),
                domain_id: DomainId::default(),
            }
        );
    }

    #[test]
    fn try_index_request__should_index_a_request_app_private_key_call() {
        // Given
        let app_public_key = CKDAppPublicKey::AppPublicKey(Bls12381G1PublicKey([5; 48]));
        let receipt = function_call_receipt(
            REQUEST_APP_PRIVATE_KEY,
            RequestAppPrivateKeyArgs::new(CKDRequestArgs {
                derivation_path: "path".to_string(),
                app_public_key: app_public_key.clone(),
                domain_id: DomainId::default(),
            }),
        );
        let outcome = succeeded(vec![]);

        // When
        let indexed = try_index_request(&receipt, &outcome, &mpc_contract_id(), BLOCK_HEIGHT);

        // Then
        let Some(IndexedRequest::Ckd(request)) = indexed else {
            panic!("expected a CKD request");
        };
        assert_eq!(request.ckd_id, NEXT_RECEIPT_ID);
        assert_eq!(request.receipt_id, RECEIPT_ID);
        assert_eq!(request.request.app_public_key, app_public_key);
        assert_eq!(request.request.domain_id, DomainId::default());
    }

    #[test]
    fn try_index_request__should_skip_a_failed_sign_call() {
        // Given
        let receipt = function_call_receipt(
            SIGN,
            SignCallArgs::new(SignRequestArgs::new(
                "path".to_string(),
                Payload::from_legacy_ecdsa([3; 32]),
                DomainId::default(),
            )),
        );
        let outcome = panicked(vec![]);

        // When
        let indexed = try_index_request(&receipt, &outcome, &mpc_contract_id(), BLOCK_HEIGHT);

        // Then
        assert!(indexed.is_none());
    }
}
