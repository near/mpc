use crate::metrics;
use crate::types::VerifyForeignTxId;
use mpc_primitives::domain::DomainId;
use near_contract_transport::BlockHeight;
use near_indexer_primitives::CryptoHash;
use near_indexer_primitives::types::FunctionArgs;
use near_indexer_primitives::views::ReceiptView;
use near_mpc_contract_interface::events::VerifyForeignTxV2YieldCreated;
use near_mpc_contract_interface::method_names::READ_RPC;
use near_mpc_contract_interface::types::{
    ForeignChainRpcRequest, Hash256, VerifyForeignTransactionRequestV2, YieldId,
};
use serde::Deserialize;

/// A V2 foreign transaction request, with the [`YieldId`] and the block height
/// that the contract stored with it. It carries the hash of the expected
/// values, not the values, to keep large values out of memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyForeignTxRequestV2FromChain {
    pub verify_foreign_tx_id: VerifyForeignTxId,
    pub receipt_id: CryptoHash,
    pub yield_id: YieldId,
    pub request_block_height: BlockHeight,
    pub request: ForeignChainRpcRequest,
    pub domain_id: DomainId,
    pub expected_values_hash: Hash256,
}

#[derive(Deserialize)]
struct UnvalidatedReadRpcArgs {
    request: VerifyForeignTransactionRequestV2,
}

#[derive(Debug, thiserror::Error)]
enum ReadRpcCallError {
    #[error("the arguments are invalid: {0}")]
    InvalidArgs(serde_json::Error),
    #[error("the receipt logs no yield created event")]
    NoEvent,
    #[error("the receipt logs {0} yield created events")]
    SeveralEvents(usize),
    #[error("the expected values cannot be hashed: {0}")]
    ExpectedValuesHash(std::io::Error),
}

/// Parses a [`READ_RPC`] call. `logs` are the logs of the call's receipt, and
/// `block_height` is the height of the block that executed it.
pub(crate) fn try_get_verify_foreign_tx_v2_request(
    receipt: &ReceiptView,
    logs: &[String],
    next_receipt_id: VerifyForeignTxId,
    block_height: BlockHeight,
    args: &FunctionArgs,
) -> Option<VerifyForeignTxRequestV2FromChain> {
    let indexed = parse_read_rpc_call(logs, args).map(|call| VerifyForeignTxRequestV2FromChain {
        verify_foreign_tx_id: next_receipt_id,
        receipt_id: receipt.receipt_id,
        yield_id: call.yield_id,
        request_block_height: block_height,
        request: call.request,
        domain_id: call.domain_id,
        expected_values_hash: call.expected_values_hash,
    });
    match indexed {
        Ok(indexed) => {
            tracing::info!(
                target: "mpc",
                receipt_id = %receipt.receipt_id,
                next_receipt_id = %next_receipt_id,
                caller_id = receipt.predecessor_id.to_string(),
                yield_id = ?indexed.yield_id,
                request = ?indexed.request,
                domain_id = ?indexed.domain_id,
                "indexed new `{READ_RPC}` function call",
            );
            Some(indexed)
        }
        Err(err) => {
            tracing::warn!(
                target: "mpc",
                %err,
                receipt_id = %receipt.receipt_id,
                "skipping `{READ_RPC}` call",
            );
            metrics::MPC_NUM_VERIFY_FOREIGN_TX_V2_REQUESTS_SKIPPED.inc();
            None
        }
    }
}

/// A [`READ_RPC`] call with its announced [`YieldId`], and the hash of the
/// expected values in place of the values.
struct ParsedReadRpcCall {
    yield_id: YieldId,
    request: ForeignChainRpcRequest,
    domain_id: DomainId,
    expected_values_hash: Hash256,
}

fn parse_read_rpc_call(
    logs: &[String],
    args: &FunctionArgs,
) -> Result<ParsedReadRpcCall, ReadRpcCallError> {
    let request = serde_json::from_slice::<UnvalidatedReadRpcArgs>(args)
        .map_err(ReadRpcCallError::InvalidArgs)?
        .request;
    let yield_id = find_announced_yield_id(logs)?;
    let expected_values_hash = request
        .expected_values_hash()
        .map_err(ReadRpcCallError::ExpectedValuesHash)?;
    Ok(ParsedReadRpcCall {
        yield_id,
        request: request.request,
        domain_id: request.domain_id,
        expected_values_hash,
    })
}

/// Finds the [`YieldId`] that the contract announces in the logs of a
/// [`READ_RPC`] receipt. The logs must hold exactly one yield created event.
fn find_announced_yield_id(logs: &[String]) -> Result<YieldId, ReadRpcCallError> {
    let events: Vec<VerifyForeignTxV2YieldCreated> = logs
        .iter()
        .filter_map(|line| VerifyForeignTxV2YieldCreated::from_log_line(line))
        .collect();
    let [event] = <[VerifyForeignTxV2YieldCreated; 1]>::try_from(events).map_err(|events| {
        if events.is_empty() {
            ReadRpcCallError::NoEvent
        } else {
            ReadRpcCallError::SeveralEvents(events.len())
        }
    })?;
    Ok(event.yield_id)
}
