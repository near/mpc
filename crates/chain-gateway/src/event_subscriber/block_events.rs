use derive_more::{Deref, From};
use near_account_id::AccountId;
use near_indexer_primitives::CryptoHash;

use crate::types::BlockHeight;

/// The BlockUpdate returned by the Chain indexer.
/// Similar to [`ChainBlockUpdate`](../../node/src/indexer/handler.rs) in the `mpc-node` crate.
#[derive(Debug)]
pub struct BlockUpdate {
    pub context: BlockContext,
    pub events: Vec<MatchedEvent>,
}

/// Context for a single block
#[derive(Debug)]
pub struct BlockContext {
    pub hash: CryptoHash,
    pub height: BlockHeight,
    pub prev_hash: CryptoHash,
    pub last_final_block: CryptoHash,
    pub block_entropy: CryptoHash,
    pub block_timestamp_nanosec: u64,
}

#[derive(Debug)]
pub struct MatchedEvent {
    /// this is needed such that the caller can identify the block event
    pub id: BlockEventId,
    /// any data associated with that event
    pub event_data: EventData,
}

/// An identifier for a block event
#[derive(Debug, Deref, From, Clone, Copy, PartialEq, Eq)]
pub struct BlockEventId(pub u64);

/// Event data, matching a filter [`super::subscriber::BlockEventFilter`]
#[derive(Debug, PartialEq)]
pub enum EventData {
    ExecutorFunctionCallSuccessWithPromise(ExecutorFunctionCallSuccessWithPromiseData),
    ReceiverFunctionCall(ReceiverFunctionCallData),
}

/// Event data for a receipt matching a [`super::subscriber::BlockEventFilter::ExecutorFunctionCallSuccessWithPromise`]
#[derive(Debug, PartialEq)]
pub struct ExecutorFunctionCallSuccessWithPromiseData {
    /// the receipt_id of the receipt this event came from
    pub receipt_id: CryptoHash,
    /// predecessor_id who signed the transaction
    pub predecessor_id: AccountId,
    /// the receipt that will hold the outcome of this receipt
    pub next_receipt_id: CryptoHash,
    /// raw bytes used for function call
    pub args_raw: Vec<u8>,
}

/// Event data for a receipt matching a [`super::subscriber::BlockEventFilter::ReceiverFunctionCall`]
#[derive(Debug, PartialEq)]
pub struct ReceiverFunctionCallData {
    /// the receipt id for the matched transaction
    pub receipt_id: CryptoHash,
    /// whether the execution outcome was successful
    pub is_success: bool,
}
