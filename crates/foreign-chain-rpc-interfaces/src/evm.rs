use crate::to_rpc_params_impl;

use borsh::BorshSerialize;
use derive_more::{Constructor, From};
use jsonrpsee::core::traits::ToRpcParams;
use serde::{Deserialize, Serialize};

pub use ethereum_types::{H160, H256, U64};

/// Partial RPC response for `eth_getTransactionReceipt`.
/// https://ethereum.org/developers/docs/apis/json-rpc/#eth_gettransactionreceipt
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionReceiptResponse {
    pub block_hash: H256,
    pub block_number: U64,
    pub status: U64,
    pub logs: Vec<Log>,
}

/// Request args for `eth_getTransactionReceipt`.
/// https://ethereum.org/developers/docs/apis/json-rpc/#eth_getBlockByNumber
pub struct GetTransactionReceiptARgs {
    pub transaction_hash: H256,
}

/// Partial RPC response for `eth_getTransactionReceipt`.
/// https://ethereum.org/developers/docs/apis/json-rpc/#eth_gettransactionreceipt
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GetBlockByNumberResponse {
    /// the block number
    pub number: U64,
}

/// Partial RPC arguments for `eth_getTransactionReceipt`.
/// https://ethereum.org/developers/docs/apis/json-rpc/#eth_gettransactionreceipt
#[derive(
    Constructor, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct GetBlockByNumberArgs(FinalityTag, ReturnFullTransactionObjects);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FinalityTag {
    Safe,
    Finalized,
}

#[derive(From, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ReturnFullTransactionObjects(bool);

impl Serialize for GetTransactionReceiptARgs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let request_parameters = [self.transaction_hash];
        request_parameters.serialize(serializer)
    }
}

/// An Ethereum log entry as defined in return
/// section of https://ethereum.org/developers/docs/apis/json-rpc/#eth_gettransactionreceipt
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Log {
    pub removed: bool,
    pub log_index: U64,
    pub transaction_index: U64,
    pub transaction_hash: H256,
    pub block_hash: H256,
    pub block_number: U64,
    pub address: H160,
    pub data: String,
    pub topics: Vec<H256>,
}

impl ToRpcParams for &GetTransactionReceiptARgs {
    to_rpc_params_impl!();
}

impl ToRpcParams for &GetBlockByNumberArgs {
    to_rpc_params_impl!();
}
