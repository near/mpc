use crate::rpc_schema::to_rpc_params_impl;

use derive_more::{Constructor, From};
use ethereum_types::{H256, U64};
use jsonrpsee::core::traits::ToRpcParams;
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};

// fn debug_logs<'de, D>(deserializer: D) -> Result<Vec<H256>, D::Error>
// where
//     D: Deserializer<'de>,
// {
//     let raw = serde_json::Value::deserialize(deserializer)?;
//     eprintln!("DEBUG logs field: {raw}");
//     serde_json::from_value(raw).map_err(serde::de::Error::custom)
// }

/// Partial RPC response for `eth_getTransactionReceipt`.
/// https://ethereum.org/developers/docs/apis/json-rpc/#eth_gettransactionreceipt
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetTransactionReceiptResponse {
    pub(crate) block_hash: H256,
    pub(crate) block_number: U64,
    pub(crate) status: U64,
    // #[serde(deserialize_with = "debug_logs")]
    pub(crate) logs: Vec<Logs>,
}

/// Request args for `eth_getTransactionReceipt`.
/// https://ethereum.org/developers/docs/apis/json-rpc/#eth_getBlockByNumber
pub(crate) struct GetTransactionReceiptARgs {
    pub(crate) transaction_hash: H256,
}

/// Partial RPC response for `eth_getTransactionReceipt`.
/// https://ethereum.org/developers/docs/apis/json-rpc/#eth_gettransactionreceipt
#[derive(Deserialize)]
pub(crate) struct GetBlockByNumberResponse {
    /// the block number
    pub(crate) number: U64,
}

/// Partial RPC arguments for `eth_getTransactionReceipt`.
/// https://ethereum.org/developers/docs/apis/json-rpc/#eth_gettransactionreceipt
#[derive(Constructor, Serialize)]
pub(crate) struct GetBlockByNumberArgs(FinalityTag, ReturnFullTransactionObjects);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum FinalityTag {
    Safe,
    Finalized,
}

#[derive(From, Serialize)]
pub(crate) struct ReturnFullTransactionObjects(bool);

impl Serialize for GetTransactionReceiptARgs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let request_parameters = [self.transaction_hash];
        request_parameters.serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Logs {}

impl ToRpcParams for &GetTransactionReceiptARgs {
    to_rpc_params_impl!();
}

impl ToRpcParams for &GetBlockByNumberArgs {
    to_rpc_params_impl!();
}
