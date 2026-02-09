use crate::rpc_schema::to_rpc_params_impl;

use derive_more::{Constructor, From};
use ethereum_types::{H256, U64};
use jsonrpsee::core::traits::ToRpcParams;
use serde::{Deserialize, Serialize};

/// Partial RPC response for `eth_getTransactionReceipt`.
/// https://ethereum.org/developers/docs/apis/json-rpc/#eth_gettransactionreceipt
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetTransactionByHashResponse {
    pub(crate) block_hash: H256,
    pub(crate) block_number: U64,
    pub(crate) status: U64,
}

/// Partial RPC response for `getrawtransaction`. See link below for full spec;
/// https://developer.bitcoin.org/reference/rpc/getrawtransaction.html#result-if-verbose-is-set-to-true
pub(crate) struct GetTransactionByHashArgs {
    pub(crate) transaction_hash: H256,
}

#[derive(Deserialize)]
pub(crate) struct GetBlockByNumberResponse {
    /// the block number
    pub(crate) number: U64,
}

#[derive(Constructor, Serialize)]
pub(crate) struct GetBlockByNumberArgs(FinalityTag, ReturnFullTransactionHash);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum FinalityTag {
    Safe,
    Finalized,
}

#[derive(From, Serialize)]
pub(crate) struct ReturnFullTransactionHash(bool);

// #[derive(Deserialize)]
// pub(crate) struct BlockNumberResponse(pub(crate) U64);

impl Serialize for GetTransactionByHashArgs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let request_parameters = [self.transaction_hash];
        request_parameters.serialize(serializer)
    }
}

impl ToRpcParams for &GetTransactionByHashArgs {
    to_rpc_params_impl!();
}

impl ToRpcParams for &GetBlockByNumberArgs {
    to_rpc_params_impl!();
}
