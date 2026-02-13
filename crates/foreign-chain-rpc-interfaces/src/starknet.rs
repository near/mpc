use crate::to_rpc_params_impl;

use jsonrpsee::core::traits::ToRpcParams;
use serde::{Deserialize, Serialize};

/// Partial RPC response for `starknet_getTransactionReceipt`.
/// https://docs.starknet.io/documentation/architecture_and_concepts/Network_Architecture/transactions/#transaction_receipt
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GetTransactionReceiptResponse {
    pub block_hash: String,
    pub finality_status: String,
    pub execution_status: String,
}

/// Request args for `starknet_getTransactionReceipt`.
pub struct GetTransactionReceiptArgs {
    pub transaction_hash: String,
}

impl Serialize for GetTransactionReceiptArgs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // `starknet_getTransactionReceipt` expects a single-element array: [transaction_hash]
        let request_parameters = [&self.transaction_hash];
        request_parameters.serialize(serializer)
    }
}

impl ToRpcParams for &GetTransactionReceiptArgs {
    to_rpc_params_impl!();
}
