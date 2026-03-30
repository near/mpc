use crate::to_rpc_params_impl;

use jsonrpsee::core::traits::ToRpcParams;
use serde::{Deserialize, Serialize};

pub struct TransportBitcoinBlockHashMarker;
pub type TransportBitcoinBlockHash =
    mpc_primitives::hash::Hash<TransportBitcoinBlockHashMarker, 32>;

pub struct TransportBitcoinTransactionHashMarker;
pub type TransportBitcoinTransactionHash =
    mpc_primitives::hash::Hash<TransportBitcoinTransactionHashMarker, 32>;

/// Partial RPC response for `getrawtransaction`. See link below for full spec;
/// <https://developer.bitcoin.org/reference/rpc/getrawtransaction.html#result-if-verbose-is-set-to-true>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GetRawTransactionVerboseResponse {
    // The block hash the transaction is in
    pub blockhash: TransportBitcoinBlockHash,
    // The number of confirmations
    pub confirmations: u64,
}

/// Partial RPC response for `getrawtransaction`. See link below for full spec;
/// <https://developer.bitcoin.org/reference/rpc/getrawtransaction.html#result-if-verbose-is-set-to-true>
pub struct GetRawTransactionArgs {
    pub transaction_hash: TransportBitcoinTransactionHash,
    pub verbose: bool,
}

impl Serialize for GetRawTransactionArgs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // `getrawtransaction` expects a list of parameters https://developer.bitcoin.org/reference/rpc/getrawtransaction.html#argument-1-txid
        // 1. tx_hash
        // 2. verbose
        let request_parameters = (&self.transaction_hash, &self.verbose);

        request_parameters.serialize(serializer)
    }
}

impl ToRpcParams for &GetRawTransactionArgs {
    to_rpc_params_impl!();
}
