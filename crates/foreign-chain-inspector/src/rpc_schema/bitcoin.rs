use crate::rpc_schema::to_rpc_params_impl;

use jsonrpsee::core::traits::ToRpcParams;
use mpc_primitives::hash::Hash32;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct BlockHashMarker;
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct TransactionHashMarker;

pub(crate) type TransportBitcoinBlockHash = Hash32<BlockHashMarker>;
pub(crate) type TransportBitcoinTransactionHash = Hash32<TransactionHashMarker>;

/// Partial RPC response for `getrawtransaction`. See link below for full spec;
/// https://developer.bitcoin.org/reference/rpc/getrawtransaction.html#result-if-verbose-is-set-to-true
#[derive(Deserialize)]
pub(crate) struct GetRawTransactionVerboseResponse {
    // The block hash the transaction is in
    pub(crate) blockhash: TransportBitcoinBlockHash,
    // The number of confirmations
    pub(crate) confirmations: u64,
}

/// Partial RPC response for `getrawtransaction`. See link below for full spec;
/// https://developer.bitcoin.org/reference/rpc/getrawtransaction.html#result-if-verbose-is-set-to-true
pub(crate) struct GetRawTransactionArgs {
    pub(crate) transaction_hash: TransportBitcoinTransactionHash,
    pub(crate) verbose: bool,
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

impl ToRpcParams for GetRawTransactionArgs {
    to_rpc_params_impl!();
}
