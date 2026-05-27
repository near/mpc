use crate::to_rpc_params_impl;

use jsonrpsee::core::traits::ToRpcParams;
use serde::{Deserialize, Serialize};

mpc_primitives::define_hash!(TransportBitcoinBlockHash, 32);
mpc_primitives::define_hash!(TransportBitcoinTransactionHash, 32);

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

/// Verbosity level for `getblock` that returns a decoded JSON header (with `height` and `hash`)
/// plus a list of txids. Lower levels return hex-encoded raw bytes which we'd have to parse.
pub const GET_BLOCK_VERBOSITY_HEADER_AND_TXIDS: u8 = 1;

/// Partial RPC response for `getblock`. See link below for full spec;
/// <https://developer.bitcoin.org/reference/rpc/getblock.html>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GetBlockResponse {
    pub hash: TransportBitcoinBlockHash,
    pub height: u64,
}

/// Request args for `getblock`.
pub struct GetBlockArgs {
    pub blockhash: TransportBitcoinBlockHash,
    pub verbosity: u8,
}

impl Serialize for GetBlockArgs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // `getblock` expects a positional list https://developer.bitcoin.org/reference/rpc/getblock.html#argument-1-blockhash
        // 1. blockhash
        // 2. verbosity
        let request_parameters = (&self.blockhash, &self.verbosity);

        request_parameters.serialize(serializer)
    }
}

impl ToRpcParams for &GetBlockArgs {
    to_rpc_params_impl!();
}

/// Request args for `getblockhash`.
/// <https://developer.bitcoin.org/reference/rpc/getblockhash.html>
pub struct GetBlockHashArgs {
    pub height: u64,
}

impl Serialize for GetBlockHashArgs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let request_parameters = [self.height];
        request_parameters.serialize(serializer)
    }
}

impl ToRpcParams for &GetBlockHashArgs {
    to_rpc_params_impl!();
}
