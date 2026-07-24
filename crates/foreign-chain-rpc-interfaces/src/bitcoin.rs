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

/// Partial RPC response for `getblockheader` with `verbose=true`. See link below for full spec;
/// <https://developer.bitcoin.org/reference/rpc/getblockheader.html>
///
/// Prefer `getblockheader` over `getblock` when only `hash`/`height` are needed: `getblock`
/// (even at verbosity 1) returns the full transaction-id list, which on mainnet adds
/// substantial bandwidth/latency to every RPC roundtrip.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GetBlockHeaderVerboseResponse {
    pub hash: TransportBitcoinBlockHash,
    pub height: u64,
}

/// Request args for `getblockheader`.
pub struct GetBlockHeaderArgs {
    pub blockhash: TransportBitcoinBlockHash,
    pub verbose: bool,
}

impl Serialize for GetBlockHeaderArgs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // `getblockheader` expects a positional list https://developer.bitcoin.org/reference/rpc/getblockheader.html#argument-1-blockhash
        // 1. blockhash
        // 2. verbose
        let request_parameters = (&self.blockhash, &self.verbose);

        request_parameters.serialize(serializer)
    }
}

impl ToRpcParams for &GetBlockHeaderArgs {
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

/// `getbestblockhash` takes no parameters; it returns the hash of the chain tip.
/// <https://developer.bitcoin.org/reference/rpc/getbestblockhash.html>
pub struct GetBestBlockHashArgs;

impl ToRpcParams for &GetBestBlockHashArgs {
    fn to_rpc_params(self) -> Result<Option<Box<serde_json::value::RawValue>>, serde_json::Error> {
        Ok(None)
    }
}

/// Request args for `getblock` at verbosity 1, whose response lists the block's transaction ids.
/// <https://developer.bitcoin.org/reference/rpc/getblock.html>
pub struct GetBlockArgs {
    pub blockhash: TransportBitcoinBlockHash,
    pub verbosity: u8,
}

impl Serialize for GetBlockArgs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let request_parameters = (&self.blockhash, &self.verbosity);
        request_parameters.serialize(serializer)
    }
}

impl ToRpcParams for &GetBlockArgs {
    to_rpc_params_impl!();
}

/// Partial `getblock` response (verbosity 1). The health probe reads the height of the chain
/// tip and a transaction id from a recent block to exercise the inspector against.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GetBlockResponse {
    pub height: u64,
    pub tx: Vec<TransportBitcoinTransactionHash>,
}
