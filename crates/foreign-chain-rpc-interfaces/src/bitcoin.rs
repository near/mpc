use crate::to_rpc_params_impl;

use jsonrpsee::core::traits::ToRpcParams;
use serde::{Deserialize, Serialize};

macro_rules! hash_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash,
            derive_more::Deref, derive_more::AsRef, derive_more::Into,
        )]
        $(#[$meta])*
        pub struct $name {
            #[deref] #[as_ref] #[into]
            bytes: [u8; 32],
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&hex::encode(&self.bytes))
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = <String as serde::Deserialize>::deserialize(deserializer)?;
                let decoded = hex::decode(&s).map_err(serde::de::Error::custom)?;
                let bytes: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
                    serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len()))
                })?;
                Ok(Self { bytes })
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(bytes: [u8; 32]) -> Self { Self { bytes } }
        }
    };
}

hash_newtype!(TransportBitcoinBlockHash);
hash_newtype!(TransportBitcoinTransactionHash);

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
