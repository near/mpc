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

/// RPC response for `getblockhash`: a block hash in the byte order block explorers render.
/// <https://developer.bitcoin.org/reference/rpc/getblockhash.html>
///
/// Kept as text rather than parsed into a [`TransportBitcoinBlockHash`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(transparent)]
pub struct GetBlockHashResponse(pub String);

impl GetBlockHashResponse {
    /// Lowercase, with a `0x` at the beginning stripped. Leading zeros are digits of the hash, so
    /// nothing is trimmed. Text that is not a 32 byte hash is returned unchanged.
    pub fn canonical_text(self) -> String {
        const HASH_CHARS: usize = 64;

        let digits = self
            .0
            .strip_prefix("0x")
            .or_else(|| self.0.strip_prefix("0X"))
            .unwrap_or(&self.0);
        let is_hash =
            digits.len() == HASH_CHARS && digits.chars().all(|digit| digit.is_ascii_hexdigit());
        if is_hash {
            digits.to_ascii_lowercase()
        } else {
            self.0
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::GetBlockHashResponse;
    use rstest::rstest;

    /// Bitcoin mainnet's genesis block hash, as block explorers render it.
    const GENESIS_HASH: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    const UPPER_CASED_GENESIS_HASH: &str =
        "000000000019D6689C085AE165831E934FF763AE46A2A6C172B3F1B60A8CE26F";

    #[rstest]
    #[case::canonical(GENESIS_HASH, GENESIS_HASH)]
    #[case::upper_cased(UPPER_CASED_GENESIS_HASH, GENESIS_HASH)]
    // Spellings only an operator writes: the RPC never prefixes a hash.
    #[case::prefixed(
        "0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        GENESIS_HASH
    )]
    #[case::upper_cased_prefix(
        "0X000000000019D6689C085AE165831E934FF763AE46A2A6C172B3F1B60A8CE26F",
        GENESIS_HASH
    )]
    // Reported as answered by the provider.
    #[case::not_a_hash("mainnet", "mainnet")]
    #[case::too_short(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26",
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26"
    )]
    #[case::not_hex(
        "00000000zz19d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        "00000000zz19d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    )]
    fn get_block_hash_response__should_canonicalize_what_a_provider_answers(
        #[case] answered: &str,
        #[case] expected: &str,
    ) {
        // Given
        let json = serde_json::json!(answered);

        // When
        let response: GetBlockHashResponse = serde_json::from_value(json).unwrap();

        // Then
        assert_eq!(response.canonical_text(), expected);
    }
}
