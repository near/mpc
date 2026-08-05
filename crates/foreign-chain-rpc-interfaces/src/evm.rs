use crate::to_rpc_params_impl;

use derive_more::{Constructor, From};
use jsonrpsee::core::traits::ToRpcParams;
use serde::{Deserialize, Serialize};

pub use ethereum_types::{H160, H256, U64};

use ethereum_types::U256;

/// Partial RPC response for `eth_getTransactionReceipt`.
/// <https://ethereum.org/developers/docs/apis/json-rpc/#eth_gettransactionreceipt>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionReceiptResponse {
    pub transaction_hash: H256,
    pub block_hash: H256,
    pub block_number: U64,
    pub status: U64,
    pub logs: Vec<Log>,
}

/// Request args for `eth_getTransactionReceipt`.
/// <https://ethereum.org/developers/docs/apis/json-rpc/#eth_getBlockByNumber>
pub struct GetTransactionReceiptARgs {
    pub transaction_hash: H256,
}

/// Partial RPC response for `eth_getBlockByNumber`.
/// <https://ethereum.org/developers/docs/apis/json-rpc/#eth_getBlockByNumber>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GetBlockByNumberResponse {
    /// the block number
    pub number: U64,
    /// the canonical block hash at this block number
    pub hash: H256,
}

/// Partial RPC arguments for `eth_getBlockByNumber`.
/// <https://ethereum.org/developers/docs/apis/json-rpc/#eth_getBlockByNumber>
#[derive(
    Constructor, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct GetBlockByNumberArgs(BlockNumberOrTag, ReturnFullTransactionObjects);

/// First argument to `eth_getBlockByNumber`: either a finality tag or a concrete block number.
/// Per the JSON-RPC spec the value is serialized as a string — finality tags as their lowercase
/// name, block numbers as `0x`-prefixed hex.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BlockNumberOrTag {
    Tag(FinalityTag),
    Number(U64),
}

impl From<FinalityTag> for BlockNumberOrTag {
    fn from(tag: FinalityTag) -> Self {
        Self::Tag(tag)
    }
}

impl From<U64> for BlockNumberOrTag {
    fn from(number: U64) -> Self {
        Self::Number(number)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FinalityTag {
    Safe,
    Finalized,
    Latest,
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
/// section of <https://ethereum.org/developers/docs/apis/json-rpc/#eth_gettransactionreceipt>
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

/// RPC response for `eth_chainId`: the EIP-155 chain id as a hex quantity.
/// <https://ethereum.org/developers/docs/apis/json-rpc/#eth_chainid>
///
/// Kept as text rather than parsed into a [`U64`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(transparent)]
pub struct ChainIdResponse(pub String);

impl ChainIdResponse {
    /// Decimal, the form EIP-155 chain ids are published in. A `0x` prefix reads as hex, anything
    /// else as decimal; text that is neither is returned unchanged.
    pub fn canonical_text(&self) -> String {
        let hex = self
            .0
            .strip_prefix("0x")
            .or_else(|| self.0.strip_prefix("0X"));
        let (digits, radix) = match hex {
            Some(digits) => (digits, 16),
            None => (self.0.as_str(), 10),
        };
        // Empty digits parse as zero, which would report a bare `0x` as chain 0.
        if digits.is_empty() {
            return self.0.clone();
        }
        match U256::from_str_radix(digits, radix) {
            Ok(chain_id) => chain_id.to_string(),
            Err(_) => self.0.clone(),
        }
    }
}

impl ToRpcParams for &GetTransactionReceiptARgs {
    to_rpc_params_impl!();
}

impl ToRpcParams for &GetBlockByNumberArgs {
    to_rpc_params_impl!();
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::ChainIdResponse;
    use rstest::rstest;

    /// Base mainnet.
    const CHAIN_ID_8453: &str = "0x2105";

    #[rstest]
    #[case::hex(CHAIN_ID_8453, "8453")]
    // Padded and upper-cased, as a provider may send it. Arbitrum, whose id has hex letters.
    #[case::padded("0x002105", "8453")]
    #[case::upper_cased_digits("0xA4B1", "42161")]
    // Spellings only an operator writes: the published decimal, and an upper-cased prefix.
    #[case::decimal("8453", "8453")]
    #[case::upper_cased_prefix("0X2105", "8453")]
    #[case::zero("0x0", "0")]
    // Wider than a u64, which EIP-155 permits.
    #[case::wider_than_a_u64("0x1ffffffffffffffff", "36893488147419103231")]
    // Reported as answered by the provider.
    #[case::not_a_number("mainnet", "mainnet")]
    #[case::empty_hex("0x", "0x")]
    fn chain_id_response__should_canonicalize_what_a_provider_answers(
        #[case] answered: &str,
        #[case] expected: &str,
    ) {
        // Given
        let json = serde_json::json!(answered);

        // When
        let response: ChainIdResponse = serde_json::from_value(json).unwrap();

        // Then
        assert_eq!(response.canonical_text(), expected);
    }
}
