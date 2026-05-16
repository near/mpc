use derive_more::{Deref, Display, From};
use ethereum_types::{H256, U64};
use http::{HeaderMap, HeaderName, HeaderValue};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use thiserror::Error;

pub use jsonrpsee::http_client;

pub mod abstract_chain;
pub mod arbitrum;
pub mod base;
pub mod bitcoin;
pub mod bnb;
pub mod contract_interface_conversions;
pub mod evm;
pub mod hyperevm;
pub mod polygon;
pub mod starknet;

pub trait ForeignChainInspector {
    type TransactionId;
    type Finality;
    type Extractor;
    type ExtractedValue;
    fn extract(
        &self,
        tx_id: Self::TransactionId,
        finality: Self::Finality,
        extractors: Vec<Self::Extractor>,
    ) -> impl Future<Output = Result<Vec<Self::ExtractedValue>, ForeignChainInspectionError>>;
}

#[derive(Debug, Clone)]
pub enum RpcAuthentication {
    /// The key is in the URL (e.g., Alchemy, QuickNode).
    /// Example: `https://eth-mainnet.alchemyapi.io/v2/your-api-key`
    KeyInUrl,
    /// Custom header for providers like NOWNodes or GetBlock.
    /// Example: key="x-api-key", value="your-secret-token"
    CustomHeader {
        header_name: HeaderName,
        header_value: HeaderValue,
    },
}

#[derive(From, Debug, Display, Clone, Copy, Deref, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockConfirmations(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EthereumFinality {
    Finalized,
    Safe,
    Latest,
}

/// Error returned by `probe_sample_tx` startup probes (see
/// `docs/foreign-chain-transactions.md`). Probes intentionally surface only the failures an
/// operator can fix: a malformed sample tx in config, or an RPC layer that can't fetch and
/// decode it. Finality and extractor checks are not part of probing.
#[derive(Error, Debug)]
pub enum ProbeError {
    #[error("sample tx id `{0}` is not a valid {1} transaction identifier")]
    InvalidTxId(String, &'static str),
    #[error("RPC call failed during sample tx probe")]
    Rpc(#[from] jsonrpsee::core::client::error::Error),
}

/// Parses a 32-byte hex tx id with an optional `0x` prefix into a fixed-size array. Used by EVM
/// and Starknet probes which share the same tx-hash shape but have distinct chain-name labels.
pub(crate) fn parse_evm_style_tx_hash(
    tx_id: &str,
    chain_label: &'static str,
) -> Result<[u8; 32], ProbeError> {
    let hex_str = tx_id.strip_prefix("0x").unwrap_or(tx_id);
    let bytes = hex::decode(hex_str)
        .map_err(|_| ProbeError::InvalidTxId(tx_id.to_string(), chain_label))?;
    bytes
        .try_into()
        .map_err(|_| ProbeError::InvalidTxId(tx_id.to_string(), chain_label))
}

#[derive(Error, Debug)]
pub enum ForeignChainInspectionError {
    #[error("inner network client failed to fetch")]
    ClientError(#[from] jsonrpsee::core::client::error::Error),
    #[error(
        "transaction did not have enough block confirmations associated with it, expected: {expected} got: {got}"
    )]
    // TODO: return specific error types ber inspector type.
    // EVM errors
    NotEnoughBlockConfirmations {
        expected: BlockConfirmations,
        got: BlockConfirmations,
    },
    #[error("transaction has not reached expected finality level")]
    NotFinalized,
    #[error(
        "transaction receipt's block_hash does not match the canonical chain at block {block_number}: receipt_hash={receipt_hash:?}, canonical_hash={canonical_hash:?}"
    )]
    NonCanonicalBlock {
        block_number: U64,
        receipt_hash: H256,
        canonical_hash: H256,
    },
    #[error("The transaction's status was not success")]
    TransactionFailed,
    #[error("provided log index is out of bounds")]
    LogIndexOutOfBounds,
    #[error("failed to borsh serialize log event")]
    EventLogFailedBorshSerialization(std::io::Error),
}

/// Builds an HTTP client with the specified authentication method.
/// This client can be used to construct a [`ForeignChainInspector`] such
/// as [`bitcoin::inspector::BitcoinInspector`].
pub fn build_http_client(
    base_url: String,
    rpc_authentication: RpcAuthentication,
) -> Result<HttpClient, jsonrpsee::core::client::error::Error> {
    let mut headers = HeaderMap::new();

    match rpc_authentication {
        RpcAuthentication::KeyInUrl => {}
        RpcAuthentication::CustomHeader {
            header_name,
            header_value,
        } => {
            headers.insert(header_name, header_value);
        }
    }

    let client = HttpClientBuilder::default()
        .set_headers(headers)
        .build(&base_url)?;

    Ok(client)
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{ProbeError, parse_evm_style_tx_hash};
    use assert_matches::assert_matches;

    #[test]
    fn parse_evm_style_tx_hash__should_accept_0x_prefixed_32_byte_hex() {
        // Given
        let tx_id = "0x1111111111111111111111111111111111111111111111111111111111111111";

        // When
        let parsed = parse_evm_style_tx_hash(tx_id, "Test").expect("should parse");

        // Then
        assert_eq!(parsed, [0x11u8; 32]);
    }

    #[test]
    fn parse_evm_style_tx_hash__should_accept_unprefixed_32_byte_hex() {
        // Given
        let tx_id = "1111111111111111111111111111111111111111111111111111111111111111";

        // When
        let parsed = parse_evm_style_tx_hash(tx_id, "Test").expect("should parse");

        // Then
        assert_eq!(parsed, [0x11u8; 32]);
    }

    #[test]
    fn parse_evm_style_tx_hash__should_reject_wrong_length() {
        // Given a tx id that's only 31 bytes long
        let tx_id = "0x11111111111111111111111111111111111111111111111111111111111111";

        // When
        let result = parse_evm_style_tx_hash(tx_id, "Test");

        // Then
        assert_matches!(
            result,
            Err(ProbeError::InvalidTxId(ref got, "Test")) if got == tx_id
        );
    }

    #[test]
    fn parse_evm_style_tx_hash__should_reject_non_hex_characters() {
        // Given a hex string with non-hex characters
        let tx_id = "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";

        // When
        let result = parse_evm_style_tx_hash(tx_id, "Test");

        // Then
        assert_matches!(
            result,
            Err(ProbeError::InvalidTxId(ref got, "Test")) if got == tx_id
        );
    }
}
