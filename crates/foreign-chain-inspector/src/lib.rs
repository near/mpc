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
    #[error("inspector clients returned mismatching extracted values")]
    InspectorResponseMismatch,
}

/// Runs `first_future` and `rest_futures` in parallel and returns the resolved value
/// of `first_future` only if every other future resolved to an equal value.
///
/// Returns [`ForeignChainInspectionError::InspectorResponseMismatch`] if any pair of
/// resolved values differs. Short-circuits on the first underlying error.
///
/// The non-empty input is encoded in the signature (one mandatory future plus zero or
/// more additional futures) so the function never needs to reason about an empty input.
pub(crate) async fn fan_out_and_match<T, Fut>(
    first_future: Fut,
    rest_futures: impl IntoIterator<Item = Fut>,
) -> Result<Vec<T>, ForeignChainInspectionError>
where
    Fut: Future<Output = Result<Vec<T>, ForeignChainInspectionError>>,
    T: PartialEq,
{
    let (first, rest) =
        futures::future::try_join(first_future, futures::future::try_join_all(rest_futures))
            .await?;
    for other in rest {
        if other != first {
            return Err(ForeignChainInspectionError::InspectorResponseMismatch);
        }
    }
    Ok(first)
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
    use super::*;
    use assert_matches::assert_matches;
    use std::pin::Pin;

    type TestFuture =
        Pin<Box<dyn Future<Output = Result<Vec<u8>, ForeignChainInspectionError>> + Send>>;

    fn ok(value: Vec<u8>) -> TestFuture {
        Box::pin(async move { Ok(value) })
    }

    fn err() -> TestFuture {
        Box::pin(async { Err(ForeignChainInspectionError::TransactionFailed) })
    }

    #[tokio::test]
    async fn fan_out_and_match__should_return_first_when_all_match() {
        // Given
        let first = ok(vec![1, 2, 3]);
        let rest = vec![ok(vec![1, 2, 3]), ok(vec![1, 2, 3])];

        // When
        let result = fan_out_and_match(first, rest).await;

        // Then
        assert_matches!(result, Ok(values) if values == vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn fan_out_and_match__should_return_first_when_only_one_future_provided() {
        // Given
        let first = ok(vec![42]);
        let rest: Vec<_> = Vec::new();

        // When
        let result = fan_out_and_match(first, rest).await;

        // Then
        assert_matches!(result, Ok(values) if values == vec![42]);
    }

    #[tokio::test]
    async fn fan_out_and_match__should_return_mismatch_when_first_differs_from_rest() {
        // Given
        let first = ok(vec![1, 2, 3]);
        let rest = vec![ok(vec![1, 2, 3]), ok(vec![9, 9, 9])];

        // When
        let result = fan_out_and_match(first, rest).await;

        // Then
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::InspectorResponseMismatch)
        );
    }

    #[tokio::test]
    async fn fan_out_and_match__should_short_circuit_on_first_error_in_rest() {
        // Given
        let first = ok(vec![1, 2, 3]);
        let rest = vec![err(), err()];

        // When
        let result = fan_out_and_match(first, rest).await;

        // Then
        assert_matches!(result, Err(ForeignChainInspectionError::TransactionFailed));
    }

    #[tokio::test]
    async fn fan_out_and_match__should_propagate_error_from_first_future() {
        // Given
        let first = err();
        let rest = vec![ok(vec![1, 2, 3])];

        // When
        let result = fan_out_and_match(first, rest).await;

        // Then
        assert_matches!(result, Err(ForeignChainInspectionError::TransactionFailed));
    }
}
