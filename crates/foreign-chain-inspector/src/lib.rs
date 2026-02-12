use derive_more::{Deref, Display, From};
use http::{HeaderMap, HeaderName, HeaderValue};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use thiserror::Error;

pub mod abstract_chain;
pub mod bitcoin;

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
    /// Example: https://eth-mainnet.alchemyapi.io/v2/your-api-key
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
