use derive_more::{Deref, Display, From};
use http::{HeaderMap, HeaderName, HeaderValue};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use thiserror::Error;

pub mod abstract_chain;
pub mod bitcoin;

pub(crate) mod rpc_schema;

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

#[derive(From, Debug, Display, Clone, Copy, Deref, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockHeight(u64);

#[derive(Debug)]
pub enum EthereumFinality {
    Finalized,
    Safe,
}

#[derive(Error, Debug)]
pub enum RpcError {
    #[error("inner network client failed to fetch")]
    ClientError(#[from] jsonrpsee::core::client::error::Error),
    #[error("The transaction is ")]
    NotFinalized,
}

#[derive(Error, Debug)]
pub enum ForeignChainInspectionError {
    #[error("rpc client failed to fetch transaction information")]
    RpcClientError(#[from] RpcError),
    #[error(
        "transaction did not have enough block confirmations associated with it, expected: {expected} got: {got}"
    )]
    NotEnoughBlockConfirmations {
        expected: BlockConfirmations,
        got: BlockConfirmations,
    },
}

/// Builds an HTTP client with the specified authentication method.
/// This client can be used to construct a [`ForeignChainInspector`] such
/// as [`bitcoin::inspector::BitcoinInspector`].
pub fn build_http_client(
    base_url: String,
    rpc_authentication: RpcAuthentication,
) -> Result<HttpClient, RpcError> {
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
