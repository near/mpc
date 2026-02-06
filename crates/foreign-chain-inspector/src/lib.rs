use derive_more::{Deref, Display, From};
use http::{HeaderName, HeaderValue};
use thiserror::Error;

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

pub trait ForeignChainRpcClient {
    type TransactionId;
    type Finality;
    type RpcResponse;

    fn get(
        &self,
        transaction: Self::TransactionId,
        finality: Self::Finality,
    ) -> impl Future<Output = Result<Self::RpcResponse, RpcError>>;
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

#[derive(Debug)]
pub enum Finality {
    Optimistic,
    Final,
}

#[derive(Error, Debug)]
pub enum RpcError {
    #[error("inner network client failed to fetch")]
    ClientError(#[from] jsonrpsee::core::client::error::Error),
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
