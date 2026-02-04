use derive_more::{Deref, Display, From};
use http::{HeaderName, HeaderValue};
use serde::Deserialize;
use thiserror::Error;

pub mod bitcoin;

pub(crate) mod rpc_types;

#[derive(Debug, Clone, Error)]
pub enum RpcError {
    #[error("inner network client failed to fetch")]
    ClientError,
    #[error("got a bad response from the RPC provider")]
    BadResponse,
}

#[derive(Debug, Clone, Error)]
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

#[derive(From, Debug, Display, Clone, Copy, Deref, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlockConfirmations(u64);

#[derive(Debug)]
pub enum Finality {
    Optimistic,
    Final,
}

pub trait ForeignChainInspector<TransactionId, Finality, Extractor, ExtractedValue> {
    fn extract(
        &self,
        tx_id: TransactionId,
        finality: Finality,
        extractors: Vec<Extractor>,
    ) -> impl Future<Output = Result<Vec<ExtractedValue>, ForeignChainInspectionError>>;
}

pub trait ForeignChainRpcClient<TransactionId, Finality, RpcResponse> {
    fn get(
        &self,
        transaction: TransactionId,
        finality: Finality,
    ) -> impl Future<Output = Result<RpcResponse, RpcError>>;
}
