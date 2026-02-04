#![allow(dead_code)]

use http::{HeaderName, HeaderValue};

pub mod bitcoin;
pub(crate) mod rpc_types;

pub enum RpcError {
    ClientError,
    BadResponse,
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

pub struct BlockConfirmations(u64);

enum Finality {
    Optimistic,
    Final,
}

pub trait ForeignChainInspector<TxId, Finality, Extractor, ExtractedValue> {
    fn extract(
        &self,
        tx_id: TxId,
        finality: Finality,
        extractors: Vec<Extractor>,
    ) -> impl Future<Output = ExtractedValue>;
}

pub trait ForeignChainRpcClient<TxId, Finality, RpcResponse> {
    fn get(
        &self,
        transaction: TxId,
        finality: Finality,
    ) -> impl Future<Output = Result<RpcResponse, RpcError>>;
}
