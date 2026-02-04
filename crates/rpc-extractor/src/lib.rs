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

pub trait ForeignChainInspector {
    type Extractor;
    type Finality;
    type TxId;
    type ExtractedValue;

    fn extract(
        &self,
        tx_id: Self::TxId,
        extractors: Vec<Self::Extractor>,
        finality: Self::Finality,
    ) -> impl Future<Output = Self::ExtractedValue>;
}

pub trait RpcClient {
    type Finality;
    type TxId;
    type RpcResponse;
    // type RpcError;

    fn get(
        &self,
        transaction: Self::TxId,
        finality: Self::Finality,
    ) -> impl Future<Output = Result<Self::RpcResponse, RpcError>>;
}
