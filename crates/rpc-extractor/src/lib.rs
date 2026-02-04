#![allow(dead_code)]

//! Design
//! extractor
//!     ^
//!     |
//! client
//!     ^
//!     |
//!

pub mod bitcoin;

enum RpcError {
    ClientError,
    BadResponse,
}

trait RpcExtractor {
    type Chain;
    type Extractor;
    type Finality;
    type TxId;
    type ExtractedValue;

    fn extract(
        tx_id: Self::TxId,
        extractors: Vec<Self::Extractor>,
        finality: Self::Finality,
    ) -> impl Future<Output = Self::ExtractedValue>;
}

trait RpcClient {
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
