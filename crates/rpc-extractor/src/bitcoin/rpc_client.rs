use crate::{
    BlockConfirmations, ForeignChainRpcClient, RpcAuthentication, RpcError,
    bitcoin::{BitcoinBlockHash, BitcoinTransactionHash},
    rpc_types::{JsonRpcRequest, JsonRpcResponse},
};
use reqwest::{Method, StatusCode, header::HeaderMap};
use serde::Deserialize;
use serde_json::json;

const JSON_RPC_VERSION: &str = "1.0";
const JSON_RPC_CLIENT_ID: &str = "client";
const GET_RAW_TRANSACTION_METHOD: &str = "getrawtransaction";

/// Normalized response.
#[derive(Debug, Clone)]
pub struct BitcoinRpcResponse {
    pub block_hash: BitcoinBlockHash,
    pub confirmations: u64,
}

#[derive(Debug, Clone)]
pub struct BitcoinCoreRpcClient {
    request_client: reqwest::Client,
    base_url: String,
}

impl BitcoinCoreRpcClient {
    pub fn new(base_url: String, auth: RpcAuthentication) -> Self {
        let mut headers = HeaderMap::new();

        match auth {
            RpcAuthentication::KeyInUrl => {}
            RpcAuthentication::CustomHeader {
                header_name,
                header_value,
            } => {
                headers.insert(header_name, header_value);
            }
        }

        let request_client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .expect("Failed to build HTTP client");

        Self {
            base_url,
            request_client,
        }
    }
}

/// The RPC response for `getrawtransaction`. See link below for full spec;
/// https://developer.bitcoin.org/reference/rpc/getrawtransaction.html#result-if-verbose-is-set-to-true
#[derive(Deserialize)]
struct GetRawTransactionVerboseResponse {
    // The block hash the transaction is in
    blockhash: BitcoinBlockHash,
    // The number of confirmations
    confirmations: u64,
}

impl ForeignChainRpcClient for BitcoinCoreRpcClient {
    type Finality = BlockConfirmations;
    type TxId = BitcoinTransactionHash;
    type RpcResponse = BitcoinRpcResponse;

    async fn get(
        &self,
        transaction: Self::TxId,
        _finality: Self::Finality,
    ) -> Result<Self::RpcResponse, RpcError> {
        let params = json!([transaction.as_hex(), true]);

        let request = JsonRpcRequest {
            jsonrpc: JSON_RPC_VERSION,
            id: JSON_RPC_CLIENT_ID,
            method: GET_RAW_TRANSACTION_METHOD,
            params,
        };

        let response = self
            .request_client
            .request(Method::POST, &self.base_url)
            .json(&request)
            .send()
            .await
            .map_err(|_| RpcError::ClientError)?;

        if response.status() != StatusCode::OK {
            return Err(RpcError::BadResponse);
        }

        let rpc_response = response
            .json::<JsonRpcResponse<GetRawTransactionVerboseResponse>>()
            .await
            .map_err(|_| RpcError::BadResponse)?
            .0
            .map_err(|_| RpcError::BadResponse)?;

        Ok(BitcoinRpcResponse {
            block_hash: rpc_response.blockhash,
            confirmations: rpc_response.confirmations,
        })
    }
}
