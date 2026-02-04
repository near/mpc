use crate::{
    BlockConfirmations, RpcClient, RpcError,
    bitcoin::{BitcoinBlockHash, BitcoinTransactionHash},
};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;

struct BitcoinRpcResponse {
    block_height: u64,
    block_hash: BitcoinBlockHash,
    /// number of confirmations including the block itself
    confirmations: u64,
}

enum BitcoinRpcProviders {
    BitcoinCore,
}

#[derive(Debug, Clone)]
enum BitcoinCoreRpcAuth {
    Basic { username: String, password: String },
    Bearer { token: String },
}

#[derive(Debug, Clone)]
struct BitcoinCoreRpcClient {
    request_client: reqwest::Client,
    base_url: String,
    auth: Option<BitcoinCoreRpcAuth>,
}

impl BitcoinCoreRpcClient {
    fn new(base_url: String, auth: Option<BitcoinCoreRpcAuth>) -> Self {
        let request_client = reqwest::Client::new();
        Self {
            base_url,
            request_client,
            auth,
        }
    }

    async fn call<T, P>(&self, method: &'static str, params: P) -> Result<T, RpcError>
    where
        T: DeserializeOwned,
        P: Serialize,
    {
        let request = JsonRpcRequest {
            jsonrpc: "1.0",
            id: "rpc-extractor",
            method,
            params,
        };

        let mut http_request = self
            .request_client
            .request(Method::POST, &self.base_url)
            .json(&request);

        if let Some(auth) = &self.auth {
            match auth {
                BitcoinCoreRpcAuth::Basic { username, password } => {
                    http_request = http_request.basic_auth(username, Some(password));
                }
                BitcoinCoreRpcAuth::Bearer { token } => {
                    http_request = http_request.bearer_auth(token);
                }
            }
        }

        let response = http_request
            .send()
            .await
            .map_err(|_| RpcError::ClientError)?;

        if response.status() != StatusCode::OK {
            return Err(RpcError::BadResponse);
        }

        let rpc_response: JsonRpcResponse<T> =
            response.json().await.map_err(|_| RpcError::BadResponse)?;

        if rpc_response.error.is_some() {
            return Err(RpcError::BadResponse);
        }

        rpc_response.result.ok_or(RpcError::BadResponse)
    }
}

#[derive(Serialize)]
struct JsonRpcRequest<P> {
    jsonrpc: &'static str,
    id: &'static str,
    method: &'static str,
    params: P,
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct GetRawTransactionVerboseResponse {
    blockhash: Option<BitcoinBlockHash>,
}

#[derive(Deserialize)]
struct GetBlockHeaderResponse {
    height: u64,
    confirmations: u64,
}

impl RpcClient for BitcoinCoreRpcClient {
    type Finality = BlockConfirmations;
    type TxId = BitcoinTransactionHash;
    type RpcResponse = BitcoinRpcResponse;
    // type RpcError;

    async fn get(
        &self,
        transaction: Self::TxId,
        _finality: Self::Finality,
    ) -> Result<Self::RpcResponse, RpcError> {
        let tx_status: GetRawTransactionVerboseResponse = self
            .call("getrawtransaction", json!([transaction.as_hex(), true]))
            .await?;

        let block_hash = tx_status.blockhash.ok_or(RpcError::BadResponse)?;
        let block_header: GetBlockHeaderResponse = self
            .call("getblockheader", json!([block_hash.as_hex(), true]))
            .await?;

        Ok(BitcoinRpcResponse {
            block_height: block_header.height,
            block_hash,
            confirmations: block_header.confirmations,
        })
    }
}
