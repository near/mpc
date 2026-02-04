use crate::{
    BlockConfirmations, ForeignChainRpcClient, RpcAuthentication, RpcError,
    bitcoin::{BitcoinBlockHash, BitcoinRpcResponse, BitcoinTransactionHash},
    rpc_types::{JsonRpcRequest, JsonRpcResponse},
};
use reqwest::{Method, StatusCode, header::HeaderMap};
use serde::Deserialize;
use serde_json::json;

const JSON_RPC_VERSION: &str = "1.0";
const JSON_RPC_CLIENT_ID: &str = "client";
/// https://developer.bitcoin.org/reference/rpc/getrawtransaction.html
const GET_RAW_TRANSACTION_METHOD: &str = "getrawtransaction";

#[derive(Debug, Clone)]
pub struct BitcoinCoreRpcClient {
    request_client: reqwest::Client,
    base_url: String,
}

impl BitcoinCoreRpcClient {
    pub fn new(base_url: String, rpc_authentication: RpcAuthentication) -> Self {
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

impl ForeignChainRpcClient<BitcoinTransactionHash, BlockConfirmations, BitcoinRpcResponse>
    for BitcoinCoreRpcClient
{
    async fn get(
        &self,
        transaction: BitcoinTransactionHash,
        _finality: BlockConfirmations,
    ) -> Result<BitcoinRpcResponse, RpcError> {
        let rpc_parameters = json!([
            transaction,
            // enable verbose response
            true
        ]);

        let request = JsonRpcRequest {
            jsonrpc: JSON_RPC_VERSION,
            id: JSON_RPC_CLIENT_ID,
            method: GET_RAW_TRANSACTION_METHOD,
            params: rpc_parameters,
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
            confirmations: rpc_response.confirmations.into(),
        })
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
#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use httpmock::prelude::*;
    use serde::de::DeserializeOwned;
    use serde_json::json;

    // --- Mocks to make the test compile standalone ---
    // (In your actual project, these come from your module imports)
    #[derive(Debug, PartialEq)]
    struct BitcoinRpcResponse {
        block_hash: String,
        confirmations: u64,
    }

    #[derive(Deserialize)]
    struct JsonRpcResponse<T>(#[serde(with = "mock_rpc_deser")] Result<T, ()>)
    where
        T: DeserializeOwned;

    mod mock_rpc_deser {
        use serde::de::DeserializeOwned;
        use serde::{Deserialize, Deserializer};
        use serde_json::Value;

        pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Result<T, ()>, D::Error>
        where
            D: Deserializer<'de>,
            T: DeserializeOwned,
        {
            let v: Value = Deserialize::deserialize(deserializer)?;
            // precise logic depends on your actual struct, this is a simplified mock
            if let Some(res) = v.get("result") {
                if !res.is_null() {
                    let t: T =
                        serde_json::from_value(res.clone()).map_err(serde::de::Error::custom)?;
                    return Ok(Ok(t));
                }
            }
            Ok(Err(()))
        }
    }

    #[tokio::test]
    async fn test_http_error_handling() {
        // Given
        let server = MockServer::start();
        let client = BitcoinCoreRpcClient::new(server.url("/"), RpcAuthentication::KeyInUrl);

        server.mock(|when, then| {
            when.method(POST);
            then.status(500); // Simulate server failure
        });

        // When
        let result = client
            .get(
                BitcoinTransactionHash::from([1; 32]),
                BlockConfirmations::from(1),
            )
            .await;

        // Then
        assert_matches!(result, Err(RpcError::BadResponse));
    }
}
