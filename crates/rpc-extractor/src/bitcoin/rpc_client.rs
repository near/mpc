use crate::{
    BlockConfirmations, ForeignChainRpcClient, RpcAuthentication, RpcError,
    bitcoin::{BitcoinBlockHash, BitcoinRpcResponse, BitcoinTransactionHash},
    rpc_types::{JsonRpcRequest, JsonRpcResponse},
};
use reqwest::{Method, StatusCode, header::HeaderMap};
use serde::{Deserialize, Serialize};
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
#[derive(Serialize, Deserialize)]
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
    use serde_json::json;

    #[tokio::test]
    async fn http_error_status_code_returns_bad_response() {
        // Given
        let server = MockServer::start();
        let client = BitcoinCoreRpcClient::new(server.url("/"), RpcAuthentication::KeyInUrl);

        server.mock(|when, then| {
            when.method(POST);
            then.status(500);
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

    #[tokio::test]
    async fn success_transaction_response_is_parsed_correctly() {
        // Given
        let server = MockServer::start();
        let client = BitcoinCoreRpcClient::new(server.url("/"), RpcAuthentication::KeyInUrl);

        let transaction_hash = BitcoinTransactionHash::from([12; 32]);

        let expected_block_hash = BitcoinBlockHash::from([42; 32]);
        let expected_confirmations = 250;

        let raw_response: GetRawTransactionVerboseResponse = GetRawTransactionVerboseResponse {
            blockhash: expected_block_hash.clone(),
            confirmations: expected_confirmations,
        };

        server.mock(|when, then| {
            when.method(POST).path("/");

            let json_rpc_response = json!({
                    "result": raw_response,
                    "error": null,
                    "id": "client"
            });

            then.status(200)
                .header("content-type", "application/json")
                .json_body(json_rpc_response);
        });

        // When
        let result = client
            .get(transaction_hash, BlockConfirmations::from(1))
            .await;

        // Then
        let response = result.unwrap();
        let expected_response = BitcoinRpcResponse {
            block_hash: expected_block_hash,
            confirmations: BlockConfirmations::from(expected_confirmations),
        };
        assert_eq!(expected_response, response);
    }

    #[tokio::test]
    async fn custom_header_authentication_values_are_used() {
        // Given
        let server = MockServer::start();

        let header = "X-Auth-Token";
        let header_value = "secret-123";

        let auth = RpcAuthentication::CustomHeader {
            header_name: header.parse().unwrap(),
            header_value: header_value.parse().unwrap(),
        };

        let client = BitcoinCoreRpcClient::new(server.url("/"), auth);

        let mock = server.mock(|when, then| {
            // Assert header is present
            when.method(POST).header(header, header_value);
            then.status(200).json_body(json!({
                "result": {
                    "blockhash": "valid_hash",
                    "confirmations": 1
                }
            }));
        });

        // When
        let _ = client
            .get(
                BitcoinTransactionHash::from([1; 32]),
                BlockConfirmations::from(1),
            )
            .await;

        // Then
        mock.assert();
    }

    #[tokio::test]
    async fn http_status_unauthorized_error_returns_bad_response() {
        // Given
        let server = MockServer::start();
        let client = BitcoinCoreRpcClient::new(server.url("/"), RpcAuthentication::KeyInUrl);

        server.mock(|when, then| {
            when.method(POST);
            then.status(401); // Unauthorized
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

    #[tokio::test]
    async fn malformed_json_response() {
        // Given
        let server = MockServer::start();
        let client = BitcoinCoreRpcClient::new(server.url("/"), RpcAuthentication::KeyInUrl);

        server.mock(|when, then| {
            when.method(POST);
            then.status(200).body("this is not json");
        });

        // When
        let result = client
            .get(
                BitcoinTransactionHash::from([1; 32]),
                BlockConfirmations::from(1),
            )
            .await;

        // Then
        assert_matches!(
            result,
            Err(RpcError::BadResponse),
            "Should fail at json deserialization step"
        );
    }

    #[tokio::test]
    async fn bad_response_is_returned_for_rpc_errors() {
        // Given
        let server = MockServer::start();
        let client = BitcoinCoreRpcClient::new(server.url("/"), RpcAuthentication::KeyInUrl);

        // Simulation of a Bitcoin node error (e.g., tx not found)
        server.mock(|when, then| {
            when.method(POST);
            then.status(200).json_body(json!({
                "result": null,
                "error": { "code": -1, "message": "Transaction not found" },
                "id": "client"
            }));
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

    #[tokio::test]
    async fn client_connection_error_returns_clienterror() {
        // Given
        // point to a closed socket address
        let invalid_url = "http://127.0.0.1:0";
        let client =
            BitcoinCoreRpcClient::new(invalid_url.to_string(), RpcAuthentication::KeyInUrl);

        // When
        let result = client
            .get(
                BitcoinTransactionHash::from([1; 32]),
                BlockConfirmations::from(1),
            )
            .await;

        // Then
        assert_matches!(
            result,
            Err(RpcError::ClientError),
            "Reqwest fails to connect, mapping to RpcError::ClientError"
        );
    }
}
