use crate::{
    BlockConfirmations, ForeignChainRpcClient, RpcAuthentication, RpcError,
    bitcoin::{BitcoinBlockHash, BitcoinRpcResponse, BitcoinTransactionHash},
};
use http::HeaderMap;
use jsonrpsee::{
    core::client::ClientT,
    http_client::{HttpClient, HttpClientBuilder},
};
use serde::{Deserialize, Serialize};

/// https://developer.bitcoin.org/reference/rpc/getrawtransaction.html
const GET_RAW_TRANSACTION_METHOD: &str = "getrawtransaction";
const VERBOSE_RESPONSE: bool = true;

#[derive(Debug, Clone)]
pub struct BitcoinCoreRpcClient<Client> {
    client: Client,
}

impl BitcoinCoreRpcClient<HttpClient> {
    pub fn new(base_url: String, rpc_authentication: RpcAuthentication) -> Result<Self, RpcError> {
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

        Ok(Self { client })
    }
}

impl<Client> BitcoinCoreRpcClient<Client> {
    pub fn with_client(client: Client) -> Self {
        Self { client }
    }
}

impl<Client> ForeignChainRpcClient for BitcoinCoreRpcClient<Client>
where
    Client: ClientT + Send + Sync,
{
    type TransactionId = BitcoinTransactionHash;
    type Finality = BlockConfirmations;
    type RpcResponse = BitcoinRpcResponse;
    async fn get(
        &self,
        transaction: BitcoinTransactionHash,
        _finality: BlockConfirmations,
    ) -> Result<BitcoinRpcResponse, RpcError> {
        let parameters = (transaction, VERBOSE_RESPONSE);

        let rpc_response: GetRawTransactionVerboseResponse = self
            .client
            .request(GET_RAW_TRANSACTION_METHOD, parameters)
            .await?;

        Ok(BitcoinRpcResponse {
            block_hash: rpc_response.blockhash,
            confirmations: rpc_response.confirmations.into(),
        })
    }
}

/// Partial RPC response for `getrawtransaction`. See link below for full spec;
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
        let client =
            BitcoinCoreRpcClient::new(server.url("/"), RpcAuthentication::KeyInUrl).unwrap();

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
        assert_matches!(result, Err(_));
    }

    #[tokio::test]
    async fn success_transaction_response_is_parsed_correctly() {
        // Given
        let server = MockServer::start();
        let client =
            BitcoinCoreRpcClient::new(server.url("/"), RpcAuthentication::KeyInUrl).unwrap();

        let transaction_hash = BitcoinTransactionHash::from([12; 32]);

        let expected_block_hash = BitcoinBlockHash::from([42; 32]);
        let expected_confirmations = 250;

        let _mock = server.mock(|when, then| {
            when.method(POST).path("/");

            // Create response with proper JSON-RPC 2.0 format
            // Serialize the blockhash as hex string
            let blockhash_hex = expected_block_hash.as_hex();

            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!({
                    "jsonrpc": "2.0",
                    "result": {
                        "blockhash": blockhash_hex,
                        "confirmations": expected_confirmations
                    },
                    "id": 0
                }));
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

        let client = BitcoinCoreRpcClient::new(server.url("/"), auth).unwrap();

        let mock = server.mock(|when, then| {
            // Assert header is present
            when.method(POST).header(header, header_value);
            then.status(200).json_body(json!({
                "jsonrpc": "2.0",
                "result": {
                    "blockhash": "valid_hash",
                    "confirmations": 1
                },
                "id": 1
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
        let client =
            BitcoinCoreRpcClient::new(server.url("/"), RpcAuthentication::KeyInUrl).unwrap();

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
        assert_matches!(result, Err(_));
    }

    #[tokio::test]
    async fn malformed_json_response() {
        // Given
        let server = MockServer::start();
        let client =
            BitcoinCoreRpcClient::new(server.url("/"), RpcAuthentication::KeyInUrl).unwrap();

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
        assert_matches!(result, Err(_));
    }

    #[tokio::test]
    async fn bad_response_is_returned_for_rpc_errors() {
        // Given
        let server = MockServer::start();
        let client =
            BitcoinCoreRpcClient::new(server.url("/"), RpcAuthentication::KeyInUrl).unwrap();

        // Simulation of a Bitcoin node error (e.g., tx not found)
        server.mock(|when, then| {
            when.method(POST);
            then.status(200).json_body(json!({
                "jsonrpc": "2.0",
                "error": { "code": -1, "message": "Transaction not found" },
                "id": 1
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
        assert_matches!(result, Err(_));
    }

    #[tokio::test]
    async fn client_connection_error_returns_clienterror() {
        // Given
        // point to a closed socket address
        let invalid_url = "http://127.0.0.1:0";
        let client =
            BitcoinCoreRpcClient::new(invalid_url.to_string(), RpcAuthentication::KeyInUrl)
                .unwrap();

        // When
        let result = client
            .get(
                BitcoinTransactionHash::from([1; 32]),
                BlockConfirmations::from(1),
            )
            .await;

        // Then
        assert_matches!(result, Err(_));
    }
}
