use foreign_chain_inspector::{
    BlockConfirmations, ForeignChainInspectionError, ForeignChainInspector, RpcAuthentication,
    RpcError,
    bitcoin::{
        BitcoinBlockHash, BitcoinTransactionHash,
        inspector::{BitcoinExtractedValue, BitcoinExtractor, BitcoinInspector},
        rpc_client::BitcoinCoreRpcClient,
    },
};

use assert_matches::assert_matches;
use httpmock::prelude::*;
use jsonrpsee::core::{
    client::BatchResponse, client::ClientT, client::Error as RpcClientError,
    params::BatchRequestBuilder,
};
use rstest::rstest;
use serde_json::json;
use std::sync::{Arc, Mutex};

// Manual mock for ClientT to avoid mockall limitations
#[derive(Clone)]
struct MockJsonRpcClient {
    response: Arc<Mutex<Option<serde_json::Value>>>,
    error: Arc<Mutex<Option<RpcClientError>>>,
}

impl MockJsonRpcClient {
    fn with_response(response: serde_json::Value) -> Self {
        Self {
            response: Arc::new(Mutex::new(Some(response))),
            error: Arc::new(Mutex::new(None)),
        }
    }

    fn with_error(error: RpcClientError) -> Self {
        Self {
            response: Arc::new(Mutex::new(None)),
            error: Arc::new(Mutex::new(Some(error))),
        }
    }
}

#[allow(clippy::manual_async_fn)]
impl ClientT for MockJsonRpcClient {
    fn request<R, Params>(
        &self,
        _method: &str,
        _params: Params,
    ) -> impl std::future::Future<Output = Result<R, RpcClientError>> + Send
    where
        R: jsonrpsee::core::DeserializeOwned,
    {
        let response = self.response.clone();
        let error = self.error.clone();

        async move {
            if let Some(err) = error.lock().unwrap().take() {
                return Err(err);
            }

            let resp = response.lock().unwrap().take().ok_or_else(|| {
                RpcClientError::ParseError(
                    serde_json::from_str::<serde_json::Value>("").unwrap_err(),
                )
            })?;

            serde_json::from_value(resp).map_err(RpcClientError::ParseError)
        }
    }

    fn notification<Params>(
        &self,
        _method: &str,
        _params: Params,
    ) -> impl std::future::Future<Output = Result<(), RpcClientError>> + Send {
        async { unimplemented!() }
    }

    fn batch_request<'a, R>(
        &self,
        _batch: BatchRequestBuilder<'a>,
    ) -> impl std::future::Future<Output = Result<BatchResponse<'a, R>, RpcClientError>> + Send
    where
        R: jsonrpsee::core::DeserializeOwned + std::fmt::Debug + 'a,
    {
        async { unimplemented!() }
    }
}

#[rstest]
#[tokio::test]
#[case::confirmations_equals_threshold(BlockConfirmations::from(1), BlockConfirmations::from(1))]
#[case::confirmations_greater_tan_threshold(
    BlockConfirmations::from(1),
    BlockConfirmations::from(2)
)]
async fn extract_returns_block_hash_when_confirmations_sufficient(
    #[case] confirmations: BlockConfirmations,
    #[case] threshold: BlockConfirmations,
) {
    // given
    let tx_id = BitcoinTransactionHash::from([3; 32]);
    let expected_block_hash = BitcoinBlockHash::from([4; 32]);

    // Mock the JSON-RPC response
    let mock_response = json!({
        "blockhash": expected_block_hash,
        "confirmations": *confirmations
    });

    let mock_client = MockJsonRpcClient::with_response(mock_response);
    let rpc_client = BitcoinCoreRpcClient::with_client(mock_client);
    let inspector = BitcoinInspector::new(rpc_client);

    // when
    let extracted_values = inspector
        .extract(tx_id, threshold, vec![BitcoinExtractor::BlockHash])
        .await
        .expect("extract should succeed");

    // then
    let expected_extractions = vec![BitcoinExtractedValue::BlockHash(expected_block_hash)];

    assert_eq!(expected_extractions, extracted_values);
}

#[tokio::test]
async fn extract_returns_error_when_confirmations_insufficient() {
    // given
    let tx_id = BitcoinTransactionHash::from([1; 32]);
    let expected_block_hash = BitcoinBlockHash::from([2; 32]);

    let confirmations = BlockConfirmations::from(2u64);
    let threshold = BlockConfirmations::from(6u64);

    let mock_response = json!({
        "blockhash": expected_block_hash,
        "confirmations": *confirmations
    });

    let mock_client = MockJsonRpcClient::with_response(mock_response);
    let rpc_client = BitcoinCoreRpcClient::with_client(mock_client);
    let inspector = BitcoinInspector::new(rpc_client);

    // when
    let response = inspector
        .extract(tx_id, threshold, vec![BitcoinExtractor::BlockHash])
        .await;

    // then
    let expected_response = Err(ForeignChainInspectionError::NotEnoughBlockConfirmations {
        expected: threshold,
        got: confirmations,
    });

    assert_eq!(response, expected_response);
}

#[tokio::test]
async fn extract_returns_empty_when_no_extractors_provided() {
    // given
    let tx_id = BitcoinTransactionHash::from([11; 32]);
    let expected_block_hash = BitcoinBlockHash::from([12; 32]);

    let confirmations = BlockConfirmations::from(9u64);
    let threshold = BlockConfirmations::from(6u64);

    let mock_response = json!({
        "blockhash": expected_block_hash,
        "confirmations": *confirmations
    });

    let mock_client = MockJsonRpcClient::with_response(mock_response);
    let rpc_client = BitcoinCoreRpcClient::with_client(mock_client);
    let inspector = BitcoinInspector::new(rpc_client);

    // when
    let extracted_values = inspector
        .extract(tx_id, threshold, Vec::new())
        .await
        .expect("extract should succeed");

    // then
    let expected_extractions: Vec<BitcoinExtractedValue> = vec![];
    assert_eq!(expected_extractions, extracted_values);
}

#[tokio::test]
async fn extract_propagates_rpc_client_errors() {
    // given
    let tx_id = BitcoinTransactionHash::from([9; 32]);
    let threshold = BlockConfirmations::from(1u64);

    let mock_client = MockJsonRpcClient::with_error(RpcClientError::Transport(Box::new(
        std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused"),
    )));

    let rpc_client = BitcoinCoreRpcClient::with_client(mock_client);
    let inspector = BitcoinInspector::new(rpc_client);

    // when
    let response = inspector
        .extract(tx_id, threshold, vec![BitcoinExtractor::BlockHash])
        .await;

    // then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::RpcClientError(
            RpcError::ClientError
        ))
    );
}

#[tokio::test]
async fn inspector_extracts_block_hash_via_http_rpc_client() {
    // given
    let server = MockServer::start();

    let tx_id = BitcoinTransactionHash::from([9; 32]);
    let expected_block_hash = BitcoinBlockHash::from([5; 32]);
    let confirmations = 10u64;
    let threshold = BlockConfirmations::from(6u64);

    server.mock(|when, then| {
        when.method(POST).path("/");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "jsonrpc": "2.0",
                "result": {
                    "blockhash": expected_block_hash.as_hex(),
                    "confirmations": confirmations
                },
                "id": 0
            }));
    });

    let client = BitcoinCoreRpcClient::new(server.url("/"), RpcAuthentication::KeyInUrl)
        .expect("Failed to create client");
    let inspector = BitcoinInspector::new(client);

    // when
    let extracted_values = inspector
        .extract(tx_id, threshold, vec![BitcoinExtractor::BlockHash])
        .await
        .expect("extract should succeed");

    // then
    let expected_extractions = vec![BitcoinExtractedValue::BlockHash(expected_block_hash)];
    assert_eq!(expected_extractions, extracted_values);
}
