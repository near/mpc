use foreign_chain_inspector::{
    BlockConfirmations, ForeignChainInspectionError, ForeignChainInspector, RpcAuthentication,
    bitcoin::{
        BitcoinBlockHash, BitcoinTransactionHash,
        inspector::{BitcoinExtractedValue, BitcoinExtractor, BitcoinInspector},
        rpc_client::BitcoinCoreRpcClient,
    },
};

use assert_matches::assert_matches;
use httpmock::prelude::*;
use jsonrpsee::core::{
    client::BatchResponse,
    client::{ClientT, error::Error as RpcClientError},
    params::BatchRequestBuilder,
};
use rstest::rstest;
use serde_json::json;
use std::sync::{Arc, Mutex};

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

    let mut mock_client = MockJsonRpcClient::new();
    mock_client
        .expect_request()
        .returning(move |_| Ok(mock_response.clone()));

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

    let mut mock_client = MockJsonRpcClient::new();
    mock_client
        .expect_request()
        .returning(move |_| Ok(mock_response.clone()));

    let rpc_client = BitcoinCoreRpcClient::with_client(mock_client);
    let inspector = BitcoinInspector::new(rpc_client);

    // when
    let response = inspector
        .extract(tx_id, threshold, vec![BitcoinExtractor::BlockHash])
        .await;

    // then
    assert_matches!(
    response,
    Err(ForeignChainInspectionError::NotEnoughBlockConfirmations { expected, got }) => {
        assert_eq!(expected,  threshold);
        assert_eq!(got,  confirmations);
    });
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

    let mut mock_client = MockJsonRpcClient::new();
    mock_client
        .expect_request()
        .returning(move |_| Ok(mock_response.clone()));

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

    let mut mock_client = MockJsonRpcClient::new();
    mock_client.expect_request().returning(|_| {
        Err(RpcClientError::Transport(Box::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connection refused",
        ))))
    });

    let rpc_client = BitcoinCoreRpcClient::with_client(mock_client);
    let inspector = BitcoinInspector::new(rpc_client);

    // when
    let response = inspector
        .extract(tx_id, threshold, vec![BitcoinExtractor::BlockHash])
        .await;

    // then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::RpcClientError(_))
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

// Note: Cannot use mockall::mock! for ClientT trait because mockall doesn't support
// method-level lifetime parameters (like 'a in batch_request).
// Using manual mock implementation that focuses on the `request` method.
/// Mock JSON-RPC client with expectation support for the `request` method
struct MockJsonRpcClient {
    request_handler:
        Arc<Mutex<Box<dyn FnMut(&str) -> Result<serde_json::Value, RpcClientError> + Send>>>,
}

impl MockJsonRpcClient {
    fn new() -> Self {
        Self {
            request_handler: Arc::new(Mutex::new(Box::new(|method| {
                panic!("Unexpected call to request() with method: {}", method)
            }))),
        }
    }

    /// Set up an expectation for the `request` method
    fn expect_request(&mut self) -> RequestExpectation<'_> {
        RequestExpectation { mock: self }
    }
}

struct RequestExpectation<'a> {
    mock: &'a mut MockJsonRpcClient,
}

impl<'a> RequestExpectation<'a> {
    /// Specify what the mocked `request` method should return
    fn returning<F>(self, f: F) -> &'a mut MockJsonRpcClient
    where
        F: FnMut(&str) -> Result<serde_json::Value, RpcClientError> + Send + 'static,
    {
        self.mock.request_handler = Arc::new(Mutex::new(Box::new(f)));
        self.mock
    }
}

impl ClientT for MockJsonRpcClient {
    fn request<R, Params>(
        &self,
        method: &str,
        _params: Params,
    ) -> impl std::future::Future<Output = Result<R, RpcClientError>> + Send
    where
        R: serde::de::DeserializeOwned,
    {
        let handler = self.request_handler.clone();
        let method = method.to_string();

        async move {
            let result = {
                let mut handler = handler.lock().unwrap();
                handler(&method)
            };

            match result {
                Ok(value) => serde_json::from_value(value).map_err(RpcClientError::ParseError),
                Err(e) => Err(e),
            }
        }
    }

    fn notification<Params>(
        &self,
        _method: &str,
        _params: Params,
    ) -> impl std::future::Future<Output = Result<(), RpcClientError>> + Send {
        async { unimplemented!("notification() not used in tests") }
    }

    fn batch_request<'a, R>(
        &self,
        _batch: BatchRequestBuilder<'a>,
    ) -> impl std::future::Future<Output = Result<BatchResponse<'a, R>, RpcClientError>> + Send
    where
        R: serde::de::DeserializeOwned + std::fmt::Debug + 'a,
    {
        async { unimplemented!("batch_request() not used in tests") }
    }
}
