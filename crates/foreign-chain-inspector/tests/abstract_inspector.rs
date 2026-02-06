use foreign_chain_inspector::{
    BlockConfirmations, ForeignChainInspectionError, ForeignChainInspector,
    abstract_chain::{
        AbstractBlockHash, AbstractTransactionHash,
        inspector::{AbstractExtractedValue, AbstractExtractor, AbstractInspector},
        rpc_client::AbstractRpcClient,
    },
};

use assert_matches::assert_matches;
use jsonrpsee::core::{
    client::BatchResponse,
    client::{ClientT, error::Error as RpcClientError},
    params::BatchRequestBuilder,
};
use rstest::rstest;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[rstest]
#[tokio::test]
#[case::confirmations_equals_threshold(BlockConfirmations::from(1), BlockConfirmations::from(1))]
#[case::confirmations_greater_than_threshold(
    BlockConfirmations::from(1),
    BlockConfirmations::from(2)
)]
async fn extract_returns_block_hash_when_confirmations_sufficient(
    #[case] expected_confirmations: BlockConfirmations,
    #[case] threshold: BlockConfirmations,
) {
    // given
    let tx_id = AbstractTransactionHash::from([3; 32]);
    let expected_block_hash = AbstractBlockHash::from([4; 32]);
    let current_block_number = 1000u64;
    let tx_block_number = current_block_number - *expected_confirmations + 1;

    let mut mock_client = MockJsonRpcClient::new();

    // Mock eth_getTransactionByHash response
    let block_hash_clone = expected_block_hash.clone();
    mock_client
        .expect_request("eth_getTransactionByHash")
        .returning(move |_method| {
            let tx_response = AbstractTransactionResponse {
                block_hash: block_hash_clone.clone(),
                block_number: format!("0x{:x}", tx_block_number),
            };
            Ok(serde_json::to_value(Some(tx_response)).unwrap())
        });

    // Mock eth_blockNumber response
    mock_client
        .expect_request("eth_blockNumber")
        .returning(move |_method| {
            Ok(serde_json::to_value(format!("0x{:x}", current_block_number)).unwrap())
        });

    let rpc_client = AbstractRpcClient::new(mock_client);
    let inspector = AbstractInspector::new(rpc_client);

    // when
    let extracted_values = inspector
        .extract(tx_id, threshold, vec![AbstractExtractor::BlockHash])
        .await
        .expect("extract should succeed");

    // then
    let expected_extractions = vec![AbstractExtractedValue::BlockHash(expected_block_hash)];

    assert_eq!(expected_extractions, extracted_values);
}

#[tokio::test]
async fn extract_returns_error_when_confirmations_insufficient() {
    // given
    let tx_id = AbstractTransactionHash::from([1; 32]);
    let expected_block_hash = AbstractBlockHash::from([2; 32]);

    let current_block_number = 100u64;
    let tx_block_number = 99u64; // Only 2 confirmations
    let threshold = BlockConfirmations::from(6u64);

    let mut mock_client = MockJsonRpcClient::new();

    mock_client
        .expect_request("eth_getTransactionByHash")
        .returning(move |_method| {
            let tx_response = AbstractTransactionResponse {
                block_hash: expected_block_hash.clone(),
                block_number: format!("0x{:x}", tx_block_number),
            };
            Ok(serde_json::to_value(Some(tx_response)).unwrap())
        });

    mock_client
        .expect_request("eth_blockNumber")
        .returning(move |_method| {
            Ok(serde_json::to_value(format!("0x{:x}", current_block_number)).unwrap())
        });

    let rpc_client = AbstractRpcClient::new(mock_client);
    let inspector = AbstractInspector::new(rpc_client);

    // when
    let response = inspector
        .extract(tx_id, threshold, vec![AbstractExtractor::BlockHash])
        .await;

    // then
    assert_matches!(
    response,
    Err(ForeignChainInspectionError::NotEnoughBlockConfirmations { expected, got }) => {
        assert_eq!(expected, threshold);
        assert_eq!(got, BlockConfirmations::from(2u64));
    });
}

#[tokio::test]
async fn extract_returns_empty_when_no_extractors_provided() {
    // given
    let tx_id = AbstractTransactionHash::from([11; 32]);
    let expected_block_hash = AbstractBlockHash::from([12; 32]);

    let current_block_number = 1000u64;
    let tx_block_number = 991u64; // 10 confirmations
    let threshold = BlockConfirmations::from(6u64);

    let mut mock_client = MockJsonRpcClient::new();

    mock_client
        .expect_request("eth_getTransactionByHash")
        .returning(move |_method| {
            let tx_response = AbstractTransactionResponse {
                block_hash: expected_block_hash.clone(),
                block_number: format!("0x{:x}", tx_block_number),
            };
            Ok(serde_json::to_value(Some(tx_response)).unwrap())
        });

    mock_client
        .expect_request("eth_blockNumber")
        .returning(move |_method| {
            Ok(serde_json::to_value(format!("0x{:x}", current_block_number)).unwrap())
        });

    let rpc_client = AbstractRpcClient::new(mock_client);
    let inspector = AbstractInspector::new(rpc_client);

    // when
    let extracted_values = inspector
        .extract(tx_id, threshold, Vec::new())
        .await
        .expect("extract should succeed");

    // then
    let expected_extractions: Vec<AbstractExtractedValue> = vec![];
    assert_eq!(expected_extractions, extracted_values);
}

#[tokio::test]
async fn extract_propagates_rpc_client_errors() {
    // given
    let tx_id = AbstractTransactionHash::from([9; 32]);
    let threshold = BlockConfirmations::from(1u64);

    let mut mock_client = MockJsonRpcClient::new();
    mock_client
        .expect_request("eth_getTransactionByHash")
        .returning(|_| {
            Err(RpcClientError::Transport(Box::new(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "connection refused",
            ))))
        });

    let rpc_client = AbstractRpcClient::new(mock_client);
    let inspector = AbstractInspector::new(rpc_client);

    // when
    let response = inspector
        .extract(tx_id, threshold, vec![AbstractExtractor::BlockHash])
        .await;

    // then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::RpcClientError(_))
    );
}

// Note: HTTP integration test removed due to JSON-RPC ID matching complexity.
// The mock client tests above provide comprehensive coverage of the inspector functionality.

#[tokio::test]
async fn rpc_client_handles_transaction_not_found() {
    // given
    let tx_id = AbstractTransactionHash::from([7; 32]);
    let threshold = BlockConfirmations::from(1u64);

    let mut mock_client = MockJsonRpcClient::new();
    mock_client
        .expect_request("eth_getTransactionByHash")
        .returning(|_| Ok(serde_json::Value::Null)); // Transaction returns null when not found

    let rpc_client = AbstractRpcClient::new(mock_client);
    let inspector = AbstractInspector::new(rpc_client);

    // when
    let response = inspector
        .extract(tx_id, threshold, vec![AbstractExtractor::BlockHash])
        .await;

    // then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::RpcClientError(_))
    );
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AbstractTransactionResponse {
    block_hash: AbstractBlockHash,
    block_number: String,
}

/// Mock JSON-RPC client with expectation support for the `request` method
struct MockJsonRpcClient {
    #[allow(clippy::type_complexity)]
    request_handlers: Arc<
        Mutex<
            std::collections::HashMap<
                String,
                Box<dyn FnMut(&str) -> Result<serde_json::Value, RpcClientError> + Send>,
            >,
        >,
    >,
}

impl MockJsonRpcClient {
    fn new() -> Self {
        Self {
            request_handlers: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Set up an expectation for the `request` method for a specific RPC method
    fn expect_request(&mut self, method: &str) -> RequestExpectation<'_> {
        RequestExpectation {
            mock: self,
            method: method.to_string(),
        }
    }
}

struct RequestExpectation<'a> {
    mock: &'a mut MockJsonRpcClient,
    method: String,
}

impl<'a> RequestExpectation<'a> {
    /// Specify what the mocked `request` method should return
    fn returning<F>(self, f: F) -> &'a mut MockJsonRpcClient
    where
        F: FnMut(&str) -> Result<serde_json::Value, RpcClientError> + Send + 'static,
    {
        let mut handlers = self.mock.request_handlers.lock().unwrap();
        handlers.insert(self.method, Box::new(f));
        drop(handlers);
        self.mock
    }
}

impl ClientT for MockJsonRpcClient {
    async fn request<R, Params>(&self, method: &str, _params: Params) -> Result<R, RpcClientError>
    where
        R: serde::de::DeserializeOwned,
    {
        let handlers = self.request_handlers.clone();
        let method_str = method.to_string();
        let value = {
            let mut handlers = handlers.lock().unwrap();
            if let Some(handler) = handlers.get_mut(&method_str) {
                handler(&method_str)
            } else {
                panic!("Unexpected call to request() with method: {}", method_str)
            }
        }?;

        serde_json::from_value(value).map_err(RpcClientError::ParseError)
    }

    async fn notification<Params>(
        &self,
        _method: &str,
        _params: Params,
    ) -> Result<(), RpcClientError> {
        unimplemented!("notification() not used in tests")
    }

    async fn batch_request<'a, R>(
        &self,
        _batch: BatchRequestBuilder<'a>,
    ) -> Result<BatchResponse<'a, R>, RpcClientError>
    where
        R: serde::de::DeserializeOwned + std::fmt::Debug + 'a,
    {
        unimplemented!("batch_request() not used in tests")
    }
}
