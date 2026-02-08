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
use serde::{Deserialize, Serialize};
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
    let mock_response = BitcoinTransactionResponse {
        blockhash: expected_block_hash.clone(),
        confirmations: *confirmations,
    };

    let mock_client = mock_client_from_fixed_response(mock_response);

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

    let mock_response = BitcoinTransactionResponse {
        blockhash: expected_block_hash,
        confirmations: *confirmations,
    };

    let mock_client = mock_client_from_fixed_response(mock_response);

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

    let mock_response = BitcoinTransactionResponse {
        blockhash: expected_block_hash,
        confirmations: *confirmations,
    };

    let mock_client = mock_client_from_fixed_response(mock_response);

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

    let mock_client = FixedResponseRpcClient::new(|| {
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

        let response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: BitcoinTransactionResponse {
                blockhash: expected_block_hash.clone(),
                confirmations,
            },
            id: 0,
        };

        then.status(200)
            .header("content-type", "application/json")
            .json_body(serde_json::to_value(&response).unwrap());
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BitcoinTransactionResponse {
    blockhash: BitcoinBlockHash,
    confirmations: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonRpcResponse<T> {
    jsonrpc: String,
    result: T,
    id: u64,
}

/// A client that always returns a hard-coded response.
/// Useful for tests.
/// Note: We have to hold a closure and not just the response
/// because `RpcClientError` does not implement `Clone`.
struct FixedResponseRpcClient<RespFn> {
    response_fn: RespFn,
}

impl<RespFn> FixedResponseRpcClient<RespFn> {
    fn new(response_fn: RespFn) -> Self {
        Self { response_fn }
    }
}

fn mock_client_from_fixed_response(
    response: impl serde::Serialize + Clone,
) -> FixedResponseRpcClient<impl Fn() -> Result<serde_json::Value, RpcClientError>> {
    FixedResponseRpcClient {
        response_fn: move || Ok(serde_json::to_value(response.clone()).unwrap()),
    }
}

impl<RespFn> ClientT for FixedResponseRpcClient<RespFn>
where
    RespFn: Fn() -> Result<serde_json::Value, RpcClientError> + Sync,
{
    async fn request<R, Params>(&self, _method: &str, _params: Params) -> Result<R, RpcClientError>
    where
        R: serde::de::DeserializeOwned,
    {
        serde_json::from_value((self.response_fn)()?).map_err(RpcClientError::ParseError)
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
