#![allow(non_snake_case)]

pub mod common;

use crate::common::{
    FixedResponseRpcClient, SequentialResponseMockClientBuilder, mock_client_from_fixed_response,
};

use foreign_chain_inspector::{
    BlockConfirmations, ForeignChainInspectionError, ForeignChainInspector, RpcAuthentication,
    bitcoin::{
        BitcoinBlockHash, BitcoinExtractedValue, BitcoinTransactionHash,
        inspector::{BitcoinExtractor, BitcoinInspector},
    },
    build_http_client,
};

use assert_matches::assert_matches;
use foreign_chain_rpc_interfaces::bitcoin::{
    GetBlockHeaderVerboseResponse, GetRawTransactionVerboseResponse, TransportBitcoinBlockHash,
};
use httpmock::prelude::*;
use httpmock::{HttpMockRequest, HttpMockResponse};
use jsonrpsee::core::client::error::Error as RpcClientError;
use rstest::rstest;

const TEST_BLOCK_HEIGHT: u64 = 800_000;
const TEST_SUFFICIENT_CONFIRMATIONS: u64 = 10;

#[rstest]
#[case::confirmations_equals_threshold(BlockConfirmations::from(1), BlockConfirmations::from(1))]
#[case::confirmations_greater_than_threshold(
    BlockConfirmations::from(2),
    BlockConfirmations::from(1)
)]
#[tokio::test]
async fn extract_returns_block_hash_when_confirmations_sufficient(
    #[case] confirmations: BlockConfirmations,
    #[case] threshold: BlockConfirmations,
) {
    // given
    let tx_id = BitcoinTransactionHash::from([3; 32]);
    let expected_block_hash = BitcoinBlockHash::from([4; 32]);
    let transport_block_hash = TransportBitcoinBlockHash::from(*expected_block_hash);

    let tx_response = GetRawTransactionVerboseResponse {
        blockhash: transport_block_hash,
        confirmations: *confirmations,
    };
    let block_response = GetBlockHeaderVerboseResponse {
        hash: transport_block_hash,
        height: TEST_BLOCK_HEIGHT,
    };

    let mock_client = SequentialResponseMockClientBuilder::new()
        .with_response(tx_response)
        .with_response(block_response)
        .with_response(transport_block_hash)
        .build();
    let inspector = BitcoinInspector::new(mock_client);

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

    let mock_response = GetRawTransactionVerboseResponse {
        blockhash: TransportBitcoinBlockHash::from(*expected_block_hash),
        confirmations: *confirmations,
    };

    let mock_client = mock_client_from_fixed_response(mock_response);
    let inspector = BitcoinInspector::new(mock_client);

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
    let transport_block_hash = TransportBitcoinBlockHash::from(*expected_block_hash);

    let tx_response = GetRawTransactionVerboseResponse {
        blockhash: transport_block_hash,
        confirmations: *confirmations,
    };
    let block_response = GetBlockHeaderVerboseResponse {
        hash: transport_block_hash,
        height: TEST_BLOCK_HEIGHT,
    };

    let mock_client = SequentialResponseMockClientBuilder::new()
        .with_response(tx_response)
        .with_response(block_response)
        .with_response(transport_block_hash)
        .build();
    let inspector = BitcoinInspector::new(mock_client);

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
    let inspector = BitcoinInspector::new(mock_client);

    // when
    let response = inspector
        .extract(tx_id, threshold, vec![BitcoinExtractor::BlockHash])
        .await;

    // then
    assert_matches!(response, Err(ForeignChainInspectionError::ClientError(_)));
}

#[tokio::test]
async fn extract__should_return_non_canonical_block_when_receipt_blockhash_differs_from_canonical()
{
    // given: the receipt's blockhash exists (getblockheader resolves its height) but the canonical hash
    // at that height differs, simulating an RPC that returned a receipt for a side block.
    let tx_id = BitcoinTransactionHash::from([1; 32]);
    let threshold = BlockConfirmations::from(1u64);
    let receipt_hash_bytes = [0xbb; 32];
    let canonical_hash_bytes = [0xcc; 32];
    let receipt_blockhash = TransportBitcoinBlockHash::from(receipt_hash_bytes);
    let canonical_blockhash = TransportBitcoinBlockHash::from(canonical_hash_bytes);

    let tx_response = GetRawTransactionVerboseResponse {
        blockhash: receipt_blockhash,
        confirmations: TEST_SUFFICIENT_CONFIRMATIONS,
    };
    let block_response = GetBlockHeaderVerboseResponse {
        hash: receipt_blockhash,
        height: TEST_BLOCK_HEIGHT,
    };

    let mock_client = SequentialResponseMockClientBuilder::new()
        .with_response(tx_response)
        .with_response(block_response)
        .with_response(canonical_blockhash)
        .build();
    let inspector = BitcoinInspector::new(mock_client);

    // when
    let response = inspector
        .extract(tx_id, threshold, vec![BitcoinExtractor::BlockHash])
        .await;

    // then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::NonCanonicalBlock {
            block_number,
            receipt_hash,
            canonical_hash,
        }) if block_number == TEST_BLOCK_HEIGHT
            && receipt_hash == foreign_chain_inspector::HexBytes(receipt_hash_bytes.to_vec())
            && canonical_hash == foreign_chain_inspector::HexBytes(canonical_hash_bytes.to_vec())
    );
}

/// `getblockheader` looks a header up by hash, so a backend that echoes back a *different* hash
/// is misbehaving, simulating an RPC that returned the wrong block for the queried hash.
#[tokio::test]
async fn extract__should_return_inconsistent_rpc_response_when_get_block_header_echoes_different_hash()
 {
    // given
    let tx_id = BitcoinTransactionHash::from([1; 32]);
    let threshold = BlockConfirmations::from(1u64);
    let receipt_hash_bytes = [0xbb; 32];
    let returned_hash_bytes = [0xdd; 32];
    let receipt_blockhash = TransportBitcoinBlockHash::from(receipt_hash_bytes);
    let returned_blockhash = TransportBitcoinBlockHash::from(returned_hash_bytes);

    let tx_response = GetRawTransactionVerboseResponse {
        blockhash: receipt_blockhash,
        confirmations: TEST_SUFFICIENT_CONFIRMATIONS,
    };
    let block_response = GetBlockHeaderVerboseResponse {
        hash: returned_blockhash,
        height: TEST_BLOCK_HEIGHT,
    };

    let mock_client = SequentialResponseMockClientBuilder::new()
        .with_response(tx_response)
        .with_response(block_response)
        .build();
    let inspector = BitcoinInspector::new(mock_client);

    // when
    let response = inspector
        .extract(tx_id, threshold, vec![BitcoinExtractor::BlockHash])
        .await;

    // then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::InconsistentRpcResponse {
            requested_hash,
            returned_hash,
        }) if requested_hash == foreign_chain_inspector::HexBytes(receipt_hash_bytes.to_vec())
            && returned_hash == foreign_chain_inspector::HexBytes(returned_hash_bytes.to_vec())
    );
}

#[tokio::test]
async fn extract__should_propagate_get_block_header_deserialize_error() {
    // given: getrawtransaction succeeds; getblockheader returns a payload that fails to deserialize.
    let tx_id = BitcoinTransactionHash::from([1; 32]);
    let threshold = BlockConfirmations::from(1u64);
    let receipt_blockhash = TransportBitcoinBlockHash::from([0xbb; 32]);

    let tx_response = GetRawTransactionVerboseResponse {
        blockhash: receipt_blockhash,
        confirmations: TEST_SUFFICIENT_CONFIRMATIONS,
    };

    let mock_client = SequentialResponseMockClientBuilder::new()
        .with_response(tx_response)
        .with_response(serde_json::json!({ "unexpected": "shape" }))
        .build();
    let inspector = BitcoinInspector::new(mock_client);

    // when
    let response = inspector
        .extract(tx_id, threshold, vec![BitcoinExtractor::BlockHash])
        .await;

    // then
    assert_matches!(response, Err(ForeignChainInspectionError::ClientError(_)));
}

#[tokio::test]
async fn extract__should_propagate_getblockhash_deserialize_error() {
    // given: getrawtransaction and getblockheader succeed; getblockhash returns a payload that fails to deserialize.
    let tx_id = BitcoinTransactionHash::from([1; 32]);
    let threshold = BlockConfirmations::from(1u64);
    let receipt_blockhash = TransportBitcoinBlockHash::from([0xbb; 32]);

    let tx_response = GetRawTransactionVerboseResponse {
        blockhash: receipt_blockhash,
        confirmations: TEST_SUFFICIENT_CONFIRMATIONS,
    };
    let block_response = GetBlockHeaderVerboseResponse {
        hash: receipt_blockhash,
        height: TEST_BLOCK_HEIGHT,
    };

    let mock_client = SequentialResponseMockClientBuilder::new()
        .with_response(tx_response)
        .with_response(block_response)
        .with_response(serde_json::json!(42))
        .build();
    let inspector = BitcoinInspector::new(mock_client);

    // when
    let response = inspector
        .extract(tx_id, threshold, vec![BitcoinExtractor::BlockHash])
        .await;

    // then
    assert_matches!(response, Err(ForeignChainInspectionError::ClientError(_)));
}

#[tokio::test]
async fn inspector_extracts_block_hash_via_http_rpc_client() {
    // given
    let server = MockServer::start();

    let tx_id = BitcoinTransactionHash::from([9; 32]);
    let expected_block_hash = BitcoinBlockHash::from([5; 32]);
    let transport_block_hash = TransportBitcoinBlockHash::from(*expected_block_hash);
    let threshold = BlockConfirmations::from(6u64);

    let tx_response = GetRawTransactionVerboseResponse {
        blockhash: transport_block_hash,
        confirmations: TEST_SUFFICIENT_CONFIRMATIONS,
    };
    let block_response = GetBlockHeaderVerboseResponse {
        hash: transport_block_hash,
        height: TEST_BLOCK_HEIGHT,
    };

    server.mock(|when, then| {
        when.method(POST).path("/");
        then.respond_with(move |req: &HttpMockRequest| {
            let body: serde_json::Value =
                serde_json::from_slice(req.body().as_ref()).expect("valid json-rpc request");
            let id = body["id"].clone();
            let method = body["method"].as_str().expect("method field");

            let result = match method {
                "getrawtransaction" => serde_json::to_value(&tx_response).unwrap(),
                "getblockheader" => serde_json::to_value(&block_response).unwrap(),
                "getblockhash" => serde_json::to_value(transport_block_hash).unwrap(),
                other => panic!("unexpected RPC method: {other}"),
            };

            let response_body = serde_json::json!({
                "jsonrpc": "2.0",
                "result": result,
                "id": id,
            });

            HttpMockResponse::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(serde_json::to_string(&response_body).unwrap())
                .build()
        });
    });

    let client = build_http_client(server.url("/"), RpcAuthentication::KeyInUrl).unwrap();
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
