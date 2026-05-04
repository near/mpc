pub mod common;

use crate::common::FixedResponseRpcClient;

use foreign_chain_inspector::{
    EthereumFinality, ForeignChainInspectionError, ForeignChainInspector, RpcAuthentication,
    build_http_client,
    evm::inspector::{EvmChain, EvmExtractedValue, EvmExtractor, EvmInspector},
};

use assert_matches::assert_matches;
use foreign_chain_rpc_interfaces::evm::{
    GetBlockByNumberResponse, GetTransactionReceiptResponse, H160, H256, Log, U64,
};
use httpmock::prelude::*;
use httpmock::{HttpMockRequest, HttpMockResponse};
use jsonrpsee::core::client::error::Error as RpcClientError;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Mocks the three RPC calls the inspector issues, in order:
///   1. `eth_getTransactionReceipt(<tx hash>)` → receipt
///   2. `eth_getBlockByNumber(<finality tag>)` → finality head
///   3. `eth_getBlockByNumber(<receipt.block_number>)` → canonical block at that height
///
/// Later calls are only reached if earlier checks pass; tests that exercise an early failure
/// path still need to supply later responses, but they will not be observed.
fn mock_evm_client(
    finality_block_response: GetBlockByNumberResponse,
    tx_response: GetTransactionReceiptResponse,
    canonical_block_response: GetBlockByNumberResponse,
) -> FixedResponseRpcClient<impl Fn() -> Result<serde_json::Value, RpcClientError>> {
    let call_count = AtomicUsize::new(0);
    FixedResponseRpcClient::new(move || {
        let count = call_count.fetch_add(1, Ordering::SeqCst);
        match count {
            0 => Ok(serde_json::to_value(&tx_response).unwrap()),
            1 => Ok(serde_json::to_value(&finality_block_response).unwrap()),
            2 => Ok(serde_json::to_value(&canonical_block_response).unwrap()),
            _ => panic!("unexpected fourth RPC call"),
        }
    })
}

fn expected_extracted_value<Chain: EvmChain>(
    extractor: &EvmExtractor,
    tx_response: &GetTransactionReceiptResponse,
) -> EvmExtractedValue<Chain> {
    match extractor {
        EvmExtractor::BlockHash => {
            EvmExtractedValue::BlockHash(From::from(*tx_response.block_hash.as_fixed_bytes()))
        }
        EvmExtractor::Log { log_index } => {
            let target_index = U64::from(*log_index);
            let log = tx_response
                .logs
                .iter()
                .find(|log| log.log_index == target_index)
                .expect("test log with matching log_index should exist");
            EvmExtractedValue::Log(log.clone())
        }
    }
}

fn test_log() -> Log {
    Log {
        removed: false,
        log_index: U64([1]),
        transaction_index: U64([2]),
        transaction_hash: H256([3; 32]),
        block_hash: H256([4; 32]),
        block_number: U64([5]),
        address: H160([6; 20]),
        data: "test_log".to_string(),
        topics: vec![H256([7; 32]), H256([8; 32])],
    }
}

macro_rules! evm_inspector_tests {
    ($chain:ty, $mod_name:ident) => {
        mod $mod_name {
            use super::*;
            use rstest::rstest;

            type Inspector<C> = EvmInspector<C, $chain>;
            type TxHash = <$chain as EvmChain>::TransactionHash;
            type BlockHash = <$chain as EvmChain>::BlockHash;
            type ExtractedValue = EvmExtractedValue<$chain>;

            #[rstest]
            #[tokio::test]
            async fn extract_returns_correct_value_when_finalized(
                #[values(EthereumFinality::Finalized, EthereumFinality::Safe)]
                finality: EthereumFinality,
                #[values(EvmExtractor::Log { log_index: 1 }, EvmExtractor::BlockHash)]
                extractor: EvmExtractor,
            ) {
                // given
                let tx_id = TxHash::from([3; 32]);

                let block_response = GetBlockByNumberResponse {
                    number: U64::from(100),
                    hash: H256::from([0xaa; 32]),
                };
                let tx_response = GetTransactionReceiptResponse {
                    block_hash: H256::from([4; 32]),
                    block_number: U64::from(90),
                    status: U64::one(),
                    logs: vec![test_log()],
                };
                let canonical_block_response = GetBlockByNumberResponse {
                    number: tx_response.block_number,
                    hash: tx_response.block_hash,
                };

                let expected = expected_extracted_value::<$chain>(&extractor, &tx_response);
                let mock_client =
                    mock_evm_client(block_response, tx_response, canonical_block_response);
                let inspector = Inspector::new(mock_client);

                // when
                let extracted_values = inspector
                    .extract(tx_id, finality, vec![extractor])
                    .await
                    .unwrap();

                // then
                assert_eq!(vec![expected], extracted_values);
            }

            #[tokio::test]
            async fn extract_succeeds_when_finality_block_equals_tx_block() {
                // given
                let tx_id = TxHash::from([3; 32]);
                let expected_block_hash = BlockHash::from([4; 32]);

                let block_number = U64::from(50);
                let block_response = GetBlockByNumberResponse {
                    number: block_number,
                    hash: H256::from([0xaa; 32]),
                };
                let tx_response = GetTransactionReceiptResponse {
                    block_hash: H256::from([4; 32]),
                    block_number,
                    status: U64::one(),
                    logs: vec![test_log()],
                };
                let canonical_block_response = GetBlockByNumberResponse {
                    number: block_number,
                    hash: tx_response.block_hash,
                };

                let mock_client =
                    mock_evm_client(block_response, tx_response, canonical_block_response);
                let inspector = Inspector::new(mock_client);

                // when
                let extracted_values = inspector
                    .extract(
                        tx_id,
                        EthereumFinality::Finalized,
                        vec![EvmExtractor::BlockHash],
                    )
                    .await
                    .unwrap();

                // then
                let expected_extractions =
                    vec![ExtractedValue::BlockHash(expected_block_hash)];
                assert_eq!(expected_extractions, extracted_values);
            }

            #[tokio::test]
            async fn extract_returns_error_when_not_finalized() {
                // given
                let tx_id = TxHash::from([1; 32]);

                let block_response = GetBlockByNumberResponse {
                    number: U64::from(50),
                    hash: H256::from([0xaa; 32]),
                };
                let tx_response = GetTransactionReceiptResponse {
                    block_hash: H256::from([2; 32]),
                    block_number: U64::from(60),
                    status: U64::one(),
                    logs: vec![test_log()],
                };
                // not reached: extract returns NotFinalized before the canonical lookup
                let canonical_block_response = GetBlockByNumberResponse {
                    number: tx_response.block_number,
                    hash: tx_response.block_hash,
                };

                let mock_client =
                    mock_evm_client(block_response, tx_response, canonical_block_response);
                let inspector = Inspector::new(mock_client);

                // when
                let response = inspector
                    .extract(
                        tx_id,
                        EthereumFinality::Finalized,
                        vec![EvmExtractor::BlockHash],
                    )
                    .await;

                // then
                assert_matches!(response, Err(ForeignChainInspectionError::NotFinalized));
            }

            #[tokio::test]
            async fn extract_returns_error_when_transaction_failed() {
                // given
                let tx_id = TxHash::from([1; 32]);

                let block_response = GetBlockByNumberResponse {
                    number: U64::from(100),
                    hash: H256::from([0xaa; 32]),
                };
                let tx_response = GetTransactionReceiptResponse {
                    block_hash: H256::from([2; 32]),
                    block_number: U64::from(90),
                    status: U64::zero(),
                    logs: vec![test_log()],
                };
                let canonical_block_response = GetBlockByNumberResponse {
                    number: tx_response.block_number,
                    hash: tx_response.block_hash,
                };

                let mock_client =
                    mock_evm_client(block_response, tx_response, canonical_block_response);
                let inspector = Inspector::new(mock_client);

                // when
                let response = inspector
                    .extract(
                        tx_id,
                        EthereumFinality::Finalized,
                        vec![EvmExtractor::BlockHash],
                    )
                    .await;

                // then
                assert_matches!(
                    response,
                    Err(ForeignChainInspectionError::TransactionFailed)
                );
            }

            #[tokio::test]
            async fn extract_returns_empty_when_no_extractors_provided() {
                // given
                let tx_id = TxHash::from([11; 32]);

                let block_response = GetBlockByNumberResponse {
                    number: U64::from(100),
                    hash: H256::from([0xaa; 32]),
                };
                let tx_response = GetTransactionReceiptResponse {
                    block_hash: H256::from([12; 32]),
                    block_number: U64::from(90),
                    status: U64::one(),
                    logs: vec![test_log()],
                };
                let canonical_block_response = GetBlockByNumberResponse {
                    number: tx_response.block_number,
                    hash: tx_response.block_hash,
                };

                let mock_client =
                    mock_evm_client(block_response, tx_response, canonical_block_response);
                let inspector = Inspector::new(mock_client);

                // when
                let extracted_values = inspector
                    .extract(tx_id, EthereumFinality::Finalized, Vec::new())
                    .await
                    .unwrap();

                // then
                let expected_extractions: Vec<ExtractedValue> = vec![];
                assert_eq!(expected_extractions, extracted_values);
            }

            #[tokio::test]
            async fn extract_propagates_rpc_client_errors() {
                // given
                let tx_id = TxHash::from([9; 32]);

                let mock_client = FixedResponseRpcClient::new(|| {
                    Err(RpcClientError::Transport(Box::new(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "connection refused",
                    ))))
                });
                let inspector = Inspector::new(mock_client);

                // when
                let response = inspector
                    .extract(
                        tx_id,
                        EthereumFinality::Finalized,
                        vec![EvmExtractor::BlockHash],
                    )
                    .await;

                // then
                assert_matches!(
                    response,
                    Err(ForeignChainInspectionError::ClientError(_))
                );
            }

            #[tokio::test]
            async fn inspector_extracts_block_hash_via_http_rpc_client() {
                // given
                let server = MockServer::start();

                let tx_id = TxHash::from([9; 32]);
                let expected_block_hash = BlockHash::from([5; 32]);

                let finality_block_response = GetBlockByNumberResponse {
                    number: U64::from(100),
                    hash: H256::from([0xaa; 32]),
                };

                let tx_response = GetTransactionReceiptResponse {
                    block_hash: H256::from([5; 32]),
                    block_number: U64::from(90),
                    status: U64::one(),
                    logs: vec![test_log()],
                };

                let canonical_block_response = GetBlockByNumberResponse {
                    number: tx_response.block_number,
                    hash: tx_response.block_hash,
                };

                server.mock(|when, then| {
                    when.method(POST).path("/");
                    then.respond_with(move |req: &HttpMockRequest| {
                        let body: serde_json::Value = serde_json::from_slice(req.body().as_ref())
                            .expect("valid json-rpc request");
                        let id = body["id"].clone();
                        let method = body["method"].as_str().expect("method field");

                        let result = match method {
                            "eth_getBlockByNumber" => {
                                // Dispatch on the first param: a finality tag like "finalized"
                                // or a hex-encoded block number. The inspector queries the
                                // finality head first and then the canonical block at the
                                // receipt's height.
                                let first_param = body["params"][0]
                                    .as_str()
                                    .expect("first param is a string");
                                let is_finality_tag = matches!(
                                    first_param,
                                    "finalized" | "safe" | "latest"
                                );
                                if is_finality_tag {
                                    serde_json::to_value(&finality_block_response).unwrap()
                                } else {
                                    serde_json::to_value(&canonical_block_response).unwrap()
                                }
                            }
                            "eth_getTransactionReceipt" => {
                                serde_json::to_value(&tx_response).unwrap()
                            }
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

                let client =
                    build_http_client(server.url("/"), RpcAuthentication::KeyInUrl).unwrap();
                let inspector = Inspector::new(client);

                // when
                let extracted_values = inspector
                    .extract(
                        tx_id,
                        EthereumFinality::Finalized,
                        vec![EvmExtractor::BlockHash],
                    )
                    .await
                    .unwrap();

                // then
                let expected_extractions =
                    vec![ExtractedValue::BlockHash(expected_block_hash)];
                assert_eq!(expected_extractions, extracted_values);
            }

            #[tokio::test]
            async fn extract_returns_error_when_log_index_out_of_bounds() {
                // given
                let tx_id = TxHash::from([1; 32]);

                let block_response = GetBlockByNumberResponse {
                    number: U64::from(100),
                    hash: H256::from([0xaa; 32]),
                };
                let tx_response = GetTransactionReceiptResponse {
                    block_hash: H256::from([2; 32]),
                    block_number: U64::from(90),
                    status: U64::one(),
                    logs: vec![test_log()],
                };
                let canonical_block_response = GetBlockByNumberResponse {
                    number: tx_response.block_number,
                    hash: tx_response.block_hash,
                };

                let mock_client =
                    mock_evm_client(block_response, tx_response, canonical_block_response);
                let inspector = Inspector::new(mock_client);

                // when
                let response = inspector
                    .extract(
                        tx_id,
                        EthereumFinality::Finalized,
                        vec![EvmExtractor::Log { log_index: 5 }],
                    )
                    .await;

                // then
                assert_matches!(
                    response,
                    Err(ForeignChainInspectionError::LogIndexOutOfBounds)
                );
            }

            #[tokio::test]
            async fn extract_returns_correct_log_by_evm_log_index() {
                // given: logs with block-level logIndex values (not array positions)
                let tx_id = TxHash::from([3; 32]);

                let log_at_index_20 = Log {
                    removed: false,
                    log_index: U64::from(20),
                    transaction_index: U64([2]),
                    transaction_hash: H256([3; 32]),
                    block_hash: H256([4; 32]),
                    block_number: U64([5]),
                    address: H160([6; 20]),
                    data: "first_log".to_string(),
                    topics: vec![H256([7; 32])],
                };
                let log_at_index_21 = Log {
                    removed: false,
                    log_index: U64::from(21),
                    transaction_index: U64([20]),
                    transaction_hash: H256([30; 32]),
                    block_hash: H256([4; 32]),
                    block_number: U64([5]),
                    address: H160([60; 20]),
                    data: "second_log".to_string(),
                    topics: vec![H256([70; 32])],
                };
                let expected_log = log_at_index_21.clone();

                let block_response = GetBlockByNumberResponse {
                    number: U64::from(100),
                    hash: H256::from([0xaa; 32]),
                };
                let tx_response = GetTransactionReceiptResponse {
                    block_hash: H256::from([4; 32]),
                    block_number: U64::from(90),
                    status: U64::one(),
                    logs: vec![log_at_index_20, log_at_index_21],
                };
                let canonical_block_response = GetBlockByNumberResponse {
                    number: tx_response.block_number,
                    hash: tx_response.block_hash,
                };

                let mock_client =
                    mock_evm_client(block_response, tx_response, canonical_block_response);
                let inspector = Inspector::new(mock_client);

                // when: request log by its EVM logIndex (21), not array position (1)
                let extracted_values = inspector
                    .extract(
                        tx_id,
                        EthereumFinality::Finalized,
                        vec![EvmExtractor::Log { log_index: 21 }],
                    )
                    .await
                    .unwrap();

                // then
                let expected_extractions = vec![ExtractedValue::Log(expected_log)];
                assert_eq!(expected_extractions, extracted_values);
            }

            #[tokio::test]
            async fn extract_returns_error_when_receipt_block_hash_is_not_canonical() {
                // given: the receipt is past the finality head (so the number-only check passes)
                // but its block hash differs from the canonical block hash at that height,
                // simulating an RPC that served a side-block receipt for a finalized height.
                let tx_id = TxHash::from([1; 32]);

                let block_response = GetBlockByNumberResponse {
                    number: U64::from(100),
                    hash: H256::from([0xaa; 32]),
                };
                let tx_response = GetTransactionReceiptResponse {
                    block_hash: H256::from([0xbb; 32]),
                    block_number: U64::from(90),
                    status: U64::one(),
                    logs: vec![test_log()],
                };
                let canonical_block_response = GetBlockByNumberResponse {
                    number: tx_response.block_number,
                    hash: H256::from([0xcc; 32]),
                };

                let mock_client =
                    mock_evm_client(block_response, tx_response, canonical_block_response);
                let inspector = Inspector::new(mock_client);

                // when
                let response = inspector
                    .extract(
                        tx_id,
                        EthereumFinality::Finalized,
                        vec![EvmExtractor::BlockHash],
                    )
                    .await;

                // then
                assert_matches!(
                    response,
                    Err(ForeignChainInspectionError::NonCanonicalBlock {
                        block_number,
                        receipt_hash,
                        canonical_hash,
                    }) if block_number == U64::from(90)
                        && receipt_hash == H256::from([0xbb; 32])
                        && canonical_hash == H256::from([0xcc; 32])
                );
            }
        }
    };
}

evm_inspector_tests!(
    foreign_chain_inspector::abstract_chain::inspector::Abstract,
    abstract_chain
);
evm_inspector_tests!(foreign_chain_inspector::base::inspector::Base, base);
evm_inspector_tests!(foreign_chain_inspector::bnb::inspector::Bnb, bnb);
evm_inspector_tests!(
    foreign_chain_inspector::arbitrum::inspector::Arbitrum,
    arbitrum
);
