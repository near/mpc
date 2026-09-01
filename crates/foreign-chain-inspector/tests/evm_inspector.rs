#![allow(non_snake_case)]

pub mod common;

use crate::common::{
    FixedResponseRpcClient, SequentialResponseMockClientBuilder, mock_client_from_fixed_response,
};

use foreign_chain_inspector::{
    EthereumFinality, ForeignChainInspectionError, ForeignChainInspector,
    NetworkFingerprintInspector, RpcAuthentication, Verdict,
    base::inspector::Base,
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
        block_number: U64::from(90),
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

                let finality_block_response = GetBlockByNumberResponse {
                    number: U64::from(100),
                    hash: H256::from([0xaa; 32]),
                };
                let tx_response = GetTransactionReceiptResponse {
                    transaction_hash: H256::from([3; 32]),
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
                let mock_client = SequentialResponseMockClientBuilder::new()
                    .with_response(&tx_response)
                    .with_response(&finality_block_response)
                    .with_response(&canonical_block_response)
                    .build();
                let inspector = Inspector::new(mock_client);

                // when
                let extracted_values = inspector
                    .extract(tx_id, finality, vec![extractor])
                    .await
                    .unwrap();

                // then
                assert_eq!(Verdict::Extracted(vec![expected]), extracted_values);
            }

            #[tokio::test]
            async fn extract_succeeds_when_finality_block_equals_tx_block() {
                // given
                let tx_id = TxHash::from([3; 32]);
                let expected_block_hash = BlockHash::from([4; 32]);

                let block_number = U64::from(50);
                let finality_block_response = GetBlockByNumberResponse {
                    number: block_number,
                    hash: H256::from([0xaa; 32]),
                };
                let tx_response = GetTransactionReceiptResponse {
                    transaction_hash: H256::from([3; 32]),
                    block_hash: H256::from([4; 32]),
                    block_number,
                    status: U64::one(),
                    logs: vec![test_log()],
                };
                let canonical_block_response = GetBlockByNumberResponse {
                    number: block_number,
                    hash: tx_response.block_hash,
                };

                let mock_client = SequentialResponseMockClientBuilder::new()
                    .with_response(&tx_response)
                    .with_response(&finality_block_response)
                    .with_response(&canonical_block_response)
                    .build();
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
                assert_eq!(Verdict::Extracted(expected_extractions), extracted_values);
            }

            #[tokio::test]
            async fn extract_returns_error_when_not_finalized() {
                // given
                let tx_id = TxHash::from([1; 32]);

                let finality_block_response = GetBlockByNumberResponse {
                    number: U64::from(50),
                    hash: H256::from([0xaa; 32]),
                };
                let tx_response = GetTransactionReceiptResponse {
                    transaction_hash: H256::from([1; 32]),
                    block_hash: H256::from([2; 32]),
                    block_number: U64::from(60),
                    status: U64::one(),
                    logs: vec![test_log()],
                };

                // extract returns NotFinalized before the canonical lookup, so only two RPC
                // calls are exercised.
                let mock_client = SequentialResponseMockClientBuilder::new()
                    .with_response(&tx_response)
                    .with_response(&finality_block_response)
                    .build();
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
            async fn extract_returns_the_transaction_failed_verdict() {
                // given
                let tx_id = TxHash::from([1; 32]);

                let finality_block_response = GetBlockByNumberResponse {
                    number: U64::from(100),
                    hash: H256::from([0xaa; 32]),
                };
                let tx_response = GetTransactionReceiptResponse {
                    transaction_hash: H256::from([1; 32]),
                    block_hash: H256::from([2; 32]),
                    block_number: U64::from(90),
                    status: U64::zero(),
                    logs: vec![test_log()],
                };
                let canonical_block_response = GetBlockByNumberResponse {
                    number: tx_response.block_number,
                    hash: tx_response.block_hash,
                };

                // The status check happens after the canonical lookup, so all three RPC
                // calls are exercised before TransactionFailed is returned.
                let mock_client = SequentialResponseMockClientBuilder::new()
                    .with_response(&tx_response)
                    .with_response(&finality_block_response)
                    .with_response(&canonical_block_response)
                    .build();
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
                    Ok(Verdict::TransactionFailed)
                );
            }

            #[tokio::test]
            async fn extract_returns_empty_when_no_extractors_provided() {
                // given
                let tx_id = TxHash::from([11; 32]);

                let finality_block_response = GetBlockByNumberResponse {
                    number: U64::from(100),
                    hash: H256::from([0xaa; 32]),
                };
                let tx_response = GetTransactionReceiptResponse {
                    transaction_hash: H256::from([11; 32]),
                    block_hash: H256::from([12; 32]),
                    block_number: U64::from(90),
                    status: U64::one(),
                    logs: vec![test_log()],
                };
                let canonical_block_response = GetBlockByNumberResponse {
                    number: tx_response.block_number,
                    hash: tx_response.block_hash,
                };

                let mock_client = SequentialResponseMockClientBuilder::new()
                    .with_response(&tx_response)
                    .with_response(&finality_block_response)
                    .with_response(&canonical_block_response)
                    .build();
                let inspector = Inspector::new(mock_client);

                // when
                let extracted_values = inspector
                    .extract(tx_id, EthereumFinality::Finalized, Vec::new())
                    .await
                    .unwrap();

                // then
                let expected_extractions: Vec<ExtractedValue> = vec![];
                assert_eq!(Verdict::Extracted(expected_extractions), extracted_values);
            }

            #[tokio::test]
            async fn extract_returns_the_not_found_verdict_when_the_receipt_is_null() {
                // given: `eth_getTransactionReceipt` answers `null` for an unknown transaction.
                let mock_client = SequentialResponseMockClientBuilder::new()
                    .with_response(&serde_json::Value::Null)
                    .build();
                let inspector = Inspector::new(mock_client);

                // when
                let response = inspector
                    .extract(
                        TxHash::from([9; 32]),
                        EthereumFinality::Finalized,
                        vec![EvmExtractor::BlockHash],
                    )
                    .await;

                // then
                assert_matches!(response, Ok(Verdict::TransactionNotFound));
            }

            #[tokio::test]
            async fn extract__should_classify_rpc_client_errors() {
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
                    Err(ForeignChainInspectionError::RpcRequestFailed(_))
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
                    transaction_hash: H256::from([9; 32]),
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
                assert_eq!(Verdict::Extracted(expected_extractions), extracted_values);
            }

            #[tokio::test]
            async fn extract_returns_the_out_of_bounds_verdict_when_log_index_is_absent() {
                // given
                let tx_id = TxHash::from([1; 32]);

                let finality_block_response = GetBlockByNumberResponse {
                    number: U64::from(100),
                    hash: H256::from([0xaa; 32]),
                };
                let tx_response = GetTransactionReceiptResponse {
                    transaction_hash: H256::from([1; 32]),
                    block_hash: H256::from([2; 32]),
                    block_number: U64::from(90),
                    status: U64::one(),
                    logs: vec![test_log()],
                };
                let canonical_block_response = GetBlockByNumberResponse {
                    number: tx_response.block_number,
                    hash: tx_response.block_hash,
                };

                let mock_client = SequentialResponseMockClientBuilder::new()
                    .with_response(&tx_response)
                    .with_response(&finality_block_response)
                    .with_response(&canonical_block_response)
                    .build();
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
                    Ok(Verdict::LogIndexOutOfBounds)
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
                    block_number: U64::from(90),
                    address: H160([6; 20]),
                    data: "first_log".to_string(),
                    topics: vec![H256([7; 32])],
                };
                let log_at_index_21 = Log {
                    removed: false,
                    log_index: U64::from(21),
                    transaction_index: U64([20]),
                    transaction_hash: H256([3; 32]),
                    block_hash: H256([4; 32]),
                    block_number: U64::from(90),
                    address: H160([60; 20]),
                    data: "second_log".to_string(),
                    topics: vec![H256([70; 32])],
                };
                let expected_log = log_at_index_21.clone();

                let finality_block_response = GetBlockByNumberResponse {
                    number: U64::from(100),
                    hash: H256::from([0xaa; 32]),
                };
                let tx_response = GetTransactionReceiptResponse {
                    transaction_hash: H256::from([3; 32]),
                    block_hash: H256::from([4; 32]),
                    block_number: U64::from(90),
                    status: U64::one(),
                    logs: vec![log_at_index_20, log_at_index_21],
                };
                let canonical_block_response = GetBlockByNumberResponse {
                    number: tx_response.block_number,
                    hash: tx_response.block_hash,
                };

                let mock_client = SequentialResponseMockClientBuilder::new()
                    .with_response(&tx_response)
                    .with_response(&finality_block_response)
                    .with_response(&canonical_block_response)
                    .build();
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
                assert_eq!(Verdict::Extracted(expected_extractions), extracted_values);
            }

            #[tokio::test]
            async fn extract_rejects_a_canonical_lookup_answering_a_different_height() {
                // given: the canonical block lookup answers with a block below the receipt's
                // height, the provider's own fault rather than a statement about the chain.
                let tx_id = TxHash::from([1; 32]);

                let finality_block_response = GetBlockByNumberResponse {
                    number: U64::from(100),
                    hash: H256::from([0xaa; 32]),
                };
                let tx_response = GetTransactionReceiptResponse {
                    transaction_hash: H256::from([1; 32]),
                    block_hash: H256::from([0xbb; 32]),
                    block_number: U64::from(90),
                    status: U64::one(),
                    logs: vec![test_log()],
                };
                let canonical_block_response = GetBlockByNumberResponse {
                    number: U64::from(89),
                    hash: tx_response.block_hash,
                };

                let mock_client = SequentialResponseMockClientBuilder::new()
                    .with_response(&tx_response)
                    .with_response(&finality_block_response)
                    .with_response(&canonical_block_response)
                    .build();
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
                    Err(ForeignChainInspectionError::MalformedRpcResponse(_))
                );
            }

            #[tokio::test]
            async fn extract_returns_the_non_canonical_verdict_when_the_receipt_block_is_not_canonical() {
                // given: the receipt is past the finality head (so the number-only check passes)
                // but its block hash differs from the canonical block hash at that height,
                // simulating an RPC that served a side-block receipt for a finalized height.
                let tx_id = TxHash::from([1; 32]);

                let finality_block_response = GetBlockByNumberResponse {
                    number: U64::from(100),
                    hash: H256::from([0xaa; 32]),
                };
                let tx_response = GetTransactionReceiptResponse {
                    transaction_hash: H256::from([1; 32]),
                    block_hash: H256::from([0xbb; 32]),
                    block_number: U64::from(90),
                    status: U64::one(),
                    logs: vec![test_log()],
                };
                let canonical_block_response = GetBlockByNumberResponse {
                    number: tx_response.block_number,
                    hash: H256::from([0xcc; 32]),
                };

                let mock_client = SequentialResponseMockClientBuilder::new()
                    .with_response(&tx_response)
                    .with_response(&finality_block_response)
                    .with_response(&canonical_block_response)
                    .build();
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
                    Ok(Verdict::NonCanonicalBlock {
                        block_number,
                        receipt_hash,
                        canonical_hash,
                    }) if block_number == 90
                        && receipt_hash == foreign_chain_inspector::HexBytes(vec![0xbb; 32])
                        && canonical_hash == foreign_chain_inspector::HexBytes(vec![0xcc; 32])
                );
            }

            #[tokio::test]
            async fn extract__should_reject_receipt_whose_transaction_hash_differs_from_request()
            {
                // Given
                let requested_tx_bytes: [u8; 32] = [1; 32];
                let returned_tx_bytes: [u8; 32] = [0xdd; 32];
                let tx_id = TxHash::from(requested_tx_bytes);

                let tx_response = GetTransactionReceiptResponse {
                    transaction_hash: H256(returned_tx_bytes),
                    block_hash: H256::from([2; 32]),
                    block_number: U64::from(90),
                    status: U64::one(),
                    logs: vec![test_log()],
                };

                // The receipt-hash check fires before the finality lookup, so only one
                // RPC call is exercised.
                let mock_client = SequentialResponseMockClientBuilder::new()
                    .with_response(&tx_response)
                    .build();
                let inspector = Inspector::new(mock_client);

                // When
                let response = inspector
                    .extract(
                        tx_id,
                        EthereumFinality::Finalized,
                        vec![EvmExtractor::BlockHash],
                    )
                    .await;

                // Then
                assert_matches!(
                    response,
                    Err(ForeignChainInspectionError::InconsistentRpcResponse {
                        requested_hash,
                        returned_hash,
                    }) if requested_hash
                        == foreign_chain_inspector::HexBytes(requested_tx_bytes.to_vec())
                        && returned_hash
                            == foreign_chain_inspector::HexBytes(returned_tx_bytes.to_vec())
                );
            }

            #[rstest]
            #[case::transaction_hash(Log {
                transaction_hash: H256([0xdd; 32]),
                ..test_log()
            })]
            #[case::block_hash(Log {
                block_hash: H256([0xdd; 32]),
                ..test_log()
            })]
            #[case::block_number(Log {
                block_number: U64::from(91),
                ..test_log()
            })]
            #[tokio::test]
            async fn extract__should_reject_log_not_bound_to_receipt(#[case] unbound_log: Log) {
                // Given
                let tx_id_bytes: [u8; 32] = [3; 32];
                let tx_id = TxHash::from(tx_id_bytes);
                let expected_log = unbound_log.clone();
                let bound_log = test_log();

                // When
                let response = extract_log_from_receipt_with(tx_id, unbound_log).await;

                // Then
                assert_matches!(
                    response,
                    Err(ForeignChainInspectionError::LogNotBoundToReceipt {
                        log_index,
                        log_transaction_hash,
                        log_block_hash,
                        log_block_number,
                        receipt_transaction_hash,
                        receipt_block_hash,
                        receipt_block_number,
                    }) if log_index == expected_log.log_index.as_u64()
                        && log_transaction_hash == expected_log.transaction_hash.into()
                        && log_block_hash == expected_log.block_hash.into()
                        && log_block_number == expected_log.block_number.as_u64()
                        && receipt_transaction_hash
                            == foreign_chain_inspector::HexBytes(tx_id_bytes.to_vec())
                        && receipt_block_hash == bound_log.block_hash.into()
                        && receipt_block_number == bound_log.block_number.as_u64()
                );
            }

            /// Runs `extract` selecting `log` by its own `log_index` from a finalized,
            /// canonical receipt for `tx_id` whose block fields match [`test_log`]'s.
            async fn extract_log_from_receipt_with(
                tx_id: TxHash,
                log: Log,
            ) -> Result<Verdict<ExtractedValue>, ForeignChainInspectionError> {
                let bound_log = test_log();
                let target_log_index = log.log_index.as_u64();
                let finality_block_response = GetBlockByNumberResponse {
                    number: U64::from(100),
                    hash: H256::from([0xaa; 32]),
                };
                let tx_response = GetTransactionReceiptResponse {
                    transaction_hash: H256(tx_id.clone().into()),
                    block_hash: bound_log.block_hash,
                    block_number: bound_log.block_number,
                    status: U64::one(),
                    logs: vec![log],
                };
                let canonical_block_response = GetBlockByNumberResponse {
                    number: tx_response.block_number,
                    hash: tx_response.block_hash,
                };

                let mock_client = SequentialResponseMockClientBuilder::new()
                    .with_response(&tx_response)
                    .with_response(&finality_block_response)
                    .with_response(&canonical_block_response)
                    .build();
                let inspector = Inspector::new(mock_client);

                inspector
                    .extract(
                        tx_id,
                        EthereumFinality::Finalized,
                        vec![EvmExtractor::Log {
                            log_index: target_log_index,
                        }],
                    )
                    .await
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
evm_inspector_tests!(
    foreign_chain_inspector::hyperevm::inspector::HyperEvm,
    hyperevm
);
evm_inspector_tests!(
    foreign_chain_inspector::polygon::inspector::Polygon,
    polygon
);
evm_inspector_tests!(
    foreign_chain_inspector::avalanche::inspector::Avalanche,
    avalanche
);
evm_inspector_tests!(foreign_chain_inspector::adi::inspector::Adi, adi);
evm_inspector_tests!(
    foreign_chain_inspector::ethereum::inspector::Ethereum,
    ethereum
);

// Base mainnet, standing in for every EVM chain: the fingerprint call has no chain-specific parts.
const CHAIN_ID_8453: &str = "0x2105";
const PADDED_CHAIN_ID_8453: &str = "0x002105";

#[tokio::test]
async fn network_fingerprint__should_return_the_chain_id_in_decimal() {
    // Given
    let inspector =
        EvmInspector::<_, Base>::new(mock_client_from_fixed_response(PADDED_CHAIN_ID_8453));

    // When
    let fingerprint = inspector
        .network_fingerprint()
        .await
        .expect("network_fingerprint should succeed");

    // Then
    assert_eq!(fingerprint.to_string(), "8453");
}

#[tokio::test]
async fn network_fingerprint__should_ask_the_provider_for_its_chain_id() {
    // Given
    let server = MockServer::start_async().await;
    let mock = server
        .mock_async(|when, then| {
            when.method(POST).body_includes(r#""method":"eth_chainId""#);
            then.status(200).json_body(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 0,
                "result": CHAIN_ID_8453,
            }));
        })
        .await;
    let client = build_http_client(server.url("/"), RpcAuthentication::KeyInUrl).unwrap();
    let inspector = EvmInspector::<_, Base>::new(client);

    // When
    let fingerprint = inspector
        .network_fingerprint()
        .await
        .expect("network_fingerprint should succeed");

    // Then
    mock.assert_async().await;
    assert_eq!(fingerprint.to_string(), "8453");
}
