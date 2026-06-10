use crate::aptos::{AptosExtractedValue, AptosTransactionHash};
use crate::{ForeignChainInspectionError, ForeignChainInspector, HexBytes};
use foreign_chain_rpc_interfaces::aptos::{
    AptosRpcClient, AptosRpcError, TransactionResponse, normalize_event_data,
};
use near_mpc_contract_interface::types::{AptosAddress, AptosEvent};

#[derive(Clone)]
pub struct AptosInspector<Client> {
    client: Client,
}

impl<Client> AptosInspector<Client> {
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AptosFinality {
    Committed,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AptosExtractor {
    Event { event_index: usize },
}

impl<Client> ForeignChainInspector for AptosInspector<Client>
where
    Client: AptosRpcClient + Send + Sync,
{
    type TransactionId = AptosTransactionHash;
    type Finality = AptosFinality;
    type Extractor = AptosExtractor;
    type ExtractedValue = AptosExtractedValue;

    async fn extract(
        &self,
        tx_id: AptosTransactionHash,
        finality: AptosFinality,
        extractors: Vec<AptosExtractor>,
    ) -> Result<Vec<AptosExtractedValue>, ForeignChainInspectionError> {
        let tx_hash_hex = format!("0x{}", hex::encode(*tx_id));

        let tx = self
            .client
            .get_transaction_by_hash(&tx_hash_hex)
            .await
            .map_err(|e| match e {
                // 404 = definitively absent → a non-transient verdict, not a retry.
                AptosRpcError::ApiError { status: 404, .. } => {
                    ForeignChainInspectionError::TransactionNotFound
                }
                other => ForeignChainInspectionError::RpcRequestFailed(other.to_string()),
            })?;

        ensure_hash_matches(&tx_hash_hex, &tx.hash)?;

        if tx.transaction_type == "pending_transaction" {
            return Err(ForeignChainInspectionError::NotFinalized);
        }

        match finality {
            AptosFinality::Committed => {
                // A committed transaction always carries an execution result.
                let Some(success) = tx.success else {
                    return Err(ForeignChainInspectionError::RpcRequestFailed(
                        "committed transaction is missing the success field".to_string(),
                    ));
                };
                if !success {
                    return Err(ForeignChainInspectionError::TransactionFailed);
                }
            }
        }

        let extracted_values = extractors
            .iter()
            .map(|extractor| extractor.extract_value(&tx))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(extracted_values)
    }
}

/// Rejects a backend that returned a different transaction than queried (case-insensitive).
fn ensure_hash_matches(requested: &str, returned: &str) -> Result<(), ForeignChainInspectionError> {
    if requested.to_lowercase() != returned.to_lowercase() {
        return Err(ForeignChainInspectionError::InconsistentRpcResponse {
            requested_hash: hex_str_to_bytes(requested),
            returned_hash: hex_str_to_bytes(returned),
        });
    }
    Ok(())
}

/// Best-effort hex decode for error messages; empty on non-hex input.
fn hex_str_to_bytes(s: &str) -> HexBytes {
    HexBytes(hex::decode(s.strip_prefix("0x").unwrap_or(s)).unwrap_or_default())
}

impl AptosExtractor {
    fn extract_value(
        &self,
        tx: &TransactionResponse,
    ) -> Result<AptosExtractedValue, ForeignChainInspectionError> {
        match self {
            AptosExtractor::Event { event_index } => {
                let event = tx
                    .events
                    .get(*event_index)
                    .ok_or(ForeignChainInspectionError::LogIndexOutOfBounds)?;

                // An unparseable field → transient, so one malformed provider drops from the
                // quorum rather than blocking signing.
                let account_address =
                    parse_aptos_address(&event.guid.account_address).map_err(|reason| {
                        ForeignChainInspectionError::RpcRequestFailed(format!(
                            "failed to parse event account_address: {reason}"
                        ))
                    })?;

                let sequence_number: u64 =
                    event
                        .sequence_number
                        .parse()
                        .map_err(|e: std::num::ParseIntError| {
                            ForeignChainInspectionError::RpcRequestFailed(format!(
                                "failed to parse event sequence_number: {e}"
                            ))
                        })?;

                // Verbatim: providers are assumed to agree on the struct-tag's address form
                // (fullnodes return canonical short form). Canonicalization deferred to BCS.
                let type_tag = event.event_type.clone();
                let data = normalize_event_data(&event.data);

                Ok(AptosExtractedValue::Event(AptosEvent {
                    account_address,
                    sequence_number,
                    type_tag,
                    data,
                }))
            }
        }
    }
}

/// Parse an Aptos address string (0x-prefixed hex, possibly short) into AptosAddress.
/// Short addresses like "0x1" are zero-padded to 32 bytes.
fn parse_aptos_address(s: &str) -> Result<AptosAddress, String> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    if hex_str.is_empty() {
        return Err(format!("empty Aptos address: {s:?}"));
    }
    if hex_str.len() > 64 {
        return Err(format!("address hex string too long: {s}"));
    }
    let padded = format!("{hex_str:0>64}");
    let bytes = hex::decode(&padded).map_err(|e| format!("invalid hex in address '{s}': {e}"))?;
    let array: [u8; 32] = bytes.try_into().expect("padded to exactly 32 bytes");
    Ok(AptosAddress(array))
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use foreign_chain_rpc_interfaces::aptos::{
        AptosEventResponse, AptosRpcError, EventGuid, TransactionResponse,
    };

    struct MockAptosClient {
        response: Result<TransactionResponse, AptosRpcError>,
    }

    impl MockAptosClient {
        fn success(tx: TransactionResponse) -> Self {
            Self { response: Ok(tx) }
        }

        fn not_found() -> Self {
            Self {
                response: Err(AptosRpcError::ApiError {
                    status: 404,
                    body: "transaction not found".to_string(),
                }),
            }
        }

        fn server_error() -> Self {
            Self {
                response: Err(AptosRpcError::ApiError {
                    status: 500,
                    body: "internal server error".to_string(),
                }),
            }
        }
    }

    impl AptosRpcClient for MockAptosClient {
        fn get_transaction_by_hash(
            &self,
            _tx_hash_hex: &str,
        ) -> impl Future<Output = Result<TransactionResponse, AptosRpcError>> + Send {
            let r = match &self.response {
                Ok(tx) => Ok(tx.clone()),
                Err(AptosRpcError::ApiError { status, body }) => Err(AptosRpcError::ApiError {
                    status: *status,
                    body: body.clone(),
                }),
                Err(other) => Err(AptosRpcError::ApiError {
                    status: 500,
                    body: other.to_string(),
                }),
            };
            std::future::ready(r)
        }
    }

    fn sample_tx(hash: &str, success: bool) -> TransactionResponse {
        TransactionResponse {
            transaction_type: "user_transaction".to_string(),
            hash: hash.to_string(),
            success: Some(success),
            events: vec![AptosEventResponse {
                guid: EventGuid {
                    creation_number: "0".to_string(),
                    account_address: "0x0".to_string(),
                },
                sequence_number: "0".to_string(),
                event_type: "0xdeadbeef::bridge::InitTransfer".to_string(),
                data: serde_json::json!({ "amount": "100" }),
            }],
        }
    }

    /// A pending transaction: present but not yet committed, so it carries no execution result.
    fn pending_tx() -> TransactionResponse {
        TransactionResponse {
            transaction_type: "pending_transaction".to_string(),
            hash: HASH.to_string(),
            success: None,
            events: vec![],
        }
    }

    const HASH: &str = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

    fn tx_id_from_hex(hex_str: &str) -> AptosTransactionHash {
        let bytes = hex::decode(hex_str.strip_prefix("0x").unwrap()).unwrap();
        let array: [u8; 32] = bytes.try_into().unwrap();
        array.into()
    }

    #[tokio::test]
    async fn extract__should_return_event_when_transaction_is_successful() {
        // Given
        let tx = sample_tx(HASH, true);
        let inspector = AptosInspector::new(MockAptosClient::success(tx));
        let tx_id = tx_id_from_hex(HASH);

        // When
        let result = inspector
            .extract(
                tx_id,
                AptosFinality::Committed,
                vec![AptosExtractor::Event { event_index: 0 }],
            )
            .await;

        // Then
        let values = result.unwrap();
        assert_eq!(values.len(), 1);
        match &values[0] {
            AptosExtractedValue::Event(event) => {
                assert_eq!(event.type_tag, "0xdeadbeef::bridge::InitTransfer");
                assert_eq!(event.sequence_number, 0);
                assert_eq!(event.data, r#"{"amount":"100"}"#);
            }
        }
    }

    #[tokio::test]
    async fn extract__should_fail_when_transaction_failed() {
        // Given
        let tx = sample_tx(HASH, false);
        let inspector = AptosInspector::new(MockAptosClient::success(tx));
        let tx_id = tx_id_from_hex(HASH);

        // When
        let result = inspector
            .extract(tx_id, AptosFinality::Committed, vec![])
            .await;

        // Then
        assert_matches!(result, Err(ForeignChainInspectionError::TransactionFailed));
    }

    #[tokio::test]
    async fn extract__should_fail_when_event_index_out_of_bounds() {
        // Given
        let tx = sample_tx(HASH, true);
        let inspector = AptosInspector::new(MockAptosClient::success(tx));
        let tx_id = tx_id_from_hex(HASH);

        // When
        let result = inspector
            .extract(
                tx_id,
                AptosFinality::Committed,
                vec![AptosExtractor::Event { event_index: 99 }],
            )
            .await;

        // Then
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::LogIndexOutOfBounds)
        );
    }

    fn event_response(type_tag: &str, data: serde_json::Value) -> AptosEventResponse {
        AptosEventResponse {
            guid: EventGuid {
                creation_number: "0".to_string(),
                account_address: "0x0".to_string(),
            },
            sequence_number: "0".to_string(),
            event_type: type_tag.to_string(),
            data,
        }
    }

    #[tokio::test]
    async fn extract__should_extract_multiple_events_by_index() {
        // Given a committed tx with two events.
        let tx = TransactionResponse {
            transaction_type: "user_transaction".to_string(),
            hash: HASH.to_string(),
            success: Some(true),
            events: vec![
                event_response("0x1::bridge::A", serde_json::json!({ "n": "1" })),
                event_response("0x2::bridge::B", serde_json::json!({ "n": "2" })),
            ],
        };
        let inspector = AptosInspector::new(MockAptosClient::success(tx));
        let tx_id = tx_id_from_hex(HASH);

        // When — request both events out of order, exercising the extractor loop and indexing.
        let values = inspector
            .extract(
                tx_id,
                AptosFinality::Committed,
                vec![
                    AptosExtractor::Event { event_index: 1 },
                    AptosExtractor::Event { event_index: 0 },
                ],
            )
            .await
            .unwrap();

        // Then
        assert_eq!(values.len(), 2);
        match (&values[0], &values[1]) {
            (AptosExtractedValue::Event(first), AptosExtractedValue::Event(second)) => {
                assert_eq!(first.type_tag, "0x2::bridge::B");
                assert_eq!(second.type_tag, "0x1::bridge::A");
            }
        }
    }

    #[tokio::test]
    async fn extract__should_fail_when_committed_tx_has_no_events() {
        // Given a committed tx whose events array is empty.
        let tx = TransactionResponse {
            transaction_type: "user_transaction".to_string(),
            hash: HASH.to_string(),
            success: Some(true),
            events: vec![],
        };
        let inspector = AptosInspector::new(MockAptosClient::success(tx));
        let tx_id = tx_id_from_hex(HASH);

        // When
        let result = inspector
            .extract(
                tx_id,
                AptosFinality::Committed,
                vec![AptosExtractor::Event { event_index: 0 }],
            )
            .await;

        // Then
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::LogIndexOutOfBounds)
        );
    }

    #[tokio::test]
    async fn extract__should_return_not_finalized_for_pending_transaction() {
        // Given — the tx exists but is still in the mempool (no execution result yet).
        let inspector = AptosInspector::new(MockAptosClient::success(pending_tx()));
        let tx_id = tx_id_from_hex(HASH);

        // When
        let result = inspector
            .extract(tx_id, AptosFinality::Committed, vec![])
            .await;

        // Then — transient, so the fan-out keeps retrying until it commits.
        assert_matches!(result, Err(ForeignChainInspectionError::NotFinalized));
        assert!(result.unwrap_err().is_transient());
    }

    #[tokio::test]
    async fn extract__should_accept_non_user_committed_kinds() {
        // Given — a committed system transaction (block metadata) with an event. The inspector
        // attests any committed kind; event-type policy belongs to the payload's consumer.
        let tx = TransactionResponse {
            transaction_type: "block_metadata_transaction".to_string(),
            hash: HASH.to_string(),
            success: Some(true),
            events: vec![event_response(
                "0x1::block::NewBlockEvent",
                serde_json::json!({ "epoch": "7510" }),
            )],
        };
        let inspector = AptosInspector::new(MockAptosClient::success(tx));
        let tx_id = tx_id_from_hex(HASH);

        // When
        let values = inspector
            .extract(
                tx_id,
                AptosFinality::Committed,
                vec![AptosExtractor::Event { event_index: 0 }],
            )
            .await
            .unwrap();

        // Then
        match &values[0] {
            AptosExtractedValue::Event(event) => {
                assert_eq!(event.type_tag, "0x1::block::NewBlockEvent");
            }
        }
    }

    #[test]
    fn parse_aptos_address__should_zero_pad_short_address() {
        // Given
        let short = "0x1";

        // When
        let addr = parse_aptos_address(short).unwrap();

        // Then
        let mut expected = [0u8; 32];
        expected[31] = 0x01;
        assert_eq!(addr.0, expected);
    }

    #[test]
    fn parse_aptos_address__should_accept_full_length_address() {
        // Given
        let full = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

        // When
        let addr = parse_aptos_address(full).unwrap();

        // Then
        assert_eq!(
            addr.0.as_slice(),
            hex::decode("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn parse_aptos_address__should_reject_empty_address() {
        // `""` and `"0x"` would otherwise be zero-padded into the all-zeros address.
        parse_aptos_address("").unwrap_err();
        parse_aptos_address("0x").unwrap_err();
    }

    #[test]
    fn parse_aptos_address__should_reject_overlong_address() {
        let too_long = format!("0x{}", "a".repeat(65));
        parse_aptos_address(&too_long).unwrap_err();
    }

    #[tokio::test]
    async fn extract__should_return_transaction_not_found_on_404() {
        // Given
        let inspector = AptosInspector::new(MockAptosClient::not_found());
        let tx_id = tx_id_from_hex(HASH);

        // When
        let result = inspector
            .extract(tx_id, AptosFinality::Committed, vec![])
            .await;

        // Then — non-transient so the node does not retry indefinitely
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::TransactionNotFound)
        );
        assert!(!result.unwrap_err().is_transient());
    }

    #[tokio::test]
    async fn extract__should_return_transient_error_on_server_error() {
        // Given
        let inspector = AptosInspector::new(MockAptosClient::server_error());
        let tx_id = tx_id_from_hex(HASH);

        // When
        let result = inspector
            .extract(tx_id, AptosFinality::Committed, vec![])
            .await;

        // Then — transient so the node retries
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::RpcRequestFailed(_))
        );
        assert!(result.unwrap_err().is_transient());
    }

    #[test]
    fn ensure_hash_matches__should_accept_same_hash_different_case() {
        // Given / When / Then
        ensure_hash_matches("0xABCD", "0xabcd").unwrap();
    }

    #[test]
    fn ensure_hash_matches__should_reject_different_hashes() {
        // Given / When / Then
        assert_matches!(
            ensure_hash_matches("0xabcd", "0xef01"),
            Err(ForeignChainInspectionError::InconsistentRpcResponse { .. })
        );
    }
}
