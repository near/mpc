use crate::sui::{SuiExtractedValue, SuiTransactionDigest};
use crate::{
    AbsenceMeaning, ClassifyRpcOutcome, ForeignChainInspectionError, ForeignChainInspector,
    HasAbsenceMeaning, HexBytes, NetworkFingerprint, NetworkFingerprintInspector,
};
use foreign_chain_rpc_interfaces::sui::proto::{
    ExecutedTransaction, GetServiceInfoResponse, GetTransactionResponse,
};
use foreign_chain_rpc_interfaces::sui::{Code, Status, SuiRpcClient};
use near_mpc_contract_interface::types::{SuiAddress, SuiEvent};
use std::str::FromStr;

#[derive(Clone)]
pub struct SuiInspector<Client> {
    client: Client,
}

impl<Client> SuiInspector<Client> {
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum SuiFinality {
    /// Included in a committee-certified checkpoint. Sui has no reorgs, so this is final.
    Checkpointed,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SuiExtractor {
    Event { event_index: usize },
}

impl<Client> NetworkFingerprintInspector for SuiInspector<Client>
where
    Client: SuiRpcClient,
{
    async fn network_fingerprint(&self) -> Result<NetworkFingerprint, ForeignChainInspectionError> {
        let service_info = self.client.get_service_info().await.classified()?;
        let Some(chain_id) = service_info.chain_id else {
            return Err(ForeignChainInspectionError::MalformedRpcResponse(
                "service info is missing the chain id".to_string(),
            ));
        };
        Ok(Self::canonical_fingerprint(&chain_id))
    }

    /// Unlike inspectors for other chains, we do not need to normalize the input string here.
    /// Base58 is case sensitive and does not permit prefix or padding.
    fn canonical_fingerprint(fingerprint: &str) -> NetworkFingerprint {
        NetworkFingerprint::new(fingerprint)
    }
}

/// The gRPC [`Event`](foreign_chain_rpc_interfaces::sui::proto::Event) carries no per-event
/// sequence number or transaction digest, so the event array order is the certified order as
/// served. The type name embedded in the event's BCS message is cross-checked against the
/// event type.
impl<Client> ForeignChainInspector for SuiInspector<Client>
where
    Client: SuiRpcClient,
{
    type TransactionId = SuiTransactionDigest;
    type Finality = SuiFinality;
    type Extractor = SuiExtractor;
    type ExtractedValue = SuiExtractedValue;

    async fn extract(
        &self,
        tx_id: SuiTransactionDigest,
        finality: SuiFinality,
        extractors: Vec<SuiExtractor>,
    ) -> Result<Vec<SuiExtractedValue>, ForeignChainInspectionError> {
        let digest = sui_sdk_types::Digest::new(*tx_id).to_base58();

        let response = self.client.get_transaction(&digest).await.classified()?;
        let Some(tx) = response.transaction else {
            return Err(ForeignChainInspectionError::MalformedRpcResponse(
                "response is missing the transaction".to_string(),
            ));
        };

        let Some(returned_digest) = &tx.digest else {
            return Err(ForeignChainInspectionError::MalformedRpcResponse(
                "transaction is missing the requested digest".to_string(),
            ));
        };
        ensure_digest_matches(&tx_id, returned_digest)?;

        match finality {
            SuiFinality::Checkpointed => {
                // The server sets `checkpoint` only once the transaction is included in a
                // certified checkpoint; until then the verdict is "not final yet", not an error.
                if tx.checkpoint.is_none() {
                    return Err(ForeignChainInspectionError::NotFinalized);
                }
            }
        }

        let success = tx
            .effects
            .as_ref()
            .and_then(|effects| effects.status.as_ref())
            .and_then(|status| status.success)
            .ok_or_else(|| {
                ForeignChainInspectionError::MalformedRpcResponse(
                    "transaction is missing the requested execution status".to_string(),
                )
            })?;
        if !success {
            return Err(ForeignChainInspectionError::TransactionFailed);
        }

        let extracted_values = extractors
            .iter()
            .map(|extractor| extractor.extract_value(&tx))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(extracted_values)
    }
}

impl HasAbsenceMeaning for GetTransactionResponse {
    const ABSENCE: AbsenceMeaning = AbsenceMeaning::TransactionIsAbsent;
}

impl HasAbsenceMeaning for GetServiceInfoResponse {
    const ABSENCE: AbsenceMeaning = AbsenceMeaning::ApiIsNotServed;
}

impl<T: HasAbsenceMeaning> ClassifyRpcOutcome for Result<T, Status> {
    type Response = T;

    fn classified(self) -> Result<T, ForeignChainInspectionError> {
        let status = match self {
            Ok(response) => return Ok(response),
            Err(status) => status,
        };

        let message = status.to_string();
        Err(match status.code() {
            Code::NotFound => match T::ABSENCE {
                AbsenceMeaning::TransactionIsAbsent => {
                    ForeignChainInspectionError::TransactionNotFound
                }
                AbsenceMeaning::ApiIsNotServed => {
                    ForeignChainInspectionError::RpcRequestRejected(message)
                }
            },
            Code::DeadlineExceeded => ForeignChainInspectionError::Timeout,
            Code::Unavailable
            | Code::ResourceExhausted
            | Code::Internal
            | Code::Unknown
            | Code::Cancelled
            | Code::Aborted => ForeignChainInspectionError::RpcRequestFailed(message),
            _ => ForeignChainInspectionError::RpcRequestRejected(message),
        })
    }
}

/// Rejects a backend that returned a different transaction than queried. A digest that is not
/// valid base58 for 32 bytes is a malformed response; a well-formed but different digest is a
/// hard inconsistency. [`Digest::from_base58`](sui_sdk_types::Digest::from_base58) decodes into a fixed 32-byte buffer, so an
/// oversized string is rejected without a superlinear decode.
fn ensure_digest_matches(
    requested: &[u8; 32],
    returned: &str,
) -> Result<(), ForeignChainInspectionError> {
    let returned = sui_sdk_types::Digest::from_base58(returned).map_err(|e| {
        ForeignChainInspectionError::MalformedRpcResponse(format!(
            "invalid transaction digest in response: {e}"
        ))
    })?;
    if returned != sui_sdk_types::Digest::new(*requested) {
        return Err(ForeignChainInspectionError::InconsistentRpcResponse {
            requested_hash: HexBytes(requested.to_vec()),
            returned_hash: HexBytes(returned.into_inner().to_vec()),
        });
    }
    Ok(())
}

impl SuiExtractor {
    fn extract_value(
        &self,
        tx: &ExecutedTransaction,
    ) -> Result<SuiExtractedValue, ForeignChainInspectionError> {
        match self {
            SuiExtractor::Event { event_index } => {
                let events = tx
                    .events
                    .as_ref()
                    .map(|events| events.events.as_slice())
                    .unwrap_or_default();
                let event = events
                    .get(*event_index)
                    .ok_or(ForeignChainInspectionError::LogIndexOutOfBounds)?;

                let package_id = event
                    .package_id
                    .as_deref()
                    .ok_or_else(|| malformed_event_field("package_id"))
                    .and_then(|s| {
                        parse_sui_address(s).map_err(|reason| {
                            ForeignChainInspectionError::MalformedRpcResponse(format!(
                                "failed to parse event package_id: {reason}"
                            ))
                        })
                    })?;
                let sender = event
                    .sender
                    .as_deref()
                    .ok_or_else(|| malformed_event_field("sender"))
                    .and_then(|s| {
                        parse_sui_address(s).map_err(|reason| {
                            ForeignChainInspectionError::MalformedRpcResponse(format!(
                                "failed to parse event sender: {reason}"
                            ))
                        })
                    })?;
                let transaction_module = event
                    .module
                    .clone()
                    .ok_or_else(|| malformed_event_field("module"))?;
                let type_tag = event
                    .event_type
                    .as_deref()
                    .ok_or_else(|| malformed_event_field("event_type"))
                    .and_then(normalize_type_tag)?;
                let contents = event
                    .contents
                    .as_ref()
                    .ok_or_else(|| malformed_event_field("bcs contents"))?;
                // When present, the type name shipped alongside the BCS bytes must agree with
                // the event type we sign; a mismatch means the payload and its claimed type
                // come apart. Both sides are normalized so a provider that renders the two
                // fields with different address forms is not rejected spuriously.
                if let Some(name) = contents.name.as_deref() {
                    let normalized_name = normalize_type_tag(name)?;
                    if normalized_name != type_tag {
                        return Err(ForeignChainInspectionError::MalformedRpcResponse(format!(
                            "event contents type {normalized_name:?} does not match the event type {type_tag:?}"
                        )));
                    }
                }
                let bcs = contents
                    .value
                    .as_ref()
                    .map(|value| value.to_vec())
                    .ok_or_else(|| malformed_event_field("bcs contents value"))?;

                Ok(SuiExtractedValue::Event(SuiEvent {
                    package_id,
                    transaction_module,
                    sender,
                    type_tag,
                    bcs,
                }))
            }
        }
    }
}

fn malformed_event_field(field: &str) -> ForeignChainInspectionError {
    ForeignChainInspectionError::MalformedRpcResponse(format!("event is missing its {field}"))
}

/// Renders a Move type tag in Sui's canonical form — addresses as `0x` + 64 lowercase hex —
/// so a provider that shortens framework addresses (`0x2::sui::SUI`) and one that returns the
/// long form converge to the same signed payload. Parsing also rejects a malformed type tag.
fn normalize_type_tag(tag: &str) -> Result<String, ForeignChainInspectionError> {
    sui_sdk_types::TypeTag::from_str(tag)
        .map(|type_tag| type_tag.to_string())
        .map_err(|e| {
            ForeignChainInspectionError::MalformedRpcResponse(format!(
                "invalid Move type tag {tag:?}: {e}"
            ))
        })
}

/// Parse a Sui address string (0x-prefixed hex, short forms zero-padded) into [`SuiAddress`].
fn parse_sui_address(s: &str) -> Result<SuiAddress, String> {
    sui_sdk_types::Address::from_str(s)
        .map(|address| SuiAddress(address.into()))
        .map_err(|e| format!("invalid Sui address {s:?}: {e}"))
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use rstest::rstest;

    fn read_as_transaction(status: Status) -> ForeignChainInspectionError {
        Result::<GetTransactionResponse, _>::Err(status)
            .classified()
            .unwrap_err()
    }

    #[test]
    fn classified__should_read_an_absent_transaction_as_the_chains_verdict() {
        // Given — the status a node returns for an unknown or pruned digest.
        let status =
            Status::not_found("Transaction 88XKXHJRmGzkfwJa8PhoeDkqt4kxz8AEsB1UTzAbtd29 not found");

        // When
        let classified = read_as_transaction(status);

        // Then — a substantive (non-transient) verdict.
        assert_matches!(classified, ForeignChainInspectionError::TransactionNotFound);
        assert!(!classified.is_transient());
    }

    #[test]
    fn classified__should_read_an_absent_service_as_a_refusal() {
        // Given
        let answered: Result<GetServiceInfoResponse, _> = Err(Status::not_found("no such service"));

        // When
        let classified = answered.classified().unwrap_err();

        // Then
        assert_matches!(
            classified,
            ForeignChainInspectionError::RpcRequestRejected(_)
        );
        assert!(!classified.is_transient());
    }

    #[rstest]
    #[case::deadline_exceeded(Code::DeadlineExceeded)]
    #[case::unavailable(Code::Unavailable)]
    #[case::invalid_argument(Code::InvalidArgument)]
    #[case::unauthenticated(Code::Unauthenticated)]
    fn classified__should_vary_by_resource_only_for_not_found(#[case] code: Code) {
        // Given
        let status = Status::new(code, "same code, either resource");

        // When
        let from_transaction = read_as_transaction(status.clone());
        let from_service_info = Result::<GetServiceInfoResponse, _>::Err(status)
            .classified()
            .unwrap_err();

        // Then
        assert_eq!(
            std::mem::discriminant(&from_transaction),
            std::mem::discriminant(&from_service_info)
        );
    }

    #[test]
    fn classified__should_name_a_deadline_exceeded_as_a_timeout() {
        // Given / When
        let classified = read_as_transaction(Status::new(Code::DeadlineExceeded, "too slow"));

        // Then
        assert_matches!(classified, ForeignChainInspectionError::Timeout);
        assert!(classified.is_transient());
    }

    #[rstest]
    #[case::unavailable(Code::Unavailable)]
    #[case::resource_exhausted(Code::ResourceExhausted)]
    #[case::internal(Code::Internal)]
    #[case::unknown(Code::Unknown)]
    fn classified__should_keep_provider_hiccups_transient(#[case] code: Code) {
        // Given / When
        let classified = read_as_transaction(Status::new(code, "provider hiccup"));

        // Then — the provider is dropped from the quorum instead of blocking it.
        assert_matches!(classified, ForeignChainInspectionError::RpcRequestFailed(_));
        assert!(classified.is_transient());
    }

    #[rstest]
    #[case::invalid_argument(Code::InvalidArgument)]
    #[case::unauthenticated(Code::Unauthenticated)]
    #[case::permission_denied(Code::PermissionDenied)]
    #[case::unimplemented(Code::Unimplemented)]
    fn classified__should_reject_deterministic_errors(#[case] code: Code) {
        // Given / When
        let classified = read_as_transaction(Status::new(code, "deterministic rejection"));

        // Then — non-transient: retrying cannot change it, and the fan-out must not
        // validate on the remaining providers alone.
        assert_matches!(
            classified,
            ForeignChainInspectionError::RpcRequestRejected(_)
        );
        assert!(!classified.is_transient());
    }

    #[test]
    fn ensure_digest_matches__should_accept_matching_digest() {
        // Given
        let digest = [0xab; 32];
        let encoded = bs58::encode(digest).into_string();

        // When / Then
        ensure_digest_matches(&digest, &encoded).unwrap();
    }

    #[test]
    fn ensure_digest_matches__should_reject_different_digest() {
        // Given
        let encoded_other = bs58::encode([0xcd; 32]).into_string();

        // When / Then
        assert_matches!(
            ensure_digest_matches(&[0xab; 32], &encoded_other),
            Err(ForeignChainInspectionError::InconsistentRpcResponse { .. })
        );
    }

    #[test]
    fn ensure_digest_matches__should_reject_non_base58_digest_as_malformed_response() {
        // Given / When
        let result = ensure_digest_matches(&[0xab; 32], "not-base58-0OIl");

        // Then — a malformed field, not a digest mismatch.
        assert_matches!(
            result,
            Err(ForeignChainInspectionError::MalformedRpcResponse(_))
        );
    }

    #[test]
    fn ensure_digest_matches__should_reject_oversized_digest_without_decoding() {
        // Given — a base58 string far longer than any 32-byte digest. Decoding it with `bs58`
        // is superlinear, so it must be rejected on length before the decode runs.
        let oversized = "1".repeat(1_000_000);

        // When / Then
        assert_matches!(
            ensure_digest_matches(&[0xab; 32], &oversized),
            Err(ForeignChainInspectionError::MalformedRpcResponse(_))
        );
    }

    #[test]
    fn ensure_digest_matches__should_reject_shorter_digest_as_inconsistent() {
        // Given — a base58 string that decodes to 31 bytes; `Digest::from_base58` zero-pads it
        // into a valid 32-byte digest, which then simply differs from the requested one.
        let short = bs58::encode([0xab; 31]).into_string();

        // When / Then
        assert_matches!(
            ensure_digest_matches(&[0xab; 32], &short),
            Err(ForeignChainInspectionError::InconsistentRpcResponse { .. })
        );
    }

    #[rstest]
    #[case::short_framework_address_is_padded(
        "0x2::sui::SUI",
        &format!("0x{}2::sui::SUI", "0".repeat(63))
    )]
    #[case::long_form_is_untouched(
        &format!("0x{}2::sui::SUI", "0".repeat(63)),
        &format!("0x{}2::sui::SUI", "0".repeat(63))
    )]
    #[case::uppercase_is_lowered(
        "0xAB::m::S",
        &format!("0x{}ab::m::S", "0".repeat(62))
    )]
    #[case::nested_generics(
        "0x2::coin::Coin<0x3::lp::LP<0xa::x::Y, u64>>",
        &format!(
            "0x{z62}02::coin::Coin<0x{z62}03::lp::LP<0x{z62}0a::x::Y, u64>>",
            z62 = "0".repeat(62)
        )
    )]
    #[case::hex_inside_identifier_is_untouched(
        "0x1::m0x01::S",
        &format!("0x{}1::m0x01::S", "0".repeat(63))
    )]
    fn normalize_type_tag__should_canonicalize_addresses(
        #[case] input: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(normalize_type_tag(input).unwrap(), expected);
    }

    #[test]
    fn parse_sui_address__should_zero_pad_short_address() {
        // Given
        let short = "0x2";

        // When
        let addr = parse_sui_address(short).unwrap();

        // Then
        let mut expected = [0u8; 32];
        expected[31] = 0x02;
        assert_eq!(addr.0, expected);
    }

    #[test]
    fn parse_sui_address__should_accept_full_length_address() {
        // Given
        let full = "0x55300367a2d40813727ccac4ecee977a39fb9cdb46f2e6b2c354b9798f5de2c0";

        // When
        let addr = parse_sui_address(full).unwrap();

        // Then
        assert_eq!(
            addr.0.as_slice(),
            hex::decode("55300367a2d40813727ccac4ecee977a39fb9cdb46f2e6b2c354b9798f5de2c0")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn parse_sui_address__should_reject_empty_address() {
        // An empty string has no hex digits to decode.
        parse_sui_address("").unwrap_err();
    }

    #[test]
    fn parse_sui_address__should_reject_overlong_address() {
        let too_long = format!("0x{}", "a".repeat(65));
        parse_sui_address(&too_long).unwrap_err();
    }
}
