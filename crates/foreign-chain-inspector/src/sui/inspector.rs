use crate::sui::{SuiExtractedValue, SuiTransactionDigest};
use crate::{ForeignChainInspectionError, ForeignChainInspector, HexBytes};
use foreign_chain_rpc_interfaces::sui::proto::ExecutedTransaction;
use foreign_chain_rpc_interfaces::sui::{Code, Status, SuiRpcClient};
use near_mpc_contract_interface::types::{SuiAddress, SuiEvent};
use std::borrow::Cow;

/// A 32-byte Sui digest is at most 44 base58 characters.
const DIGEST_MAX_BASE58_LEN: usize = 44;

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
        let digest = bs58::encode(*tx_id).into_string();

        let response = self
            .client
            .get_transaction(&digest)
            .await
            .map_err(classify_status)?;
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
                // The node sets `checkpoint` only once the transaction is included in a
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

/// gRPC status codes carry the verdict semantics directly: `NotFound` is the node's
/// deterministic answer for an unknown (or pruned) digest, other deterministic rejections
/// (bad request, auth, unimplemented method) must count as substantive verdicts in the
/// fan-out, and only genuine provider hiccups stay transient.
fn classify_status(status: Status) -> ForeignChainInspectionError {
    match status.code() {
        Code::NotFound => ForeignChainInspectionError::TransactionNotFound,
        Code::DeadlineExceeded
        | Code::Unavailable
        | Code::ResourceExhausted
        | Code::Internal
        | Code::Unknown
        | Code::Cancelled
        | Code::Aborted => ForeignChainInspectionError::RpcRequestFailed(status.to_string()),
        _ => ForeignChainInspectionError::RpcRequestRejected(status.to_string()),
    }
}

/// Rejects a backend that returned a different transaction than queried. A non-base58 or
/// wrong-length `returned` digest is a malformed response; a well-formed but different
/// digest is a hard inconsistency.
fn ensure_digest_matches(
    requested: &[u8; 32],
    returned: &str,
) -> Result<(), ForeignChainInspectionError> {
    if returned.len() > DIGEST_MAX_BASE58_LEN {
        return Err(ForeignChainInspectionError::MalformedRpcResponse(format!(
            "transaction digest in response is too long: {} characters",
            returned.len()
        )));
    }
    let returned_bytes = bs58::decode(returned).into_vec().map_err(|e| {
        ForeignChainInspectionError::MalformedRpcResponse(format!(
            "non-base58 transaction digest in response: {e}"
        ))
    })?;
    if returned_bytes.len() != requested.len() {
        return Err(ForeignChainInspectionError::MalformedRpcResponse(format!(
            "transaction digest in response is {} bytes, expected 32",
            returned_bytes.len()
        )));
    }
    if returned_bytes.as_slice() != requested.as_slice() {
        return Err(ForeignChainInspectionError::InconsistentRpcResponse {
            requested_hash: HexBytes(requested.to_vec()),
            returned_hash: HexBytes(returned_bytes),
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
                    .map(normalize_type_tag)
                    .ok_or_else(|| malformed_event_field("event_type"))?;
                let contents = event
                    .contents
                    .as_ref()
                    .ok_or_else(|| malformed_event_field("bcs contents"))?;
                // When present, the type name shipped alongside the BCS bytes must agree with
                // the event type we sign; a mismatch means the payload and its claimed type
                // come apart. Both sides are normalized so a provider that renders the two
                // fields with different address forms is not rejected spuriously.
                if let Some(name) = contents.name.as_deref() {
                    let normalized_name = normalize_type_tag(name);
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
                    .ok_or_else(|| malformed_event_field("bcs contents"))?;

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

/// Rewrites every address inside a Move struct tag to Sui's canonical long form —
/// `0x` followed by 64 lowercase hex digits — so providers that shorten framework
/// addresses and providers that return the long form converge to the same signed payload.
///
/// Examples:
/// - `0x2::sui::SUI` → `0x00…02::sui::SUI` (64 hex digits)
/// - `0xAB::m::S` → `0x00…ab::m::S`
/// - `0x2::coin::Coin<0x2::sui::SUI>` → `0x00…02::coin::Coin<0x00…02::sui::SUI>`
///
/// Addresses appear at the start of the tag or of a generic type argument — that is, right
/// after `<`, `,` or a space — and are always followed by `::`. Splitting on those delimiters
/// (keeping them) yields pieces that each begin at a potential address position, so only a
/// leading `0x<hex>::` of a piece is rewritten; anything else (identifiers that merely contain
/// `0x` such as a module named `m0x01`, primitive type args, …) is copied verbatim.
fn normalize_type_tag(tag: &str) -> String {
    tag.split_inclusive(['<', ',', ' '])
        .map(normalize_leading_address)
        .collect()
}

/// If `piece` begins with an address followed by `::` (e.g. `0x2::m::S<`), rewrites that
/// address to zero-padded lowercase (`0x00…02::m::S<`); any other piece is returned unchanged.
fn normalize_leading_address(piece: &str) -> Cow<'_, str> {
    let Some(stripped) = piece.strip_prefix("0x") else {
        return Cow::Borrowed(piece);
    };
    let Some((hex, rest)) = stripped.split_once("::") else {
        return Cow::Borrowed(piece);
    };
    let is_address =
        !hex.is_empty() && hex.len() <= 64 && hex.bytes().all(|b| b.is_ascii_hexdigit());
    if !is_address {
        return Cow::Borrowed(piece);
    }
    let padded = format!("{:0>64}", hex.to_ascii_lowercase());
    Cow::Owned(format!("0x{padded}::{rest}"))
}

/// Parse a Sui address string (0x-prefixed hex, possibly short) into [`SuiAddress`].
/// Short addresses like "0x2" are zero-padded to 32 bytes.
fn parse_sui_address(s: &str) -> Result<SuiAddress, String> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    if hex_str.is_empty() {
        return Err(format!("empty Sui address: {s:?}"));
    }
    if hex_str.len() > 64 {
        return Err(format!("address hex string too long: {s}"));
    }
    let padded = format!("{hex_str:0>64}");
    let bytes = hex::decode(&padded).map_err(|e| format!("invalid hex in address '{s}': {e}"))?;
    let array: [u8; 32] = bytes.try_into().expect("padded to exactly 32 bytes");
    Ok(SuiAddress(array))
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use rstest::rstest;

    #[test]
    fn classify_status__should_map_not_found_to_transaction_not_found() {
        // Given — the status a node returns for an unknown or pruned digest.
        let status =
            Status::not_found("Transaction 88XKXHJRmGzkfwJa8PhoeDkqt4kxz8AEsB1UTzAbtd29 not found");

        // When
        let classified = classify_status(status);

        // Then — a substantive (non-transient) verdict.
        assert_matches!(classified, ForeignChainInspectionError::TransactionNotFound);
        assert!(!classified.is_transient());
    }

    #[rstest]
    #[case::deadline_exceeded(Code::DeadlineExceeded)]
    #[case::unavailable(Code::Unavailable)]
    #[case::resource_exhausted(Code::ResourceExhausted)]
    #[case::internal(Code::Internal)]
    #[case::unknown(Code::Unknown)]
    fn classify_status__should_keep_provider_hiccups_transient(#[case] code: Code) {
        // Given / When
        let classified = classify_status(Status::new(code, "provider hiccup"));

        // Then — the provider is dropped from the quorum instead of blocking it.
        assert_matches!(classified, ForeignChainInspectionError::RpcRequestFailed(_));
        assert!(classified.is_transient());
    }

    #[rstest]
    #[case::invalid_argument(Code::InvalidArgument)]
    #[case::unauthenticated(Code::Unauthenticated)]
    #[case::permission_denied(Code::PermissionDenied)]
    #[case::unimplemented(Code::Unimplemented)]
    fn classify_status__should_reject_deterministic_errors(#[case] code: Code) {
        // Given / When
        let classified = classify_status(Status::new(code, "deterministic rejection"));

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
    fn ensure_digest_matches__should_reject_wrong_length_digest_as_malformed_response() {
        // Given — a valid base58 string that decodes to 31 bytes, not 32.
        let short = bs58::encode([0xab; 31]).into_string();

        // When / Then — a malformed field, not a digest mismatch.
        assert_matches!(
            ensure_digest_matches(&[0xab; 32], &short),
            Err(ForeignChainInspectionError::MalformedRpcResponse(_))
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
        assert_eq!(normalize_type_tag(input), expected);
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
        // `""` and `"0x"` would otherwise be zero-padded into the all-zeros address.
        parse_sui_address("").unwrap_err();
        parse_sui_address("0x").unwrap_err();
    }

    #[test]
    fn parse_sui_address__should_reject_overlong_address() {
        let too_long = format!("0x{}", "a".repeat(65));
        parse_sui_address(&too_long).unwrap_err();
    }
}
