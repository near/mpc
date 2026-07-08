use crate::sui::{SuiExtractedValue, SuiTransactionDigest};
use crate::{ForeignChainInspectionError, ForeignChainInspector, HexBytes};
use base64::Engine as _;
use foreign_chain_rpc_interfaces::sui::{
    GetTransactionBlockArgs, SuiEventResponse, TransactionBlockResponse,
};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::core::client::error::Error as RpcClientError;
use near_mpc_contract_interface::types::{SuiAddress, SuiEvent};
use std::borrow::Cow;

const GET_TRANSACTION_BLOCK_METHOD: &str = "sui_getTransactionBlock";

/// A 32-byte Sui digest is at most 44 base58 characters.
const DIGEST_MAX_BASE58_LEN: usize = 44;

/// Upper bound on a base58 event payload we will decode. Like [`DIGEST_MAX_BASE58_LEN`], this
/// caps `bs58`'s superlinear decode against an oversized provider response. It exceeds any real
/// event payload by orders of magnitude (Sui bridge and system events are well under a kilobyte),
/// and only the long-deprecated pre-v1.26 base58 event encoding reaches this path at all —
/// current nodes send base64, which decodes in linear time.
const EVENT_BCS_MAX_BASE58_LEN: usize = 16_384;

/// Upper bound on a base64 event payload we will decode. Base64 decoding is linear, so unlike
/// [`EVENT_BCS_MAX_BASE58_LEN`] this is not a CPU guard — it rejects absurd responses before
/// allocating for them. Sized above the base64 form (~342k characters) of Sui's protocol limit
/// on emitted event size (`max_event_emit_size`, 256 KB), so every protocol-legal event passes.
const EVENT_BCS_MAX_BASE64_LEN: usize = 400_000;

/// Message prefix a Sui node returns for an unknown (or pruned) transaction digest.
/// Its JSON-RPC error code (-32602) is shared with invalid-params errors, so the
/// message is the only discriminator.
const TRANSACTION_NOT_FOUND_MESSAGE_PREFIX: &str = "Could not find the referenced transaction";

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
    Client: ClientT + Send + Sync,
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
        let args = GetTransactionBlockArgs {
            digest: bs58::encode(*tx_id).into_string(),
        };

        let tx: TransactionBlockResponse = self
            .client
            .request(GET_TRANSACTION_BLOCK_METHOD, &args)
            .await
            .map_err(classify_rpc_error)?;

        ensure_digest_matches(&tx_id, &tx.digest)?;

        match finality {
            SuiFinality::Checkpointed => {
                // The read API sets `checkpoint` only once the transaction is included in a
                // certified checkpoint; until then the verdict is "not final yet", not an error.
                if tx.checkpoint.is_none() {
                    return Err(ForeignChainInspectionError::NotFinalized);
                }
            }
        }

        let Some(effects) = &tx.effects else {
            return Err(ForeignChainInspectionError::MalformedRpcResponse(
                "transaction response is missing the requested effects".to_string(),
            ));
        };
        if effects.status.status != "success" {
            return Err(ForeignChainInspectionError::TransactionFailed);
        }

        let extracted_values = extractors
            .iter()
            .map(|extractor| extractor.extract_value(&tx))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(extracted_values)
    }
}

/// A `Call` error is a substantive answer from a working node: an unknown digest maps to
/// [`ForeignChainInspectionError::TransactionNotFound`], any other rejection is
/// deterministic and must not be dropped from the fan-out quorum as a mere hiccup.
/// Transport-level failures stay transient via
/// [`ForeignChainInspectionError::ClientError`].
fn classify_rpc_error(error: RpcClientError) -> ForeignChainInspectionError {
    match error {
        RpcClientError::Call(object) => {
            if object
                .message()
                .starts_with(TRANSACTION_NOT_FOUND_MESSAGE_PREFIX)
            {
                ForeignChainInspectionError::TransactionNotFound
            } else {
                ForeignChainInspectionError::RpcRequestRejected(object.to_string())
            }
        }
        RpcClientError::ParseError(e) => {
            ForeignChainInspectionError::MalformedRpcResponse(e.to_string())
        }
        other => ForeignChainInspectionError::ClientError(other),
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
        tx: &TransactionBlockResponse,
    ) -> Result<SuiExtractedValue, ForeignChainInspectionError> {
        match self {
            SuiExtractor::Event { event_index } => {
                let event = tx
                    .events
                    .get(*event_index)
                    .ok_or(ForeignChainInspectionError::LogIndexOutOfBounds)?;

                ensure_event_id_consistent(event, *event_index, &tx.digest)?;

                let package_id = parse_sui_address(&event.package_id).map_err(|reason| {
                    ForeignChainInspectionError::MalformedRpcResponse(format!(
                        "failed to parse event package_id: {reason}"
                    ))
                })?;
                let sender = parse_sui_address(&event.sender).map_err(|reason| {
                    ForeignChainInspectionError::MalformedRpcResponse(format!(
                        "failed to parse event sender: {reason}"
                    ))
                })?;

                let bcs = decode_event_bcs(event)?;

                let type_tag = normalize_type_tag(&event.event_type);

                Ok(SuiExtractedValue::Event(SuiEvent {
                    package_id,
                    transaction_module: event.transaction_module.clone(),
                    sender,
                    type_tag,
                    bcs,
                }))
            }
        }
    }
}

/// The certified event order is the array order: `id.eventSeq` equals the position and
/// `id.txDigest` echoes the transaction. A response violating either served a reordered
/// or foreign event list, which must not be signed even when only one provider is
/// configured.
fn ensure_event_id_consistent(
    event: &SuiEventResponse,
    event_index: usize,
    tx_digest: &str,
) -> Result<(), ForeignChainInspectionError> {
    if event.id.tx_digest != tx_digest {
        return Err(ForeignChainInspectionError::MalformedRpcResponse(format!(
            "event txDigest {:?} does not match the transaction digest {tx_digest:?}",
            event.id.tx_digest
        )));
    }
    if event.id.event_seq != event_index.to_string() {
        return Err(ForeignChainInspectionError::MalformedRpcResponse(format!(
            "event at position {event_index} carries eventSeq {:?}",
            event.id.event_seq
        )));
    }
    Ok(())
}

fn decode_event_bcs(event: &SuiEventResponse) -> Result<Vec<u8>, ForeignChainInspectionError> {
    match event.bcs_encoding.as_deref() {
        Some("base64") => {
            if event.bcs.len() > EVENT_BCS_MAX_BASE64_LEN {
                return Err(ForeignChainInspectionError::MalformedRpcResponse(format!(
                    "base64 event bcs is too long: {} characters",
                    event.bcs.len()
                )));
            }
            base64::engine::general_purpose::STANDARD
                .decode(&event.bcs)
                .map_err(|e| {
                    ForeignChainInspectionError::MalformedRpcResponse(format!(
                        "non-base64 event bcs: {e}"
                    ))
                })
        }
        // Nodes before v1.26 emitted base58 without a `bcsEncoding` tag.
        Some("base58") | None => {
            if event.bcs.len() > EVENT_BCS_MAX_BASE58_LEN {
                return Err(ForeignChainInspectionError::MalformedRpcResponse(format!(
                    "base58 event bcs is too long: {} characters",
                    event.bcs.len()
                )));
            }
            bs58::decode(&event.bcs).into_vec().map_err(|e| {
                ForeignChainInspectionError::MalformedRpcResponse(format!(
                    "non-base58 event bcs: {e}"
                ))
            })
        }
        Some(other) => Err(ForeignChainInspectionError::MalformedRpcResponse(format!(
            "unknown event bcs encoding: {other:?}"
        ))),
    }
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
    use jsonrpsee::types::ErrorObject;
    use rstest::rstest;

    #[test]
    fn classify_rpc_error__should_map_unknown_digest_to_transaction_not_found() {
        // Given — the exact envelope a mainnet node returns for an unknown digest.
        let error = RpcClientError::Call(ErrorObject::owned(
            -32602,
            "Could not find the referenced transaction [TransactionDigest(88XKXHJRmGzkfwJa8PhoeDkqt4kxz8AEsB1UTzAbtd29)].",
            None::<()>,
        ));

        // When
        let classified = classify_rpc_error(error);

        // Then — a substantive (non-transient) verdict.
        assert_matches!(classified, ForeignChainInspectionError::TransactionNotFound);
        assert!(!classified.is_transient());
    }

    #[test]
    fn classify_rpc_error__should_map_other_call_errors_to_rejected() {
        // Given
        let error = RpcClientError::Call(ErrorObject::owned(
            -32602,
            "Invalid params",
            Some("Deserialization failed"),
        ));

        // When
        let classified = classify_rpc_error(error);

        // Then — deterministic rejection: retrying cannot change it, and the fan-out
        // must not validate on the remaining providers alone.
        assert_matches!(
            classified,
            ForeignChainInspectionError::RpcRequestRejected(_)
        );
        assert!(!classified.is_transient());
    }

    #[test]
    fn classify_rpc_error__should_map_parse_errors_to_malformed_response() {
        // Given
        let serde_error = serde_json::from_str::<u64>("not-json").unwrap_err();

        // When
        let classified = classify_rpc_error(RpcClientError::ParseError(serde_error));

        // Then
        assert_matches!(
            classified,
            ForeignChainInspectionError::MalformedRpcResponse(_)
        );
        assert!(!classified.is_transient());
    }

    #[test]
    fn classify_rpc_error__should_keep_transport_errors_transient() {
        // Given
        let error = RpcClientError::Transport(Box::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connection refused",
        )));

        // When
        let classified = classify_rpc_error(error);

        // Then — a provider hiccup: dropped from the quorum instead of blocking it.
        assert_matches!(classified, ForeignChainInspectionError::ClientError(_));
        assert!(classified.is_transient());
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

    fn event_response(event_seq: &str, tx_digest: &str) -> SuiEventResponse {
        SuiEventResponse {
            id: foreign_chain_rpc_interfaces::sui::SuiEventId {
                tx_digest: tx_digest.to_string(),
                event_seq: event_seq.to_string(),
            },
            package_id: "0x2".to_string(),
            transaction_module: "m".to_string(),
            sender: "0x1".to_string(),
            event_type: "0x2::m::E".to_string(),
            bcs: base64::engine::general_purpose::STANDARD.encode([0xde, 0xad]),
            bcs_encoding: Some("base64".to_string()),
        }
    }

    #[test]
    fn ensure_event_id_consistent__should_accept_matching_id() {
        // Given / When / Then
        ensure_event_id_consistent(&event_response("3", "digest"), 3, "digest").unwrap();
    }

    #[rstest]
    #[case::wrong_seq("4", "digest")]
    #[case::wrong_digest("3", "other-digest")]
    fn ensure_event_id_consistent__should_reject_inconsistent_id(
        #[case] event_seq: &str,
        #[case] event_tx_digest: &str,
    ) {
        // Given
        let event = event_response(event_seq, event_tx_digest);

        // When / Then
        assert_matches!(
            ensure_event_id_consistent(&event, 3, "digest"),
            Err(ForeignChainInspectionError::MalformedRpcResponse(_))
        );
    }

    #[test]
    fn decode_event_bcs__should_decode_base64_encoding() {
        // Given
        let event = event_response("0", "digest");

        // When / Then
        assert_eq!(decode_event_bcs(&event).unwrap(), vec![0xde, 0xad]);
    }

    #[test]
    fn decode_event_bcs__should_decode_legacy_base58_without_encoding_tag() {
        // Given
        let mut event = event_response("0", "digest");
        event.bcs = bs58::encode([0xde, 0xad]).into_string();
        event.bcs_encoding = None;

        // When / Then
        assert_eq!(decode_event_bcs(&event).unwrap(), vec![0xde, 0xad]);
    }

    #[test]
    fn decode_event_bcs__should_decode_explicitly_tagged_base58() {
        // Given — a node that tags its base58 output must decode to the same bytes as base64.
        let mut event = event_response("0", "digest");
        event.bcs = bs58::encode([0xde, 0xad]).into_string();
        event.bcs_encoding = Some("base58".to_string());

        // When / Then
        assert_eq!(decode_event_bcs(&event).unwrap(), vec![0xde, 0xad]);
    }

    #[test]
    fn decode_event_bcs__should_reject_oversized_base58_without_decoding() {
        // Given — a base58 payload far larger than any real event; superlinear decode is
        // bounded by rejecting it on length.
        let mut event = event_response("0", "digest");
        event.bcs = "1".repeat(1_000_000);
        event.bcs_encoding = Some("base58".to_string());

        // When / Then
        assert_matches!(
            decode_event_bcs(&event),
            Err(ForeignChainInspectionError::MalformedRpcResponse(_))
        );
    }

    #[test]
    fn decode_event_bcs__should_reject_oversized_base64() {
        // Given — a base64 payload beyond the protocol's maximum emitted event size.
        let mut event = event_response("0", "digest");
        event.bcs = "A".repeat(EVENT_BCS_MAX_BASE64_LEN + 4);
        event.bcs_encoding = Some("base64".to_string());

        // When / Then
        assert_matches!(
            decode_event_bcs(&event),
            Err(ForeignChainInspectionError::MalformedRpcResponse(_))
        );
    }

    #[test]
    fn decode_event_bcs__should_reject_unknown_encoding() {
        // Given
        let mut event = event_response("0", "digest");
        event.bcs_encoding = Some("hex".to_string());

        // When / Then
        assert_matches!(
            decode_event_bcs(&event),
            Err(ForeignChainInspectionError::MalformedRpcResponse(_))
        );
    }

    #[test]
    fn decode_event_bcs__should_reject_invalid_base64_as_malformed_response() {
        // Given
        let mut event = event_response("0", "digest");
        event.bcs = "!!!not-base64!!!".to_string();

        // When / Then
        assert_matches!(
            decode_event_bcs(&event),
            Err(ForeignChainInspectionError::MalformedRpcResponse(_))
        );
    }
}
