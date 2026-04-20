//! Sign request types used by the contract's `sign()` API.
//!
//! [`SignRequestArgs`] is the canonical sign request type with required fields.
//! Its custom [`Deserialize`] impl handles backward compatibility by accepting
//! both current field names (payload_v2, domain_id) and deprecated ones
//! (payload, key_version).
//!
//! [`SignatureRequest`] is the resolved form stored in the contract state,
//! containing the derived tweak, payload, and domain ID.

use borsh::{BorshDeserialize, BorshSerialize};
use near_account_id::AccountId;
use serde::{Deserialize, Deserializer, Serialize};

use crate::{Payload, Tweak};
use mpc_primitives::domain::DomainId;

/// Sign request args with backward-compatible deserialization.
///
/// The struct field is `payload` but serializes as `payload_v2` on the wire
/// for compatibility with existing consumers. Deserialization accepts both
/// `payload_v2` and the deprecated `payload` (as raw `[u8; 32]`) plus
/// `key_version` as an alias for `domain_id`.
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct SignRequestArgs {
    pub path: String,
    #[serde(rename = "payload_v2")]
    pub payload: Payload,
    pub domain_id: DomainId,
}

/// Compat layer: all fields optional so both old and new wire formats parse.
#[derive(Deserialize)]
struct SignRequestArgsCompat {
    path: String,
    payload_v2: Option<Payload>,
    #[serde(rename = "payload")]
    deprecated_payload: Option<[u8; 32]>,
    domain_id: Option<DomainId>,
    #[serde(rename = "key_version")]
    deprecated_key_version: Option<u32>,
}

impl<'de> Deserialize<'de> for SignRequestArgs {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let compat = SignRequestArgsCompat::deserialize(deserializer)?;

        let payload = match (compat.payload_v2, compat.deprecated_payload) {
            (Some(p), None) => p,
            (None, Some(bytes)) => Payload::from_legacy_ecdsa(bytes),
            (Some(_), Some(_)) => {
                return Err(serde::de::Error::custom(
                    "payload_v2 and payload are mutually exclusive",
                ));
            }
            (None, None) => return Err(serde::de::Error::missing_field("payload_v2")),
        };

        let domain_id = match (compat.domain_id, compat.deprecated_key_version) {
            (Some(id), None) => id,
            (None, Some(kv)) => DomainId(kv.into()),
            (Some(_), Some(_)) => {
                return Err(serde::de::Error::custom(
                    "domain_id and key_version are mutually exclusive",
                ));
            }
            (None, None) => return Err(serde::de::Error::missing_field("domain_id")),
        };

        Ok(SignRequestArgs {
            path: compat.path,
            payload,
            domain_id,
        })
    }
}

/// A signature request after computing the tweak from the caller's account and
/// derivation path. This is what gets stored in the contract state and sent
/// back to the respond function.
#[derive(
    Debug,
    Clone,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct SignatureRequest {
    pub tweak: Tweak,
    pub payload: Payload,
    pub domain_id: DomainId,
}

impl SignatureRequest {
    pub fn new(domain: DomainId, payload: Payload, predecessor_id: &AccountId, path: &str) -> Self {
        let tweak = crate::kdf::derive_tweak(predecessor_id, path);
        SignatureRequest {
            domain_id: domain,
            tweak,
            payload,
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use near_mpc_bounded_collections::BoundedVec;

    fn ecdsa_payload_hex() -> String {
        "0707070707070707070707070707070707070707070707070707070707070707".to_string()
    }

    fn ecdsa_payload_bytes() -> [u8; 32] {
        [7u8; 32]
    }

    fn eddsa_payload_hex() -> String {
        "0a".repeat(64)
    }

    fn eddsa_payload_bytes() -> Vec<u8> {
        vec![0x0a; 64]
    }

    #[test]
    fn deserialize__should_parse_v2_ecdsa_format() {
        // Given
        let json = serde_json::json!({
            "path": "m/44'/60'/0'/0/0",
            "payload_v2": {"Ecdsa": ecdsa_payload_hex()},
            "domain_id": 0
        });

        // When
        let args: SignRequestArgs = serde_json::from_value(json).unwrap();

        // Then
        assert_eq!(args.path, "m/44'/60'/0'/0/0");
        assert_eq!(args.domain_id, DomainId(0));
        assert_eq!(args.payload.as_ecdsa().unwrap(), &ecdsa_payload_bytes());
    }

    #[test]
    fn deserialize__should_parse_v2_eddsa_format() {
        // Given
        let json = serde_json::json!({
            "path": "solana-path",
            "payload_v2": {"Eddsa": eddsa_payload_hex()},
            "domain_id": 1
        });

        // When
        let args: SignRequestArgs = serde_json::from_value(json).unwrap();

        // Then
        assert_eq!(args.path, "solana-path");
        assert_eq!(args.domain_id, DomainId(1));
        assert_eq!(args.payload.as_eddsa().unwrap(), &eddsa_payload_bytes());
    }

    #[test]
    fn deserialize__should_parse_legacy_v1_format_with_raw_payload_and_key_version() {
        // Given
        let json = serde_json::json!({
            "path": "m/44'/60'/0'/0/0",
            "payload": ecdsa_payload_bytes().to_vec(),
            "key_version": 0
        });

        // When
        let args: SignRequestArgs = serde_json::from_value(json).unwrap();

        // Then
        assert_eq!(args.path, "m/44'/60'/0'/0/0");
        assert_eq!(args.domain_id, DomainId(0));
        assert_eq!(args.payload.as_ecdsa().unwrap(), &ecdsa_payload_bytes());
    }

    #[test]
    fn deserialize__should_reject_both_payload_v2_and_deprecated_payload() {
        // Given — both payload_v2 and payload present
        let json = serde_json::json!({
            "path": "test",
            "payload_v2": {"Ecdsa": ecdsa_payload_hex()},
            "payload": vec![0u8; 32],
            "domain_id": 0
        });

        // When
        let result = serde_json::from_value::<SignRequestArgs>(json);

        // Then
        result.unwrap_err();
    }

    #[test]
    fn deserialize__should_reject_both_domain_id_and_key_version() {
        // Given — both domain_id and key_version present
        let json = serde_json::json!({
            "path": "test",
            "payload_v2": {"Ecdsa": ecdsa_payload_hex()},
            "domain_id": 5,
            "key_version": 0
        });

        // When
        let result = serde_json::from_value::<SignRequestArgs>(json);

        // Then
        result.unwrap_err();
    }

    #[test]
    fn deserialize__should_convert_key_version_to_domain_id() {
        // Given
        let json = serde_json::json!({
            "path": "test",
            "payload_v2": {"Ecdsa": ecdsa_payload_hex()},
            "key_version": 3
        });

        // When
        let args: SignRequestArgs = serde_json::from_value(json).unwrap();

        // Then
        assert_eq!(args.domain_id, DomainId(3));
    }

    #[test]
    fn deserialize__should_reject_missing_payload() {
        // Given
        let json = serde_json::json!({
            "path": "test",
            "domain_id": 0
        });

        // When
        let result = serde_json::from_value::<SignRequestArgs>(json);

        // Then
        result.unwrap_err();
    }

    #[test]
    fn deserialize__should_reject_missing_domain_id_and_key_version() {
        // Given
        let json = serde_json::json!({
            "path": "test",
            "payload_v2": {"Ecdsa": ecdsa_payload_hex()}
        });

        // When
        let result = serde_json::from_value::<SignRequestArgs>(json);

        // Then
        result.unwrap_err();
    }

    #[test]
    fn deserialize__should_reject_missing_path() {
        // Given
        let json = serde_json::json!({
            "payload_v2": {"Ecdsa": ecdsa_payload_hex()},
            "domain_id": 0
        });

        // When
        let result = serde_json::from_value::<SignRequestArgs>(json);

        // Then
        result.unwrap_err();
    }

    #[test]
    fn deserialize__should_accept_mixed_payload_v2_with_key_version() {
        // Given — new payload format + old domain format
        let json = serde_json::json!({
            "path": "test",
            "payload_v2": {"Ecdsa": ecdsa_payload_hex()},
            "key_version": 2
        });

        // When
        let args: SignRequestArgs = serde_json::from_value(json).unwrap();

        // Then
        assert_eq!(args.payload.as_ecdsa().unwrap(), &ecdsa_payload_bytes());
        assert_eq!(args.domain_id, DomainId(2));
    }

    #[test]
    fn deserialize__should_accept_mixed_legacy_payload_with_domain_id() {
        // Given — old payload format + new domain format
        let json = serde_json::json!({
            "path": "test",
            "payload": ecdsa_payload_bytes().to_vec(),
            "domain_id": 3
        });

        // When
        let args: SignRequestArgs = serde_json::from_value(json).unwrap();

        // Then
        assert_eq!(args.payload.as_ecdsa().unwrap(), &ecdsa_payload_bytes());
        assert_eq!(args.domain_id, DomainId(3));
    }

    #[test]
    fn deserialize__should_accept_empty_path() {
        // Given
        let json = serde_json::json!({
            "path": "",
            "payload_v2": {"Ecdsa": ecdsa_payload_hex()},
            "domain_id": 0
        });

        // When
        let args: SignRequestArgs = serde_json::from_value(json).unwrap();

        // Then
        assert_eq!(args.path, "");
    }

    #[test]
    fn deserialize__should_reject_invalid_legacy_payload_wrong_length() {
        // Given — 16 bytes instead of 32
        let json = serde_json::json!({
            "path": "test",
            "payload": vec![0u8; 16],
            "key_version": 0
        });

        // When
        let result = serde_json::from_value::<SignRequestArgs>(json);

        // Then
        result.unwrap_err();
    }

    #[test]
    fn serialize__should_emit_payload_v2_on_wire() {
        // Given
        let args = SignRequestArgs {
            path: "test".to_string(),
            payload: Payload::from_legacy_ecdsa(ecdsa_payload_bytes()),
            domain_id: DomainId(1),
        };

        // When
        let json = serde_json::to_value(&args).unwrap();

        // Then
        assert!(json.get("payload_v2").is_some());
        assert!(json.get("payload").is_none());
        assert!(json.get("domain_id").is_some());
        assert!(json.get("key_version").is_none());
        assert_eq!(json.get("path").unwrap(), "test");
    }

    #[test]
    fn serialize__should_emit_payload_v2_for_eddsa() {
        // Given
        let bounded: BoundedVec<u8, 32, 1232> = eddsa_payload_bytes().try_into().unwrap();
        let args = SignRequestArgs {
            path: "test".to_string(),
            payload: Payload::Eddsa(bounded),
            domain_id: DomainId(1),
        };

        // When
        let json = serde_json::to_value(&args).unwrap();

        // Then — EdDSA also serializes under payload_v2
        assert!(json.get("payload_v2").is_some());
        assert!(json.get("payload").is_none());
        let payload_v2 = json.get("payload_v2").unwrap();
        assert!(payload_v2.get("Eddsa").is_some());
    }

    #[test]
    fn serialize__should_roundtrip_ecdsa() {
        // Given
        let args = SignRequestArgs {
            path: "m/44'/60'/0'/0/0".to_string(),
            payload: Payload::from_legacy_ecdsa(ecdsa_payload_bytes()),
            domain_id: DomainId(0),
        };

        // When
        let json = serde_json::to_value(&args).unwrap();
        let deserialized: SignRequestArgs = serde_json::from_value(json).unwrap();

        // Then
        assert_eq!(deserialized.path, args.path);
        assert_eq!(deserialized.domain_id, args.domain_id);
        assert_eq!(deserialized.payload.as_ecdsa(), args.payload.as_ecdsa());
    }

    #[test]
    fn serialize__should_roundtrip_eddsa() {
        // Given
        let bounded: BoundedVec<u8, 32, 1232> = eddsa_payload_bytes().try_into().unwrap();
        let args = SignRequestArgs {
            path: "solana-path".to_string(),
            payload: Payload::Eddsa(bounded),
            domain_id: DomainId(1),
        };

        // When
        let json = serde_json::to_value(&args).unwrap();
        let deserialized: SignRequestArgs = serde_json::from_value(json).unwrap();

        // Then
        assert_eq!(deserialized.path, args.path);
        assert_eq!(deserialized.domain_id, args.domain_id);
        assert_eq!(deserialized.payload.as_eddsa(), args.payload.as_eddsa());
    }
}
