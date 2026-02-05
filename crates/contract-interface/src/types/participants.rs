//! DTO types for Participants JSON serialization format.
//!
//! These types define the JSON wire format for the `Participants` struct used in
//! the contract state endpoint. They enable backward-compatible serialization
//! that outputs the legacy Vec-based format while accepting both Vec and Map
//! formats during deserialization.

use near_account_id::AccountId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A participant's unique ID assigned during insertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct ParticipantId(pub u32);

/// Participant connection and verification info.
///
/// The `sign_pk` field serializes as a string like `"ed25519:base58..."`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct ParticipantInfo {
    pub url: String,
    /// The public key used for verifying messages, serialized as "curve:base58key".
    pub sign_pk: String,
}

/// Data stored for each participant in the Map format.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct ParticipantData {
    pub id: ParticipantId,
    pub info: ParticipantInfo,
}

/// JSON serialization helper that outputs the legacy Vec-based format.
///
/// This is the format used in API responses for backward compatibility:
/// ```json
/// {
///   "next_id": 5,
///   "participants": [
///     ["account1.near", 0, {"url": "...", "sign_pk": "ed25519:..."}],
///     ...
///   ]
/// }
/// ```
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct ParticipantsJson {
    pub next_id: ParticipantId,
    pub participants: Vec<(AccountId, ParticipantId, ParticipantInfo)>,
}

/// Helper enum for deserializing both legacy Vec and new Map formats.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ParticipantsField {
    /// Legacy format: array of [AccountId, ParticipantId, ParticipantInfo] tuples
    Vec(Vec<(AccountId, ParticipantId, ParticipantInfo)>),
    /// New format: map of AccountId -> ParticipantData
    Map(BTreeMap<AccountId, ParticipantData>),
}

/// JSON deserialization helper that accepts both Vec and Map formats.
#[derive(Debug, Clone, Deserialize)]
pub struct ParticipantsJsonDeserialize {
    pub next_id: ParticipantId,
    pub participants: ParticipantsField,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vec_format_roundtrip() {
        let json = r#"{
            "next_id": 2,
            "participants": [
                ["alice.near", 0, {"url": "https://alice.com", "sign_pk": "ed25519:abc"}],
                ["bob.near", 1, {"url": "https://bob.com", "sign_pk": "ed25519:def"}]
            ]
        }"#;

        let parsed: ParticipantsJsonDeserialize = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.next_id.0, 2);

        match parsed.participants {
            ParticipantsField::Vec(vec) => {
                assert_eq!(vec.len(), 2);
                assert_eq!(vec[0].0.as_str(), "alice.near");
            }
            ParticipantsField::Map(_) => panic!("Expected Vec format"),
        }
    }

    #[test]
    fn test_map_format_deserialize() {
        let json = r#"{
            "next_id": 2,
            "participants": {
                "alice.near": {"id": 0, "info": {"url": "https://alice.com", "sign_pk": "ed25519:abc"}},
                "bob.near": {"id": 1, "info": {"url": "https://bob.com", "sign_pk": "ed25519:def"}}
            }
        }"#;

        let parsed: ParticipantsJsonDeserialize = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.next_id.0, 2);

        match parsed.participants {
            ParticipantsField::Map(map) => {
                assert_eq!(map.len(), 2);
                let alice: AccountId = "alice.near".parse().unwrap();
                assert!(map.contains_key(&alice));
            }
            ParticipantsField::Vec(_) => panic!("Expected Map format"),
        }
    }

    #[test]
    fn test_serialize_outputs_vec_format() {
        let participants_json = ParticipantsJson {
            next_id: ParticipantId(1),
            participants: vec![(
                "alice.near".parse().unwrap(),
                ParticipantId(0),
                ParticipantInfo {
                    url: "https://alice.com".to_string(),
                    sign_pk: "ed25519:abc".to_string(),
                },
            )],
        };

        let json = serde_json::to_string(&participants_json).unwrap();
        // Vec format uses nested arrays for tuples
        assert!(json.contains("\"participants\":[["));
    }
}
