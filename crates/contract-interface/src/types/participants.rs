use borsh::{BorshDeserialize, BorshSerialize};
use near_account_id::AccountId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct ParticipantId(pub u32);

#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct ParticipantInfo {
    pub url: String,
    pub sign_pk: String,
}

#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct ParticipantData {
    pub id: ParticipantId,
    pub info: ParticipantInfo,
}

#[derive(Clone, Debug, Serialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct ParticipantsJson {
    pub next_id: ParticipantId,
    pub participants: Vec<(AccountId, ParticipantId, ParticipantInfo)>,
}

/// Helper enum for deserializing both legacy Vec and new Map formats.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum ParticipantsField {
    /// Legacy format: array of [AccountId, ParticipantId, ParticipantInfo] tuples
    Vec(Vec<(AccountId, ParticipantId, ParticipantInfo)>),
    /// New format: map of AccountId -> ParticipantData
    Map(BTreeMap<AccountId, ParticipantData>),
}

/// JSON deserialization helper that accepts both Vec and Map formats.
#[derive(Clone, Debug, Deserialize)]
pub struct ParticipantsJsonDeserialize {
    pub next_id: ParticipantId,
    pub participants: ParticipantsField,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vec_format_deserialize() {
        let json = r#"{
            "next_id": 2,
            "participants": [
                ["alice.near", 0, {"url": "https://alice.com", "sign_pk": "ed25519:abc"}],
                ["bob.near", 1, {"url": "https://bob.com", "sign_pk": "ed25519:def"}]
            ]
        }"#;

        let parsed: ParticipantsJsonDeserialize = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.next_id, ParticipantId(2));
        assert_eq!(
            parsed.participants,
            ParticipantsField::Vec(vec![
                (
                    "alice.near".parse().unwrap(),
                    ParticipantId(0),
                    ParticipantInfo {
                        url: "https://alice.com".to_string(),
                        sign_pk: "ed25519:abc".to_string(),
                    },
                ),
                (
                    "bob.near".parse().unwrap(),
                    ParticipantId(1),
                    ParticipantInfo {
                        url: "https://bob.com".to_string(),
                        sign_pk: "ed25519:def".to_string(),
                    },
                ),
            ])
        );
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
        assert_eq!(parsed.next_id, ParticipantId(2));
        assert_eq!(
            parsed.participants,
            ParticipantsField::Map(BTreeMap::from([
                (
                    "alice.near".parse().unwrap(),
                    ParticipantData {
                        id: ParticipantId(0),
                        info: ParticipantInfo {
                            url: "https://alice.com".to_string(),
                            sign_pk: "ed25519:abc".to_string(),
                        },
                    },
                ),
                (
                    "bob.near".parse().unwrap(),
                    ParticipantData {
                        id: ParticipantId(1),
                        info: ParticipantInfo {
                            url: "https://bob.com".to_string(),
                            sign_pk: "ed25519:def".to_string(),
                        },
                    },
                ),
            ]))
        );
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
        assert_eq!(
            json,
            r#"{"next_id":1,"participants":[["alice.near",0,{"url":"https://alice.com","sign_pk":"ed25519:abc"}]]}"#
        );
    }
}
