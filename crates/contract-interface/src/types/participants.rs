use crate::types::primitives::AccountId;
use borsh::{BorshDeserialize, BorshSerialize};
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
    derive_more::Deref,
    derive_more::From,
    derive_more::Into,
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

/// The data stored for each participant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct ParticipantData {
    pub id: ParticipantId,
    pub info: ParticipantInfo,
}

/// DTO representation of the contract-internal `Participants` type.
///
/// It mirrors the contract-internal [`BTreeMap`]-based structure, mapping each
/// [`AccountId`] to its [`ParticipantData`] (participant ID + connection info).
///
/// Deserialization supports both the current BTreeMap format and the legacy
/// Vec-of-tuples format (`[[account, id, info], ...]`) for backward
/// compatibility with older contract versions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct Participants {
    pub next_id: ParticipantId,
    #[serde(deserialize_with = "deserialize_participants")]
    pub participants: BTreeMap<AccountId, ParticipantData>,
}

/// Custom deserializer for the `participants` field that accepts both the
/// current map format (`{account: {id, info}}`) and the legacy vec-of-tuples
/// format (`[[account, id, info], ...]`).
fn deserialize_participants<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<AccountId, ParticipantData>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ParticipantsField {
        Map(BTreeMap<AccountId, ParticipantData>),
        Vec(Vec<(AccountId, ParticipantId, ParticipantInfo)>),
    }

    match ParticipantsField::deserialize(deserializer)? {
        ParticipantsField::Map(map) => Ok(map),
        ParticipantsField::Vec(vec) => Ok(vec
            .into_iter()
            .map(|(account, id, info)| (account, ParticipantData { id, info }))
            .collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_outputs_map_format() {
        let mut participants = BTreeMap::new();
        participants.insert(
            AccountId("alice.near".to_string()),
            ParticipantData {
                id: ParticipantId(0),
                info: ParticipantInfo {
                    url: "https://alice.com".to_string(),
                    sign_pk: "ed25519:abc".to_string(),
                },
            },
        );
        let p = Participants {
            next_id: ParticipantId(1),
            participants,
        };

        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(
            json,
            r#"{"next_id":1,"participants":{"alice.near":{"id":0,"info":{"url":"https://alice.com","sign_pk":"ed25519:abc"}}}}"#
        );
    }

    #[test]
    fn test_deserialize_map_format() {
        let json = r#"{"next_id":1,"participants":{"alice.near":{"id":0,"info":{"url":"https://alice.com","sign_pk":"ed25519:abc"}}}}"#;
        let deserialized: Participants = serde_json::from_str(json).unwrap();

        let mut expected_participants = BTreeMap::new();
        expected_participants.insert(
            AccountId("alice.near".to_string()),
            ParticipantData {
                id: ParticipantId(0),
                info: ParticipantInfo {
                    url: "https://alice.com".to_string(),
                    sign_pk: "ed25519:abc".to_string(),
                },
            },
        );
        assert_eq!(
            deserialized,
            Participants {
                next_id: ParticipantId(1),
                participants: expected_participants,
            }
        );
    }

    #[test]
    fn test_deserialize_legacy_vec_format() {
        // Old contracts serialize participants as a Vec of (AccountId, ParticipantId, ParticipantInfo) tuples.
        let json = r#"{"next_id":2,"participants":[["alice.near",0,{"url":"https://alice.com","sign_pk":"ed25519:abc"}],["bob.near",1,{"url":"https://bob.com","sign_pk":"ed25519:def"}]]}"#;
        let deserialized: Participants = serde_json::from_str(json).unwrap();

        let mut expected_participants = BTreeMap::new();
        expected_participants.insert(
            AccountId("alice.near".to_string()),
            ParticipantData {
                id: ParticipantId(0),
                info: ParticipantInfo {
                    url: "https://alice.com".to_string(),
                    sign_pk: "ed25519:abc".to_string(),
                },
            },
        );
        expected_participants.insert(
            AccountId("bob.near".to_string()),
            ParticipantData {
                id: ParticipantId(1),
                info: ParticipantInfo {
                    url: "https://bob.com".to_string(),
                    sign_pk: "ed25519:def".to_string(),
                },
            },
        );
        assert_eq!(
            deserialized,
            Participants {
                next_id: ParticipantId(2),
                participants: expected_participants,
            }
        );
    }
}
