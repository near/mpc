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
/// compatibility with older contract versions. This can be removed once all
/// deployed contracts have been upgraded past the `Vec`-based format.
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

    fn participant(name: &str, id: u32) -> (AccountId, ParticipantData) {
        (
            AccountId(format!("{name}.near")),
            ParticipantData {
                id: ParticipantId(id),
                info: ParticipantInfo {
                    url: format!("https://{name}.com"),
                    sign_pk: format!("ed25519:{name}"),
                },
            },
        )
    }

    #[test]
    fn test_serialize_outputs_map_format() {
        let (id, data) = participant("alice", 0);
        let p = Participants {
            next_id: ParticipantId(1),
            participants: BTreeMap::from([(id.clone(), data.clone())]),
        };

        let json = serde_json::to_string(&p).unwrap();
        let expected = format!(
            r#"{{"next_id":1,"participants":{{"{}":{{"id":{},"info":{{"url":"{}","sign_pk":"{}"}}}}}}}}"#,
            id.0, data.id.0, data.info.url, data.info.sign_pk,
        );
        assert_eq!(json, expected);
    }

    #[test]
    fn test_deserialize_map_format() {
        let expected = Participants {
            next_id: ParticipantId(1),
            participants: BTreeMap::from([participant("alice", 0)]),
        };

        let json = serde_json::to_string(&expected).unwrap();
        let deserialized: Participants = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, expected);
    }

    #[test]
    fn test_deserialize_legacy_vec_format() {
        let (alice_id, alice_data) = participant("alice", 0);
        let (bob_id, bob_data) = participant("bob", 1);
        let expected = Participants {
            next_id: ParticipantId(2),
            participants: BTreeMap::from([
                (alice_id.clone(), alice_data.clone()),
                (bob_id.clone(), bob_data.clone()),
            ]),
        };

        // Old contracts serialize participants as a Vec of (AccountId, ParticipantId, ParticipantInfo) tuples.
        let legacy_json = serde_json::json!({
            "next_id": 2,
            "participants": [
                [&alice_id, &alice_data.id, &alice_data.info],
                [&bob_id, &bob_data.id, &bob_data.info],
            ]
        });
        let deserialized: Participants = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(deserialized, expected);
    }
}
