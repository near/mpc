use crate::types::primitives::AccountId;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

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

/// DTO representation of the contract-internal `Participants` type.
///
/// It decouples the JSON wire format (used in view methods like `state()` via
/// [`ThresholdParameters`](crate::types::state::ThresholdParameters)) from the
/// internal `Participants` representation, allowing internal changes (e.g.,
/// migrating to [`BTreeMap`](std::collections::BTreeMap) in [#1861](https://github.com/near/mpc/pull/1861))
/// without breaking the public API.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct Participants {
    pub next_id: ParticipantId,
    pub participants: Vec<(AccountId, ParticipantId, ParticipantInfo)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_outputs_vec_format() {
        let participants_json = Participants {
            next_id: ParticipantId(1),
            participants: vec![(
                AccountId("alice.near".to_string()),
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

    #[test]
    fn test_deserialize_vec_format() {
        let json = r#"{"next_id":1,"participants":[["alice.near",0,{"url":"https://alice.com","sign_pk":"ed25519:abc"}]]}"#;
        let deserialized: Participants = serde_json::from_str(json).unwrap();
        assert_eq!(
            deserialized,
            Participants {
                next_id: ParticipantId(1),
                participants: vec![(
                    AccountId("alice.near".to_string()),
                    ParticipantId(0),
                    ParticipantInfo {
                        url: "https://alice.com".to_string(),
                        sign_pk: "ed25519:abc".to_string(),
                    },
                )],
            }
        );
    }
}
