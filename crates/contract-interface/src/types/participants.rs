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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct ParticipantsJson {
    pub next_id: ParticipantId,
    pub participants: Vec<(AccountId, ParticipantId, ParticipantInfo)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_outputs_vec_format() {
        let participants_json = ParticipantsJson {
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
}
