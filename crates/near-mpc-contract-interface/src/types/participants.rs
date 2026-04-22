use crate::types::primitives::AccountId;
use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_crypto_types::Ed25519PublicKey;
use serde::{Deserialize, Serialize};

pub use mpc_primitives::ParticipantId;

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
    // Accepts "sign_pk" for compat with pre-3.10.0 contracts. Remove after 3.10.0 deployment.
    #[serde(alias = "sign_pk")]
    pub tls_public_key: Ed25519PublicKey,
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

    const TEST_KEY_STR: &str = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp";

    fn test_key() -> Ed25519PublicKey {
        TEST_KEY_STR.parse().unwrap()
    }

    #[test]
    fn test_serialize_outputs_vec_format() {
        let participants_json = Participants {
            next_id: ParticipantId(1),
            participants: vec![(
                "alice.near".parse().unwrap(),
                ParticipantId(0),
                ParticipantInfo {
                    url: "https://alice.com".to_string(),
                    tls_public_key: test_key(),
                },
            )],
        };

        let json = serde_json::to_string(&participants_json).unwrap();
        let expected = format!(
            r#"{{"next_id":1,"participants":[["alice.near",0,{{"url":"https://alice.com","tls_public_key":"{TEST_KEY_STR}"}}]]}}"#,
        );
        assert_eq!(json, expected);
    }

    #[test]
    fn test_deserialize_vec_format() {
        let json = format!(
            r#"{{"next_id":1,"participants":[["alice.near",0,{{"url":"https://alice.com","tls_public_key":"{TEST_KEY_STR}"}}]]}}"#,
        );
        let deserialized: Participants = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized,
            Participants {
                next_id: ParticipantId(1),
                participants: vec![(
                    "alice.near".parse().unwrap(),
                    ParticipantId(0),
                    ParticipantInfo {
                        url: "https://alice.com".to_string(),
                        tls_public_key: test_key(),
                    },
                )],
            }
        );
    }

    #[test]
    #[expect(non_snake_case)]
    fn participant_info_deserialize__should_accept_legacy_sign_pk_alias() {
        // Given a JSON payload using the legacy "sign_pk" field name
        let json = format!(r#"{{"url":"https://alice.com","sign_pk":"{TEST_KEY_STR}"}}"#,);

        // When deserializing into the renamed DTO
        let deserialized: ParticipantInfo = serde_json::from_str(&json).unwrap();

        // Then the alias is honored and populates tls_public_key
        assert_eq!(
            deserialized,
            ParticipantInfo {
                url: "https://alice.com".to_string(),
                tls_public_key: test_key(),
            }
        );
    }
}
