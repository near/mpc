use crate::types::primitives::AccountId;
use crate::types::state::AuthenticatedParticipantId;
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_primitives::hash::{
    KeyProviderEventDigest, LauncherImageHash, MrtdHash, NodeImageHash, Rtmr0Hash, Rtmr1Hash,
    Rtmr2Hash,
};
use near_mpc_crypto_types::Ed25519PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Hash,
    Ord,
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
pub struct NodeId {
    /// Operator account.
    pub account_id: AccountId,
    /// TLS public key used by the node for peer-to-peer communication.
    pub tls_public_key: Ed25519PublicKey,
    /// Full-access Ed25519 public key of the operator account.
    pub account_public_key: Ed25519PublicKey,
}

#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Hash,
    Ord,
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
pub struct AllowedMpcDockerImageHash {
    pub image_hash: NodeImageHash,
    /// block-time at which this hash is evicted from the allowlist.
    /// None if expiration date is not yet known.
    pub expiry_timestamp_seconds: Option<u64>,
}

/// The TDX measurements an attestation is required to match.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
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
pub struct ExpectedMeasurements {
    pub mrtd: MrtdHash,
    pub rtmr0: Rtmr0Hash,
    pub rtmr1: Rtmr1Hash,
    pub rtmr2: Rtmr2Hash,
    pub key_provider_event_digest: KeyProviderEventDigest,
}

/// The action a participant is voting for on an OS measurement set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub enum MeasurementVoteAction {
    Add(ExpectedMeasurements),
    Remove(ExpectedMeasurements),
}

/// Tracks votes for adding or removing OS measurements.
/// Each participant can have at most one active vote at a time.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct MeasurementVotes {
    pub vote_by_account: BTreeMap<AuthenticatedParticipantId, MeasurementVoteAction>,
}

/// The action a participant is voting for on a launcher image hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub enum LauncherVoteAction {
    Add(LauncherImageHash),
    Remove(LauncherImageHash),
}

/// Tracks votes for adding or removing launcher image hashes.
/// Each participant can have at most one active vote at a time.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct LauncherHashVotes {
    pub vote_by_account: BTreeMap<AuthenticatedParticipantId, LauncherVoteAction>,
}

/// Tracks votes to add whitelisted TEE code hashes. Each participant can at any given time vote for
/// a code hash to add.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct CodeHashesVotes {
    pub proposal_by_account: BTreeMap<AuthenticatedParticipantId, NodeImageHash>,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::types::participants::ParticipantId;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    const TLS_KEY_STR: &str = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp";
    const ACCOUNT_KEY_STR: &str = "ed25519:Fru1RoC6dw1xY2J6C6ZSBUt5PEysxTLX2kDexxqoDN6k";
    const OTHER_ACCOUNT_KEY_STR: &str = "ed25519:3t4M1gXg2Qd5g6X8z1g2X3t4M1gXg2Qd5g6X8z1g2X3t";

    fn tls_key() -> Ed25519PublicKey {
        TLS_KEY_STR.parse().unwrap()
    }

    fn account_key() -> Ed25519PublicKey {
        ACCOUNT_KEY_STR.parse().unwrap()
    }

    fn other_account_key() -> Ed25519PublicKey {
        OTHER_ACCOUNT_KEY_STR.parse().unwrap()
    }

    fn node_id_with_account_key(account_key: Ed25519PublicKey) -> NodeId {
        NodeId {
            account_id: "alice.near".parse().unwrap(),
            tls_public_key: tls_key(),
            account_public_key: account_key,
        }
    }

    fn hash_of(node_id: &NodeId) -> u64 {
        let mut hasher = DefaultHasher::new();
        node_id.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn node_id__eq_differs_when_account_public_key_differs() {
        // Given
        let with_key = node_id_with_account_key(account_key());
        let with_other_key = node_id_with_account_key(other_account_key());

        // Then
        assert_ne!(with_key, with_other_key);
    }

    #[test]
    fn node_id__hash_differs_when_account_public_key_differs() {
        // Given
        let with_key = node_id_with_account_key(account_key());
        let with_other_key = node_id_with_account_key(other_account_key());

        // Then
        assert_ne!(hash_of(&with_key), hash_of(&with_other_key));
    }

    #[test]
    fn node_id__serializes_public_keys_as_strings() {
        // Given
        let node_id = node_id_with_account_key(account_key());

        // When
        let json = serde_json::to_string(&node_id).unwrap();

        // Then
        let expected = format!(
            r#"{{"account_id":"alice.near","tls_public_key":"{TLS_KEY_STR}","account_public_key":"{ACCOUNT_KEY_STR}"}}"#,
        );
        assert_eq!(json, expected);
    }

    #[test]
    fn node_id__deserializes_json() {
        // Given
        let json = format!(
            r#"{{"account_id":"alice.near","tls_public_key":"{TLS_KEY_STR}","account_public_key":"{ACCOUNT_KEY_STR}"}}"#,
        );

        // When
        let deserialized: NodeId = serde_json::from_str(&json).unwrap();

        // Then
        assert_eq!(deserialized, node_id_with_account_key(account_key()));
    }

    fn measurements(byte: u8) -> ExpectedMeasurements {
        ExpectedMeasurements {
            mrtd: MrtdHash::from([byte; 48]),
            rtmr0: Rtmr0Hash::from([byte; 48]),
            rtmr1: Rtmr1Hash::from([byte; 48]),
            rtmr2: Rtmr2Hash::from([byte; 48]),
            key_provider_event_digest: KeyProviderEventDigest::from([byte; 48]),
        }
    }

    #[test]
    fn expected_measurements__should_serialize_digests_as_hex_strings() {
        // Given
        let measurements = measurements(0x01);

        // When
        let json = serde_json::to_value(&measurements).unwrap();

        // Then
        assert_eq!(json["mrtd"], "01".repeat(48));
        assert_eq!(json["key_provider_event_digest"], "01".repeat(48));
    }

    #[test]
    fn measurement_votes__should_serialize_participant_ids_as_object_keys() {
        // Given
        let votes = MeasurementVotes {
            vote_by_account: BTreeMap::from([(
                AuthenticatedParticipantId(ParticipantId::new(7)),
                MeasurementVoteAction::Add(measurements(0x01)),
            )]),
        };

        // When
        let json = serde_json::to_value(&votes).unwrap();

        // Then
        assert_eq!(json["vote_by_account"]["7"]["Add"]["mrtd"], "01".repeat(48));
    }

    #[test]
    fn launcher_hash_votes__should_serialize_participant_ids_as_object_keys() {
        // Given
        let votes = LauncherHashVotes {
            vote_by_account: BTreeMap::from([(
                AuthenticatedParticipantId(ParticipantId::new(7)),
                LauncherVoteAction::Add(LauncherImageHash::from([0xAB; 32])),
            )]),
        };

        // When
        let json = serde_json::to_value(&votes).unwrap();

        // Then
        assert_eq!(json["vote_by_account"]["7"]["Add"], "ab".repeat(32));
    }
}
