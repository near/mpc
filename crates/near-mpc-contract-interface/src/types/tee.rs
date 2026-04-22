use crate::types::primitives::AccountId;
use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_crypto_types::Ed25519PublicKey;
use serde::{Deserialize, Serialize};

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

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
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
}
