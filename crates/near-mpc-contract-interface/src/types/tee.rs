use crate::types::primitives::AccountId;
use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_crypto_types::Ed25519PublicKey;
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

/// Identity of an MPC node.
///
/// Equality and hashing intentionally ignore `account_public_key`: two `NodeId`
/// values are considered equal when they share the same `account_id` and
/// `tls_public_key`, even if one is still missing the account key. The derived
/// `Ord`/`PartialOrd` impls remain lexicographic over all fields and are used
/// for stable ordering in `BTreeSet`/`BTreeMap`.
#[derive(
    Clone, Debug, Ord, PartialOrd, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
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
    /// Full-access Ed25519 public key of the operator account. The node
    /// always generates an Ed25519 signer key, so non-Ed25519 keys never
    /// reach this field. `None` is allowed for legacy/mock nodes that were
    /// registered before this field became mandatory.
    pub account_public_key: Option<Ed25519PublicKey>,
}

impl PartialEq for NodeId {
    fn eq(&self, other: &Self) -> bool {
        self.account_id == other.account_id && self.tls_public_key == other.tls_public_key
    }
}

impl Eq for NodeId {}

impl Hash for NodeId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.account_id.hash(state);
        self.tls_public_key.hash(state);
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;

    const TLS_KEY_STR: &str = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp";
    const ACCOUNT_KEY_STR: &str = "ed25519:Fru1RoC6dw1xY2J6C6ZSBUt5PEysxTLX2kDexxqoDN6k";

    fn tls_key() -> Ed25519PublicKey {
        TLS_KEY_STR.parse().unwrap()
    }

    fn account_key() -> Ed25519PublicKey {
        ACCOUNT_KEY_STR.parse().unwrap()
    }

    fn node_id_with_account_key(account_key: Option<Ed25519PublicKey>) -> NodeId {
        NodeId {
            account_id: AccountId("alice.near".to_string()),
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
    fn node_id__eq_ignores_account_public_key() {
        // Given
        let with_key = node_id_with_account_key(Some(account_key()));
        let without_key = node_id_with_account_key(None);

        // Then
        assert_eq!(with_key, without_key);
    }

    #[test]
    fn node_id__hash_ignores_account_public_key() {
        // Given
        let with_key = node_id_with_account_key(Some(account_key()));
        let without_key = node_id_with_account_key(None);

        // Then
        assert_eq!(hash_of(&with_key), hash_of(&without_key));
    }

    #[test]
    fn node_id__serializes_public_keys_as_strings() {
        // Given
        let node_id = node_id_with_account_key(Some(account_key()));

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
            r#"{{"account_id":"alice.near","tls_public_key":"{TLS_KEY_STR}","account_public_key":null}}"#,
        );

        // When
        let deserialized: NodeId = serde_json::from_str(&json).unwrap();

        // Then
        assert_eq!(deserialized, node_id_with_account_key(None));
    }
}
