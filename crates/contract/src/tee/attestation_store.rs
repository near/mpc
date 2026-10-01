use crate::storage_keys::StorageKey;
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_attestation::attestation::VerifiedAttestation;
use near_mpc_contract_interface::types::{Ed25519PublicKey, NodeId};
use near_sdk::{
    near,
    store::{IterableMap, LookupMap},
};

#[derive(Debug)]
pub(crate) enum ParticipantInsertion {
    NewlyInsertedParticipant,
    UpdatedExistingParticipant,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub(crate) struct NodeAttestation {
    pub(crate) node_id: NodeId,
    pub(crate) verified_attestation: VerifiedAttestation,
}

/// Attestations keyed by TLS public key, with a reverse index from each account public key
/// to the TLS key most recently written for it.
#[near(serializers=[borsh])]
#[derive(Debug)]
pub(crate) struct AttestationStore {
    by_tls_key: IterableMap<Ed25519PublicKey, NodeAttestation>,
    by_account_key: LookupMap<Ed25519PublicKey, Ed25519PublicKey>,
}

impl Default for AttestationStore {
    fn default() -> Self {
        Self {
            by_tls_key: IterableMap::new(StorageKey::StoredAttestations),
            by_account_key: LookupMap::new(StorageKey::StoredAttestationsByAccountKey),
        }
    }
}

impl AttestationStore {
    /// Adopts entries written before the reverse index existed and leaves the index empty, so
    /// the cost does not grow with the number of entries. Such an entry is found by the scan in
    /// [`Self::get_by_account_key`] until it is next written.
    pub(crate) fn from_unindexed_map(
        by_tls_key: IterableMap<Ed25519PublicKey, NodeAttestation>,
    ) -> Self {
        Self {
            by_tls_key,
            by_account_key: LookupMap::new(StorageKey::StoredAttestationsByAccountKey),
        }
    }

    /// The newest write for an account key wins its index row. Rotating the account key of a
    /// TLS key drops the previous account key's row when it still points at this TLS key.
    pub(crate) fn insert(
        &mut self,
        node_id: NodeId,
        verified_attestation: VerifiedAttestation,
    ) -> ParticipantInsertion {
        let tls_pk = node_id.tls_public_key.clone();
        let account_pk = node_id.account_public_key.clone();

        let previous = self.by_tls_key.insert(
            tls_pk.clone(),
            NodeAttestation {
                node_id,
                verified_attestation,
            },
        );
        if let Some(previous) = &previous
            && previous.node_id.account_public_key != account_pk
        {
            self.remove_row_pointing_at(&previous.node_id.account_public_key, &tls_pk);
        }
        // A re-attestation leaves the row as it is, so skip the storage write.
        if self.by_account_key.get(&account_pk) != Some(&tls_pk) {
            self.by_account_key.insert(account_pk, tls_pk);
        }

        match previous {
            Some(_) => ParticipantInsertion::UpdatedExistingParticipant,
            None => ParticipantInsertion::NewlyInsertedParticipant,
        }
    }

    pub(crate) fn get_by_tls_key(&self, tls_pk: &Ed25519PublicKey) -> Option<&NodeAttestation> {
        self.by_tls_key.get(tls_pk)
    }

    /// Returns the entry most recently written for `account_pk`, or else the first entry
    /// carrying it. The fallback scans every entry, so authorize the caller before calling
    /// this.
    pub(crate) fn get_by_account_key(
        &self,
        account_pk: &Ed25519PublicKey,
    ) -> Option<&NodeAttestation> {
        self.get_indexed(account_pk).or_else(|| {
            // TODO(#4621): drop this scan once every participant node has rewritten its entry
            // since the index was added.
            self.by_tls_key
                .values()
                .find(|attestation| attestation.node_id.account_public_key == *account_pk)
        })
    }

    fn get_indexed(&self, account_pk: &Ed25519PublicKey) -> Option<&NodeAttestation> {
        let tls_pk = self.by_account_key.get(account_pk)?;
        self.by_tls_key
            .get(tls_pk)
            .filter(|attestation| attestation.node_id.account_public_key == *account_pk)
    }

    /// Keeps the account key row when it already points at a newer entry.
    pub(crate) fn remove(&mut self, tls_pk: &Ed25519PublicKey) -> Option<NodeAttestation> {
        let removed = self.by_tls_key.remove(tls_pk)?;
        self.remove_row_pointing_at(&removed.node_id.account_public_key, tls_pk);
        Some(removed)
    }

    fn remove_row_pointing_at(&mut self, account_pk: &Ed25519PublicKey, tls_pk: &Ed25519PublicKey) {
        if self.by_account_key.get(account_pk) == Some(tls_pk) {
            self.by_account_key.remove(account_pk);
        }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&Ed25519PublicKey, &NodeAttestation)> {
        self.by_tls_key.iter()
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = &NodeAttestation> {
        self.by_tls_key.values()
    }

    #[cfg(test)]
    pub(crate) fn is_indexed(&self, account_pk: &Ed25519PublicKey) -> bool {
        self.get_indexed(account_pk).is_some()
    }

    #[cfg(test)]
    pub(crate) fn contains_key(&self, tls_pk: &Ed25519PublicKey) -> bool {
        self.by_tls_key.contains_key(tls_pk)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> u32 {
        self.by_tls_key.len()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.by_tls_key.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn flush(&mut self) {
        self.by_tls_key.flush();
        self.by_account_key.flush();
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::primitives::test_utils::bogus_ed25519_public_key;
    use assert_matches::assert_matches;
    use mpc_attestation::attestation::MockAttestation;

    fn alice_node_id(
        tls_public_key: &Ed25519PublicKey,
        account_public_key: &Ed25519PublicKey,
    ) -> NodeId {
        NodeId {
            account_id: "alice.near".parse().unwrap(),
            tls_public_key: tls_public_key.clone(),
            account_public_key: account_public_key.clone(),
        }
    }

    fn valid_mock() -> VerifiedAttestation {
        VerifiedAttestation::Mock(MockAttestation::Valid)
    }

    fn unindexed_store(node_ids: impl IntoIterator<Item = NodeId>) -> AttestationStore {
        let mut by_tls_key = IterableMap::new(StorageKey::StoredAttestations);
        for node_id in node_ids {
            by_tls_key.insert(
                node_id.tls_public_key.clone(),
                NodeAttestation {
                    node_id,
                    verified_attestation: valid_mock(),
                },
            );
        }
        AttestationStore::from_unindexed_map(by_tls_key)
    }

    #[test]
    fn attestation_store__insert__should_overwrite_the_entry_of_a_reattesting_node() {
        // Given
        let mut store = AttestationStore::default();
        let tls_pk = bogus_ed25519_public_key();
        let account_pk = bogus_ed25519_public_key();
        let node = alice_node_id(&tls_pk, &account_pk);
        store.insert(node.clone(), valid_mock());

        // When
        let insertion = store.insert(
            node.clone(),
            VerifiedAttestation::Mock(MockAttestation::Invalid),
        );

        // Then
        assert_matches!(insertion, ParticipantInsertion::UpdatedExistingParticipant);
        assert_eq!(store.len(), 1);
        assert_matches!(
            store.get_by_tls_key(&tls_pk).unwrap().verified_attestation,
            VerifiedAttestation::Mock(MockAttestation::Invalid)
        );
        assert!(store.is_indexed(&account_pk));
        assert_eq!(store.get_by_account_key(&account_pk).unwrap().node_id, node);
    }

    #[test]
    fn attestation_store__insert__should_move_the_row_when_a_tls_key_rotates_its_account_key() {
        // Given
        let mut store = AttestationStore::default();
        let tls_pk = bogus_ed25519_public_key();
        let old_account_pk = bogus_ed25519_public_key();
        let new_account_pk = bogus_ed25519_public_key();
        store.insert(alice_node_id(&tls_pk, &old_account_pk), valid_mock());

        // When
        let new_node = alice_node_id(&tls_pk, &new_account_pk);
        store.insert(new_node.clone(), valid_mock());

        // Then
        assert!(store.by_account_key.get(&old_account_pk).is_none());
        assert!(store.get_by_account_key(&old_account_pk).is_none());
        assert!(store.is_indexed(&new_account_pk));
        assert_eq!(
            store.get_by_account_key(&new_account_pk).unwrap().node_id,
            new_node
        );
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn attestation_store__remove__should_keep_the_row_of_a_newer_entry() {
        // Given
        let mut store = AttestationStore::default();
        let account_pk = bogus_ed25519_public_key();
        let old_tls_pk = bogus_ed25519_public_key();
        let new_tls_pk = bogus_ed25519_public_key();
        let old_node = alice_node_id(&old_tls_pk, &account_pk);
        let new_node = alice_node_id(&new_tls_pk, &account_pk);
        store.insert(old_node.clone(), valid_mock());
        store.insert(new_node.clone(), valid_mock());

        // When
        let removed = store.remove(&old_tls_pk);

        // Then
        assert_eq!(removed.unwrap().node_id, old_node);
        assert!(store.is_indexed(&account_pk));
        assert_eq!(
            store.get_by_account_key(&account_pk).unwrap().node_id,
            new_node
        );
    }

    #[test]
    fn attestation_store__remove__should_drop_the_row_pointing_at_the_removed_entry() {
        // Given
        let mut store = AttestationStore::default();
        let tls_pk = bogus_ed25519_public_key();
        let account_pk = bogus_ed25519_public_key();
        store.insert(alice_node_id(&tls_pk, &account_pk), valid_mock());

        // When
        store.remove(&tls_pk);

        // Then
        assert!(store.by_account_key.get(&account_pk).is_none());
        assert!(store.get_by_account_key(&account_pk).is_none());
    }

    #[test]
    fn attestation_store__get_by_account_key__should_resolve_newest_after_repeated_rotations() {
        // Given
        let mut store = AttestationStore::default();
        let account_pk = bogus_ed25519_public_key();
        let tls_keys: Vec<Ed25519PublicKey> = (0..3).map(|_| bogus_ed25519_public_key()).collect();

        // When
        for tls_pk in &tls_keys {
            store.insert(alice_node_id(tls_pk, &account_pk), valid_mock());
        }

        // Then
        assert_eq!(
            store.get_by_account_key(&account_pk).unwrap().node_id,
            alice_node_id(&tls_keys[2], &account_pk)
        );
        assert_eq!(store.len(), 3);
    }

    #[test]
    fn attestation_store__get_by_account_key__should_resolve_an_unindexed_entry_by_scanning() {
        // Given
        let account_pk = bogus_ed25519_public_key();
        let node = alice_node_id(&bogus_ed25519_public_key(), &account_pk);
        let other = alice_node_id(&bogus_ed25519_public_key(), &bogus_ed25519_public_key());
        let store = unindexed_store([other, node.clone()]);

        // When
        let resolved = store.get_by_account_key(&account_pk);

        // Then
        assert!(!store.is_indexed(&account_pk));
        assert_eq!(resolved.unwrap().node_id, node);
    }

    #[test]
    fn attestation_store__insert__should_index_an_unindexed_entry_when_it_is_rewritten() {
        // Given
        let account_pk = bogus_ed25519_public_key();
        let node = alice_node_id(&bogus_ed25519_public_key(), &account_pk);
        let mut store = unindexed_store([node.clone()]);

        // When
        let insertion = store.insert(node.clone(), valid_mock());

        // Then
        assert_matches!(insertion, ParticipantInsertion::UpdatedExistingParticipant);
        assert!(store.is_indexed(&account_pk));
        assert_eq!(store.get_by_account_key(&account_pk).unwrap().node_id, node);
    }

    #[test]
    fn attestation_store__get_by_account_key__should_resolve_the_older_entry_once_the_newest_is_removed()
     {
        // Given
        let mut store = AttestationStore::default();
        let account_pk = bogus_ed25519_public_key();
        let older_node = alice_node_id(&bogus_ed25519_public_key(), &account_pk);
        let newest_node = alice_node_id(&bogus_ed25519_public_key(), &account_pk);
        store.insert(older_node.clone(), valid_mock());
        store.insert(newest_node.clone(), valid_mock());
        store.remove(&newest_node.tls_public_key);

        // When
        let resolved = store.get_by_account_key(&account_pk);

        // Then
        assert_eq!(resolved.unwrap().node_id, older_node);
    }

    #[test]
    fn attestation_store__get_by_account_key__should_return_none_for_an_unknown_key() {
        // Given
        let mut store = AttestationStore::default();
        store.insert(
            alice_node_id(&bogus_ed25519_public_key(), &bogus_ed25519_public_key()),
            valid_mock(),
        );

        // When
        let resolved = store.get_by_account_key(&bogus_ed25519_public_key());

        // Then
        assert!(resolved.is_none());
    }

    #[test]
    fn attestation_store__get_by_account_key__should_never_resolve_a_stale_row_to_an_entry_carrying_another_key()
     {
        // Given
        let account_pk = bogus_ed25519_public_key();
        let foreign_node = alice_node_id(&bogus_ed25519_public_key(), &bogus_ed25519_public_key());
        let node = alice_node_id(&bogus_ed25519_public_key(), &account_pk);
        let mut store = unindexed_store([foreign_node.clone(), node.clone()]);
        store
            .by_account_key
            .insert(account_pk.clone(), foreign_node.tls_public_key.clone());

        // When
        let resolved = store.get_by_account_key(&account_pk);

        // Then
        assert!(!store.is_indexed(&account_pk));
        assert_eq!(resolved.unwrap().node_id, node);
    }
}
