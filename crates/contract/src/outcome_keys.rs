//! The outcome key of each participant account. Its node signs node outcomes with this key.

use near_mpc_contract_interface::types as dtos;
use near_sdk::{AccountId, near, store::IterableMap};
use std::collections::BTreeMap;

use crate::{primitives::participants::Participants, storage_keys::StorageKey};

#[near(serializers=[borsh])]
#[derive(Debug)]
pub(crate) struct OutcomeKeys {
    keys: IterableMap<AccountId, dtos::Ed25519PublicKey>,
}

impl Default for OutcomeKeys {
    fn default() -> Self {
        Self {
            keys: IterableMap::new(StorageKey::OutcomeKeysByAccount),
        }
    }
}

impl OutcomeKeys {
    /// Replaces the account's key, if it has one.
    pub(crate) fn set(&mut self, account_id: AccountId, outcome_key: dtos::Ed25519PublicKey) {
        self.keys.insert(account_id, outcome_key);
    }

    pub(crate) fn remove(&mut self, account_id: &AccountId) {
        self.keys.remove(account_id);
    }

    pub(crate) fn retain_participants(&mut self, participants: &Participants) {
        let departed: Vec<AccountId> = self
            .keys
            .keys()
            .filter(|account_id| !participants.is_participant(*account_id))
            .cloned()
            .collect();
        for account_id in departed {
            self.keys.remove(&account_id);
        }
    }

    pub(crate) fn snapshot(&self) -> dtos::OutcomeKeys {
        self.keys
            .iter()
            .map(|(account_id, outcome_key)| (account_id.clone(), outcome_key.clone()))
            .collect::<BTreeMap<_, _>>()
            .into()
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::primitives::test_utils::gen_participants;

    fn key(byte: u8) -> dtos::Ed25519PublicKey {
        dtos::Ed25519PublicKey::from([byte; 32])
    }

    #[test]
    fn set__should_replace_the_key_of_the_account() {
        // Given
        let mut outcome_keys = OutcomeKeys::default();
        let account_id: AccountId = "alice.near".parse().unwrap();
        outcome_keys.set(account_id.clone(), key(1));

        // When
        outcome_keys.set(account_id.clone(), key(2));

        // Then
        assert_eq!(
            outcome_keys.snapshot(),
            dtos::OutcomeKeys::from(BTreeMap::from([(account_id, key(2))]))
        );
    }

    #[test]
    fn retain_participants__should_drop_only_the_keys_of_non_participants() {
        // Given
        let participants = gen_participants(2);
        let mut outcome_keys = OutcomeKeys::default();
        for (account_id, _, _) in participants.participants() {
            outcome_keys.set(account_id.clone(), key(1));
        }
        outcome_keys.set("departed.near".parse().unwrap(), key(2));

        // When
        outcome_keys.retain_participants(&participants);

        // Then
        let participant_keys: BTreeMap<AccountId, dtos::Ed25519PublicKey> = participants
            .participants()
            .iter()
            .map(|(account_id, _, _)| (account_id.clone(), key(1)))
            .collect();
        assert_eq!(outcome_keys.snapshot(), participant_keys.into());
    }
}
