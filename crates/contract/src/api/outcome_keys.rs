//! The outcome keys nodes sign their node outcomes for V2 foreign transaction requests with.

use crate::{MpcContract, MpcContractExt};
use near_mpc_contract_interface::types as dtos;
use near_sdk::{env, log, near};

#[near]
impl MpcContract {
    /// Sets the outcome key of the caller's account, replacing the one it had. Only the
    /// account's attested node can call it, with its attested account key.
    pub fn register_outcome_key(&mut self, outcome_key: dtos::Ed25519PublicKey) {
        log!("register_outcome_key: signer={}", env::signer_account_id());
        self.assert_caller_is_attested_participant_and_protocol_active();
        self.outcome_keys.set(env::signer_account_id(), outcome_key);
    }

    /// The outcome key of each account that registered one. A key of an account that is not a
    /// current participant may remain after a cancelled resharing or keygen, so readers use only
    /// the keys of current participants.
    pub fn outcome_keys(&self) -> dtos::OutcomeKeys {
        self.outcome_keys.snapshot()
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::api::node_migration::MINIMUM_NODE_MANAGEMENT_DEPOSIT;
    use crate::api::test_utils::{
        basic_setup, destination_of, must_attest_new_node, must_get_attested_signer_key,
        participant_account_ids, prepay_and_submit_mock_attestation,
        running_contract_called_by_participant_via_forwarder,
    };
    use crate::dto_mapping::IntoInterfaceType;
    use crate::primitives::test_utils::{
        bogus_ed25519_near_public_key, bogus_ed25519_public_key, gen_account_id,
    };
    use crate::primitives::thresholds::{GovernanceThreshold, GovernanceThresholdParameters};
    use crate::state::ProtocolContractState;
    use crate::state::key_event::tests::Environment;
    use dtos::Curve;
    use near_sdk::AccountId;
    use rand::rngs::OsRng;
    use std::collections::BTreeMap;

    fn outcome_key(byte: u8) -> dtos::Ed25519PublicKey {
        dtos::Ed25519PublicKey::from([byte; 32])
    }

    fn call_as(account_id: &AccountId, signer_pk: near_sdk::PublicKey) {
        let mut env = Environment::new(None, Some(account_id.clone()), None);
        env.set_pk(signer_pk);
    }

    fn attested_key_of_participant(
        contract: &MpcContract,
        account_id: &AccountId,
    ) -> near_sdk::PublicKey {
        let tls_public_key = contract
            .protocol_state
            .active_participants()
            .info(account_id)
            .expect("the account must be a participant")
            .tls_public_key
            .clone();
        must_get_attested_signer_key(contract, &tls_public_key)
    }

    fn register_as_participant(
        contract: &mut MpcContract,
        account_id: &AccountId,
        key: dtos::Ed25519PublicKey,
    ) {
        call_as(
            account_id,
            attested_key_of_participant(contract, account_id),
        );
        contract.register_outcome_key(key);
    }

    #[test]
    fn register_outcome_key__should_store_the_key_of_an_attested_participant() {
        // Given
        let (_context, mut contract, _) = basic_setup(Curve::Secp256k1, &mut OsRng);
        let participant = participant_account_ids(&contract)[0].clone();
        call_as(
            &participant,
            attested_key_of_participant(&contract, &participant),
        );

        // When
        contract.register_outcome_key(outcome_key(1));

        // Then
        assert_eq!(
            contract.outcome_keys(),
            BTreeMap::from([(participant, outcome_key(1))]).into()
        );
    }

    #[test]
    fn register_outcome_key__should_replace_the_key_of_the_account() {
        // Given
        let (_context, mut contract, _) = basic_setup(Curve::Secp256k1, &mut OsRng);
        let participant = participant_account_ids(&contract)[0].clone();
        register_as_participant(&mut contract, &participant, outcome_key(1));

        // When
        register_as_participant(&mut contract, &participant, outcome_key(2));

        // Then
        assert_eq!(
            contract.outcome_keys(),
            BTreeMap::from([(participant, outcome_key(2))]).into()
        );
    }

    #[test]
    #[should_panic(expected = "Caller must be an attested participant")]
    fn register_outcome_key__should_reject_an_attested_non_participant() {
        // Given
        let (_context, mut contract, _) = basic_setup(Curve::Secp256k1, &mut OsRng);
        let outsider = gen_account_id();
        let outsider_tls_key = bogus_ed25519_public_key();
        prepay_and_submit_mock_attestation(&mut contract, &outsider, outsider_tls_key.clone())
            .unwrap();
        call_as(
            &outsider,
            must_get_attested_signer_key(&contract, &outsider_tls_key),
        );

        // When
        contract.register_outcome_key(outcome_key(1));
    }

    #[test]
    #[should_panic(expected = "Caller must be an attested participant")]
    fn register_outcome_key__should_reject_a_participant_signing_with_another_key() {
        // Given
        let (_context, mut contract, _) = basic_setup(Curve::Secp256k1, &mut OsRng);
        let participant = participant_account_ids(&contract)[0].clone();
        let operator_key = bogus_ed25519_near_public_key();
        assert_ne!(
            operator_key,
            attested_key_of_participant(&contract, &participant)
        );
        call_as(&participant, operator_key);

        // When
        contract.register_outcome_key(outcome_key(1));
    }

    #[test]
    #[should_panic(expected = "Caller must be the signer account")]
    fn register_outcome_key__should_reject_a_call_through_another_contract() {
        // Given
        let mut contract = running_contract_called_by_participant_via_forwarder();

        // When
        contract.register_outcome_key(outcome_key(1));
    }

    #[test]
    fn conclude_node_migration__should_drop_the_outcome_key_of_the_account() {
        // Given
        let (_context, mut contract, _) = basic_setup(Curve::Secp256k1, &mut OsRng);
        let participants = participant_account_ids(&contract);
        let operator = participants[0].clone();
        let other = participants[1].clone();
        register_as_participant(&mut contract, &operator, outcome_key(1));
        register_as_participant(&mut contract, &other, outcome_key(2));
        let destination = must_attest_new_node(&mut contract, &operator);
        let mut env = Environment::new(None, Some(operator.clone()), None);
        env.set_deposit(MINIMUM_NODE_MANAGEMENT_DEPOSIT);
        contract
            .start_node_migration(destination_of(&destination))
            .expect("participant should be able to start a node migration");
        let ProtocolContractState::Running(state) = &contract.protocol_state else {
            panic!("expected Running");
        };
        let keyset = (&state.keyset).into_dto_type();
        call_as(
            &operator,
            near_sdk::PublicKey::from(destination.account_public_key.clone()),
        );

        // When
        contract
            .conclude_node_migration(keyset)
            .expect("migration should conclude");

        // Then
        assert_eq!(
            contract.outcome_keys(),
            BTreeMap::from([(other, outcome_key(2))]).into()
        );
    }

    #[test]
    fn clean_foreign_chain_data__should_drop_the_outcome_keys_of_departed_participants() {
        // Given
        let (_context, mut contract, _) = basic_setup(Curve::Secp256k1, &mut OsRng);
        let participants = participant_account_ids(&contract);
        for (index, account_id) in (0u8..).zip(&participants) {
            register_as_participant(&mut contract, account_id, outcome_key(index));
        }
        let departed = &participants[2];
        let ProtocolContractState::Running(state) = &mut contract.protocol_state else {
            panic!("expected Running");
        };
        let mut remaining = state.parameters.participants().clone();
        remaining.remove(departed);
        state.parameters =
            GovernanceThresholdParameters::new_unvalidated(remaining, GovernanceThreshold::new(3));

        // When
        contract
            .clean_foreign_chain_data()
            .expect("clean should succeed");

        // Then
        let expected: BTreeMap<AccountId, dtos::Ed25519PublicKey> = (0u8..)
            .zip(&participants)
            .filter(|(_, account_id)| *account_id != departed)
            .map(|(index, account_id)| (account_id.clone(), outcome_key(index)))
            .collect();
        assert_eq!(contract.outcome_keys(), expected.into());
    }
}
