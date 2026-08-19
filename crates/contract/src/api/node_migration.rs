//! Node migration: registering a backup service, starting and concluding a
//! migration to new hardware, and updating a participant's URL.

use crate::api::common::require_deposit;
use crate::dto_mapping::IntoContractType;
use crate::errors::{self, Error, InvalidParameters, InvalidState};
use crate::primitives::key_state::Keyset;
use crate::primitives::participants::ParticipantInfo;
use crate::state::ProtocolContractState;
use crate::tee::tee_state::{NodeId, TeeQuoteStatus};
use crate::{MpcContract, MpcContractExt};
use near_mpc_contract_interface::deposits::MINIMUM_NODE_MANAGEMENT_DEPOSIT_YOCTONEAR;
use near_mpc_contract_interface::types::{self as dtos};
use near_sdk::{AccountId, NearToken, env, log, near};
use std::collections::BTreeMap;
use std::time::Duration;

#[near]
impl MpcContract {
    pub fn migration_info(
        &self,
    ) -> BTreeMap<
        AccountId,
        (
            Option<dtos::BackupServiceInfo>,
            Option<dtos::DestinationNodeInfo>,
        ),
    > {
        log!("migration_info");
        self.node_migrations.get_all()
    }

    /// Registers or updates the backup service information for the caller account.
    ///
    /// The caller (`signer_account_id`) must be an existing or prospective participant.
    /// Otherwise, the transaction will fail.
    ///
    /// Requires a deposit of at least [`MINIMUM_NODE_MANAGEMENT_DEPOSIT`] (excess is refunded), so
    /// the call must be signed by a full-access key rather than the node's function-call access
    /// key.
    #[payable]
    #[handle_result]
    pub fn register_backup_service(
        &mut self,
        backup_service_info: dtos::BackupServiceInfo,
    ) -> Result<(), Error> {
        let account_id = Self::assert_caller_is_signer();
        log!(
            "register_backup_service: signer={:?}, backup_service_info={:?}",
            account_id,
            backup_service_info
        );
        if !self
            .protocol_state
            .is_existing_or_prospective_participant(&account_id)?
        {
            return Err(InvalidState::NotParticipant {
                account_id: account_id.clone(),
            }
            .into());
        }
        // Checked after the participant/state validation so those errors take precedence.
        require_deposit(MINIMUM_NODE_MANAGEMENT_DEPOSIT, &account_id);
        self.node_migrations
            .set_backup_service_info(account_id, backup_service_info);
        Ok(())
    }

    /// Sets the destination node for the calling account.
    ///
    /// This function can only be called while the protocol is in a [`Running`](ProtocolContractState::Running) state.
    /// The signer must be a current participant of the current epoch, otherwise an error is returned.
    /// On success, the provided [`DestinationNodeInfo`](dtos::DestinationNodeInfo) is stored in the contract state
    /// under the signer’s account ID.
    ///
    /// # Errors
    /// - [`InvalidState::ProtocolStateNotRunning`] if the protocol is not in the [`Running`](ProtocolContractState::Running) state.
    /// - [`InvalidState::NotParticipant`] if the signer is not a current participant.
    ///
    /// Requires a deposit of at least [`MINIMUM_NODE_MANAGEMENT_DEPOSIT`] (excess is refunded), so
    /// the call must be signed by a full-access key rather than the node's function-call access
    /// key.
    #[payable]
    #[handle_result]
    pub fn start_node_migration(
        &mut self,
        destination_node_info: dtos::DestinationNodeInfo,
    ) -> Result<(), Error> {
        let account_id = Self::assert_caller_is_signer();

        log!(
            "start_node_migration: signer={:?}, destination_node_info={:?}",
            account_id,
            destination_node_info
        );
        let ProtocolContractState::Running(running_state) = &self.protocol_state else {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        };

        if !running_state.is_participant_given_account_id(&account_id) {
            return Err(InvalidState::NotParticipant {
                account_id: account_id.clone(),
            }
            .into());
        }
        // Checked after the participant/state validation so those errors take precedence.
        require_deposit(MINIMUM_NODE_MANAGEMENT_DEPOSIT, &account_id);
        self.node_migrations
            .set_destination_node_info(account_id, destination_node_info);
        Ok(())
    }

    /// Updates the calling participant's registered URL, keeping the TLS key and participant ID.
    ///
    /// Requires a deposit of at least [`MINIMUM_NODE_MANAGEMENT_DEPOSIT`] (excess is refunded), so
    /// the call must be signed by a full-access key rather than the node's function-call access
    /// key.
    #[payable]
    #[handle_result]
    pub fn update_participant_url(&mut self, url: String) -> Result<(), Error> {
        let account_id = Self::assert_caller_is_signer();
        log!(
            "update_participant_url: signer={:?}, url={:?}",
            account_id,
            url
        );

        let ProtocolContractState::Running(running_state) = &mut self.protocol_state else {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        };

        let Some(existing_info) = running_state.parameters.participants().info(&account_id) else {
            return Err(InvalidState::NotParticipant { account_id }.into());
        };

        let new_info = ParticipantInfo {
            url,
            tls_public_key: existing_info.tls_public_key.clone(),
        };
        // Checked after the participant/state validation so those errors take precedence.
        require_deposit(MINIMUM_NODE_MANAGEMENT_DEPOSIT, &account_id);
        running_state.parameters.update_info(account_id, new_info)
    }

    /// Finalizes a node migration for the calling account.
    ///
    /// This method can only be called while the protocol is in a [`Running`](ProtocolContractState::Running) state
    /// and by an existing participant. On success, the participant’s information is
    /// updated to the new destination node.
    ///
    /// # Errors
    /// Returns the following errors:
    /// - [`InvalidState::ProtocolStateNotRunning`]: if protocol is not in [`Running`](ProtocolContractState::Running) state
    /// - [`InvalidState::NotParticipant`]: if caller is not a current participant
    /// - [`NodeMigrationError::KeysetMismatch`](crate::errors::NodeMigrationError::KeysetMismatch): if provided keyset does not match the expected keyset
    /// - [`NodeMigrationError::MigrationNotFound`](crate::errors::NodeMigrationError::MigrationNotFound): if no migration record exists for the caller
    /// - [`NodeMigrationError::AccountPublicKeyMismatch`](crate::errors::NodeMigrationError::AccountPublicKeyMismatch): if caller’s public key does not match the expected destination node
    /// - [`InvalidParameters::InvalidTeeRemoteAttestation`]: if destination node’s TEE quote is invalid
    #[handle_result]
    pub fn conclude_node_migration(&mut self, keyset: &Keyset) -> Result<(), Error> {
        let account_id = Self::assert_caller_is_signer();
        let signer_pk = env::signer_account_pk();
        log!(
            "conclude_node_migration: signer={:?}, signer_pk={:?} keyset={:?}",
            account_id,
            signer_pk,
            keyset
        );
        let ProtocolContractState::Running(running_state) = &mut self.protocol_state else {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        };

        if !running_state.is_participant_given_account_id(&account_id) {
            return Err(InvalidState::NotParticipant {
                account_id: account_id.clone(),
            }
            .into());
        }

        let expected_keyset = &running_state.keyset;
        if expected_keyset != keyset {
            return Err(errors::NodeMigrationError::KeysetMismatch {
                found: keyset.clone(),
                expected: expected_keyset.clone(),
            }
            .into());
        }

        let Some(expected_destination_node) = self.node_migrations.remove_migration(&account_id)
        else {
            return Err(errors::NodeMigrationError::MigrationNotFound.into());
        };
        let expected_signer_pk =
            near_sdk::PublicKey::from(expected_destination_node.signer_account_pk.clone());
        if expected_signer_pk != signer_pk {
            return Err(errors::NodeMigrationError::AccountPublicKeyMismatch {
                found: signer_pk,
                expected: expected_signer_pk,
            }
            .into());
        }
        // ensure that this node has a valid TEE quote.
        let node_id = NodeId {
            account_id: account_id.clone(),
            account_public_key: expected_destination_node.signer_account_pk,
            tls_public_key: expected_destination_node
                .destination_node_info
                .tls_public_key
                .clone(),
        };

        if !(matches!(
            self.tee_state.reverify_participants(
                &node_id,
                Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds),
            ),
            TeeQuoteStatus::Valid
        )) {
            return Err(InvalidParameters::InvalidTeeRemoteAttestation {
                reason: "destination node TEE quote is invalid".into(),
            }
            .into());
        };

        let old_tls_key = running_state
            .parameters
            .participants()
            .info(&account_id)
            .map(|info| info.tls_public_key.clone());

        let contract_participant_info = expected_destination_node
            .destination_node_info
            .into_contract_type();
        log!(
            "Moving Account {:?} to {:?}",
            account_id,
            contract_participant_info
        );

        running_state
            .parameters
            .update_info(account_id, contract_participant_info)?;

        if let Some(old_key) = old_tls_key {
            self.foreign_chains
                .get_mut()
                .foreign_chains_configs
                .remove(&old_key);
        }

        self.recompute_available_foreign_chains();
        Ok(())
    }

    #[private]
    #[handle_result]
    pub fn cleanup_orphaned_node_migrations(&mut self) -> Result<(), Error> {
        log!(
            "cleanup_orphaned_node_migrations signer={:?}",
            env::signer_account_id(),
        );
        let backup_services: Vec<AccountId> = self
            .node_migrations
            .backup_services_info()
            .keys()
            .cloned()
            .collect();

        for account_id in &backup_services {
            if !self
                .protocol_state
                .is_existing_or_prospective_participant(account_id)?
            {
                self.node_migrations.remove_account_data(account_id);
            }
        }
        Ok(())
    }
}

/// Minimum deposit required for the operator-authenticated node-management methods
/// (`register_backup_service`, `start_node_migration`, `update_participant_url`).
///
/// A non-zero deposit forces the call to be signed by a full-access key: the node's own key
/// is registered as a function-call access key, which cannot attach a deposit, so a leaked
/// node key cannot invoke these methods.
pub const MINIMUM_NODE_MANAGEMENT_DEPOSIT: NearToken =
    NearToken::from_yoctonear(MINIMUM_NODE_MANAGEMENT_DEPOSIT_YOCTONEAR);

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::api::test_utils::NUM_DOMAINS;
    use crate::errors::NodeMigrationError;
    use crate::primitives::participants::{ParticipantId, Participants};
    use crate::primitives::test_utils::{
        bogus_ed25519_public_key, gen_account_id, gen_participant,
    };
    use crate::state::key_event::tests::Environment;
    use crate::state::test_utils::{
        gen_initializing_state, gen_resharing_state, gen_running_state,
    };
    use crate::tee::tee_state::ParticipantInsertion;
    use assert_matches::assert_matches;
    use dtos::Ed25519PublicKey;
    use mpc_attestation::attestation::MockAttestation as MpcMockAttestation;
    use near_mpc_contract_interface::types::{BackupServiceInfo, DestinationNodeInfo};
    use std::panic;

    pub fn migration_info(
        contract_state: &MpcContract,
        account_id: &AccountId,
    ) -> (
        AccountId,
        Option<BackupServiceInfo>,
        Option<DestinationNodeInfo>,
    ) {
        contract_state.node_migrations.get_for_account(account_id)
    }

    #[test]
    fn test_start_node_migration_failure_not_participant() {
        let running_state = ProtocolContractState::Running(gen_running_state(NUM_DOMAINS));
        let mut contract = MpcContract::new_from_protocol_state(running_state);

        // sanity check
        assert!(contract.migration_info().is_empty());
        let destination_node_info = gen_random_destination_info();

        let non_participant = gen_account_id();
        Environment::new(None, Some(non_participant), None);

        let res = contract.start_node_migration(destination_node_info.clone());
        let _ = res.expect_err("Non-participants should not start node migrations");
        assert!(contract.migration_info().is_empty());
    }

    #[test]
    fn test_start_node_migration_success() {
        let running_state = ProtocolContractState::Running(gen_running_state(NUM_DOMAINS));
        let mut contract = MpcContract::new_from_protocol_state(running_state);

        // sanity check
        assert!(contract.migration_info().is_empty());

        let participants = {
            let ProtocolContractState::Running(running) = &contract.protocol_state else {
                panic!("expected running state");
            };
            running.parameters.participants().clone()
        };
        let mut expected_migration_state = BTreeMap::new();
        let mut test_env = Environment::new(None, None, None);
        test_env.set_deposit(MINIMUM_NODE_MANAGEMENT_DEPOSIT);
        for (account_id, _, _) in participants.participants() {
            test_env.set_signer(account_id);
            // sanity check
            assert_eq!(
                migration_info(&contract, account_id),
                (account_id.clone(), None, None)
            );
            let destination_node_info = gen_random_destination_info();
            let res = contract.start_node_migration(destination_node_info.clone());
            res.expect("Participant should be able to start node migration");
            let expected_res = (account_id.clone(), None, Some(destination_node_info));
            assert_eq!(migration_info(&contract, account_id), expected_res);
            expected_migration_state.insert(expected_res.0, (expected_res.1, expected_res.2));
        }

        let result = contract.migration_info();

        assert_eq!(result, expected_migration_state);
    }

    fn gen_random_destination_info() -> DestinationNodeInfo {
        let url_id: usize = rand::random();
        let (_, participant_info) = gen_participant(url_id);
        DestinationNodeInfo {
            signer_account_pk: bogus_ed25519_public_key(),
            destination_node_info: participant_info.into(),
        }
    }

    fn test_start_migration_node_failure_not_running(mut contract: MpcContract) {
        assert!(contract.migration_info().is_empty());
        let destination_node_info = gen_random_destination_info();
        let res = contract.start_node_migration(destination_node_info.clone());
        assert_matches!(
            res.unwrap_err(),
            Error::InvalidState(InvalidState::ProtocolStateNotRunning)
        );
        assert!(contract.migration_info().is_empty());
    }

    #[test]
    fn test_start_node_migration_failure_initializing() {
        let initializing_state =
            ProtocolContractState::Initializing(gen_initializing_state(NUM_DOMAINS, 0).1);
        let contract = MpcContract::new_from_protocol_state(initializing_state);
        test_start_migration_node_failure_not_running(contract);
    }

    #[test]
    fn test_start_node_migration_failure_resharing() {
        let resharing_state = ProtocolContractState::Resharing(gen_resharing_state(NUM_DOMAINS).1);
        let contract = MpcContract::new_from_protocol_state(resharing_state);
        test_start_migration_node_failure_not_running(contract);
    }

    fn test_register_backup_service_fail_non_participant(mut contract: MpcContract) {
        // sanity check
        assert!(contract.migration_info().is_empty());
        let backup_service_info = BackupServiceInfo {
            public_key: bogus_ed25519_public_key(),
        };

        let non_participant = gen_account_id();
        Environment::new(None, Some(non_participant), None);
        let res = contract.register_backup_service(backup_service_info);
        assert_matches!(
            res.unwrap_err(),
            Error::InvalidState(InvalidState::NotParticipant { .. })
        );
        assert!(contract.migration_info().is_empty());
    }

    #[test]
    fn test_register_backup_service_fail_non_participant_running() {
        let running_state = ProtocolContractState::Running(gen_running_state(NUM_DOMAINS));
        let contract = MpcContract::new_from_protocol_state(running_state);
        test_register_backup_service_fail_non_participant(contract);
    }

    #[test]
    fn test_register_backup_service_fail_non_participant_initializing() {
        let initializing_state =
            ProtocolContractState::Initializing(gen_initializing_state(NUM_DOMAINS, 0).1);
        let contract = MpcContract::new_from_protocol_state(initializing_state);
        test_register_backup_service_fail_non_participant(contract);
    }

    #[test]
    fn test_register_backup_service_fail_non_participant_resharnig() {
        let resharing_state = ProtocolContractState::Resharing(gen_resharing_state(NUM_DOMAINS).1);
        let contract = MpcContract::new_from_protocol_state(resharing_state);
        test_register_backup_service_fail_non_participant(contract);
    }

    fn test_register_backup_service_success(
        participants: &Participants,
        mut contract: MpcContract,
    ) {
        // sanity check
        assert!(contract.migration_info().is_empty());
        let mut expected_migration_state = BTreeMap::new();
        let mut test_env = Environment::new(None, None, None);
        test_env.set_deposit(MINIMUM_NODE_MANAGEMENT_DEPOSIT);
        for (account_id, _, _) in participants.participants() {
            test_env.set_signer(account_id);
            // sanity check
            assert_eq!(
                migration_info(&contract, account_id),
                (account_id.clone(), None, None)
            );
            let backup_service_info = BackupServiceInfo {
                public_key: bogus_ed25519_public_key(),
            };
            let res = contract.register_backup_service(backup_service_info.clone());
            res.expect("Participant should be able to register backup service");
            let expected_res = (account_id.clone(), Some(backup_service_info), None);
            assert_eq!(migration_info(&contract, account_id), expected_res);
            expected_migration_state.insert(expected_res.0, (expected_res.1, expected_res.2));
        }

        let result = contract.migration_info();

        assert_eq!(result, expected_migration_state);
    }

    #[test]
    fn test_register_backup_service_success_running() {
        let running_state = gen_running_state(NUM_DOMAINS);
        let participants = running_state.parameters.participants().clone();
        let running_state = ProtocolContractState::Running(running_state);
        let contract = MpcContract::new_from_protocol_state(running_state);
        test_register_backup_service_success(&participants, contract);
    }

    #[test]
    fn test_register_backup_service_success_resharing() {
        let resharing_state = gen_resharing_state(NUM_DOMAINS).1;
        let participants = resharing_state
            .resharing_key
            .proposed_parameters()
            .participants()
            .clone();
        let resharing_state = ProtocolContractState::Resharing(resharing_state);
        let contract = MpcContract::new_from_protocol_state(resharing_state);
        test_register_backup_service_success(&participants, contract);
    }

    #[test]
    fn test_register_backup_service_success_initializing() {
        let initializing_state = gen_initializing_state(NUM_DOMAINS, 0).1;
        let participants = initializing_state
            .generating_key
            .proposed_parameters()
            .participants()
            .clone();
        let initializing_state = ProtocolContractState::Initializing(initializing_state);
        let contract = MpcContract::new_from_protocol_state(initializing_state);
        test_register_backup_service_success(&participants, contract);
    }

    #[test]
    #[should_panic(expected = "Attached deposit is lower than required")]
    fn start_node_migration__should_reject_when_no_deposit_attached() {
        // Given
        let running_state = gen_running_state(NUM_DOMAINS);
        let account_id = running_state.parameters.participants().participants()[0]
            .0
            .clone();
        let mut contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running_state));
        let mut test_env = Environment::new(None, Some(account_id), None);
        test_env.set_deposit(NearToken::from_yoctonear(0));

        // panics via `require_deposit` before the migration is stored
        // When, Then
        let _ = contract.start_node_migration(gen_random_destination_info());
    }

    #[test]
    #[should_panic(expected = "Attached deposit is lower than required")]
    fn register_backup_service__should_reject_when_no_deposit_attached() {
        // Given
        let running_state = gen_running_state(NUM_DOMAINS);
        let account_id = running_state.parameters.participants().participants()[0]
            .0
            .clone();
        let mut contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running_state));
        let mut test_env = Environment::new(None, Some(account_id), None);
        test_env.set_deposit(NearToken::from_yoctonear(0));
        let backup_service_info = BackupServiceInfo {
            public_key: bogus_ed25519_public_key(),
        };

        // panics via `require_deposit` before the backup service is stored
        // When, Then
        let _ = contract.register_backup_service(backup_service_info);
    }

    #[test]
    fn test_conclude_node_migration_success() {
        let running_state = gen_running_state(NUM_DOMAINS);
        let keyset = running_state.keyset.clone();
        let participants = running_state.parameters.participants().clone();
        let running_state = ProtocolContractState::Running(running_state);
        let mut contract = MpcContract::new_from_protocol_state(running_state);
        for (account_id, expected_participant_id, _) in participants.participants() {
            let destination_node_info = gen_random_destination_info();
            let setup = ConcludeNodeMigrationTestSetup {
                destination_node_info: Some(destination_node_info.clone()),
                attestation_tls_key: destination_node_info
                    .destination_node_info
                    .tls_public_key
                    .clone(),
                signer_account_id: account_id.clone(),
                signer_account_pk: near_sdk::PublicKey::from(
                    destination_node_info.signer_account_pk.clone(),
                ),
                expected_error_check: None,
                expected_post_call_info: Some((
                    *expected_participant_id,
                    destination_node_info
                        .destination_node_info
                        .clone()
                        .into_contract_type(),
                )),
            };
            setup.run(&mut contract, &keyset);
        }
        assert!(contract.node_migrations.get_all().is_empty());
    }

    #[test]
    fn test_conclude_node_migration_invalid_tee() {
        let running_state = gen_running_state(NUM_DOMAINS);
        let keyset = running_state.keyset.clone();
        let participants = running_state.parameters.participants().clone();
        let running_state = ProtocolContractState::Running(running_state);
        let mut contract = MpcContract::new_from_protocol_state(running_state);
        for (account_id, expected_participant_id, expected_participant_info) in
            participants.participants()
        {
            let destination_node_info = gen_random_destination_info();
            let setup = ConcludeNodeMigrationTestSetup {
                destination_node_info: Some(destination_node_info.clone()),
                attestation_tls_key: bogus_ed25519_public_key(),
                signer_account_id: account_id.clone(),
                signer_account_pk: near_sdk::PublicKey::from(
                    destination_node_info.signer_account_pk.clone(),
                ),
                expected_error_check: Some(|k| {
                    matches!(
                        k,
                        Error::InvalidParameters(
                            InvalidParameters::InvalidTeeRemoteAttestation { .. }
                        )
                    )
                }),
                expected_post_call_info: Some((
                    *expected_participant_id,
                    expected_participant_info.clone(),
                )),
            };
            setup.run(&mut contract, &keyset);
        }
    }

    #[test]
    fn test_conclude_node_migration_migration_not_found() {
        let running_state = gen_running_state(NUM_DOMAINS);
        let keyset = running_state.keyset.clone();
        let participants = running_state.parameters.participants().clone();
        let running_state = ProtocolContractState::Running(running_state);
        let mut contract = MpcContract::new_from_protocol_state(running_state);
        for (account_id, expected_participant_id, expected_participant_info) in
            participants.participants()
        {
            let destination_node_info = gen_random_destination_info();
            let setup = ConcludeNodeMigrationTestSetup {
                destination_node_info: None,
                attestation_tls_key: destination_node_info
                    .destination_node_info
                    .tls_public_key
                    .clone(),
                signer_account_id: account_id.clone(),
                signer_account_pk: near_sdk::PublicKey::from(
                    destination_node_info.signer_account_pk.clone(),
                ),
                expected_error_check: Some(|k| {
                    matches!(
                        k,
                        Error::NodeMigrationError(NodeMigrationError::MigrationNotFound)
                    )
                }),
                expected_post_call_info: Some((
                    *expected_participant_id,
                    expected_participant_info.clone(),
                )),
            };
            setup.run(&mut contract, &keyset);
        }
    }

    #[test]
    fn test_conclude_node_migration_keyset_mismatch() {
        let running_state = gen_running_state(NUM_DOMAINS);
        let mut keyset = running_state.keyset.clone();
        keyset.epoch_id = keyset.epoch_id.next();
        let participants = running_state.parameters.participants().clone();
        let running_state = ProtocolContractState::Running(running_state);
        let mut contract = MpcContract::new_from_protocol_state(running_state);
        for (account_id, expected_participant_id, expected_participant_info) in
            participants.participants()
        {
            let destination_node_info = gen_random_destination_info();
            let setup = ConcludeNodeMigrationTestSetup {
                destination_node_info: Some(destination_node_info.clone()),
                attestation_tls_key: destination_node_info
                    .destination_node_info
                    .tls_public_key
                    .clone(),
                signer_account_id: account_id.clone(),
                signer_account_pk: near_sdk::PublicKey::from(
                    destination_node_info.signer_account_pk.clone(),
                ),
                expected_error_check: Some(|k| {
                    matches!(
                        k,
                        Error::NodeMigrationError(NodeMigrationError::KeysetMismatch { .. })
                    )
                }),
                expected_post_call_info: Some((
                    *expected_participant_id,
                    expected_participant_info.clone(),
                )),
            };
            setup.run(&mut contract, &keyset);
        }
    }

    #[test]
    fn test_conclude_node_migration_not_participant() {
        let running_state = gen_running_state(NUM_DOMAINS);
        let keyset = running_state.keyset.clone();
        let running_state = ProtocolContractState::Running(running_state);
        let mut contract = MpcContract::new_from_protocol_state(running_state);
        let non_participant_account_id = gen_account_id();
        let destination_node_info = gen_random_destination_info();
        let setup = ConcludeNodeMigrationTestSetup {
            destination_node_info: Some(destination_node_info.clone()),
            attestation_tls_key: destination_node_info
                .destination_node_info
                .tls_public_key
                .clone(),
            signer_account_id: non_participant_account_id.clone(),
            signer_account_pk: near_sdk::PublicKey::from(
                destination_node_info.signer_account_pk.clone(),
            ),
            expected_error_check: Some(|k| {
                matches!(k, Error::InvalidState(InvalidState::NotParticipant { .. }))
            }),
            expected_post_call_info: None,
        };
        setup.run(&mut contract, &keyset);
    }

    fn test_conclude_node_migration_failure_not_running(
        participants: &Participants,
        contract: &mut MpcContract,
        keyset: &Keyset,
    ) {
        for (account_id, expected_participant_id, expected_participant_info) in
            participants.participants()
        {
            let destination_node_info = gen_random_destination_info();
            let setup = ConcludeNodeMigrationTestSetup {
                destination_node_info: Some(destination_node_info.clone()),
                attestation_tls_key: destination_node_info
                    .destination_node_info
                    .tls_public_key
                    .clone(),
                signer_account_id: account_id.clone(),
                signer_account_pk: near_sdk::PublicKey::from(
                    destination_node_info.signer_account_pk.clone(),
                ),
                expected_error_check: Some(|k| {
                    matches!(
                        k,
                        Error::InvalidState(InvalidState::ProtocolStateNotRunning)
                    )
                }),
                expected_post_call_info: Some((
                    *expected_participant_id,
                    expected_participant_info.clone(),
                )),
            };
            setup.run(contract, keyset);
        }
    }

    #[test]
    fn test_conclude_node_migration_failure_resharing() {
        let (_, resharing_state) = gen_resharing_state(NUM_DOMAINS);

        let keyset = resharing_state.previous_running_state.keyset.clone();
        let participants = resharing_state
            .previous_running_state
            .parameters
            .participants()
            .clone();
        let resharing_state = ProtocolContractState::Resharing(resharing_state);
        let mut contract = MpcContract::new_from_protocol_state(resharing_state);
        test_conclude_node_migration_failure_not_running(&participants, &mut contract, &keyset);
    }

    #[test]
    fn test_conclude_node_migration_failure_initializing() {
        let (_, initializing) = gen_initializing_state(NUM_DOMAINS, 0);

        let keyset = Keyset::new(
            initializing.generating_key.epoch_id(),
            initializing.generated_keys.clone(),
        );
        let participants = initializing
            .generating_key
            .proposed_parameters()
            .participants()
            .clone();
        let initializing_state = ProtocolContractState::Initializing(initializing);
        let mut contract = MpcContract::new_from_protocol_state(initializing_state);
        test_conclude_node_migration_failure_not_running(&participants, &mut contract, &keyset);
    }

    struct ConcludeNodeMigrationTestSetup {
        // a destination node info to store in the migration state
        destination_node_info: Option<DestinationNodeInfo>,
        // the tls key to store for the attestation
        attestation_tls_key: Ed25519PublicKey,
        signer_account_id: AccountId,
        signer_account_pk: near_sdk::PublicKey,
        expected_error_check: Option<fn(&Error) -> bool>,
        expected_post_call_info: Option<(ParticipantId, ParticipantInfo)>,
    }

    impl ConcludeNodeMigrationTestSetup {
        fn setup(&self, contract: &mut MpcContract) {
            if let Some(destination_node_info) = self.destination_node_info.clone() {
                contract.node_migrations.set_destination_node_info(
                    self.signer_account_id.clone(),
                    destination_node_info,
                );
            }
            let valid_participant_attestation = MpcMockAttestation::Valid;

            let tee_upgrade_duration =
                Duration::from_secs(contract.config.tee_upgrade_deadline_duration_seconds);

            let insertion_result = contract.tee_state.verify_and_store_mock(
                NodeId {
                    account_id: self.signer_account_id.clone(),
                    tls_public_key: self.attestation_tls_key.clone(),
                    account_public_key: dtos::Ed25519PublicKey::try_from(&self.signer_account_pk)
                        .expect("test signer_account_pk must be Ed25519"),
                },
                valid_participant_attestation,
                tee_upgrade_duration,
            );
            assert_matches::assert_matches!(
                insertion_result,
                Ok(ParticipantInsertion::NewlyInsertedParticipant)
            );
        }

        pub fn run(&self, contract: &mut MpcContract, keyset: &Keyset) {
            self.setup(contract);
            let mut test_env = Environment::new(None, None, None);
            test_env.set_signer(&self.signer_account_id);
            test_env.set_pk(self.signer_account_pk.clone());

            let res = contract.conclude_node_migration(keyset);

            if let Some(check) = &self.expected_error_check {
                let err = res.unwrap_err();
                assert!(check(&err), "Unexpected error kind: {:?}", err);
            } else {
                res.expect("Concluding a valid migration should succeed");
            }
            if let Some((expected_participant_id, expected_participant_info)) =
                &self.expected_post_call_info
            {
                let res_participants = {
                    match &contract.protocol_state {
                        ProtocolContractState::Running(running) => {
                            running.parameters.participants()
                        }
                        ProtocolContractState::Resharing(resharing) => {
                            resharing.previous_running_state.parameters.participants()
                        }
                        ProtocolContractState::Initializing(initializing) => initializing
                            .generating_key
                            .proposed_parameters()
                            .participants(),
                        _ => panic!("expected different state"),
                    }
                };
                let found_info = res_participants.info(&self.signer_account_id).unwrap();
                assert_eq!(found_info, expected_participant_info);
                let found_id = res_participants.id(&self.signer_account_id).unwrap();
                assert_eq!(&found_id, expected_participant_id);
            }
        }
    }

    #[test]
    pub fn test_cleanup_orphaned_node_migrations() {
        let running_state = gen_running_state(NUM_DOMAINS);
        let participants = running_state.parameters.participants().clone();
        let running_state = ProtocolContractState::Running(running_state);
        let mut contract = MpcContract::new_from_protocol_state(running_state);
        let mut expected_vals = BTreeMap::new();
        for (account_id, _, _) in participants.participants() {
            let destination_node_info = gen_random_destination_info();

            contract
                .node_migrations
                .set_destination_node_info(account_id.clone(), destination_node_info.clone());
            let backup_service_info = BackupServiceInfo {
                public_key: bogus_ed25519_public_key(),
            };
            contract
                .node_migrations
                .set_backup_service_info(account_id.clone(), backup_service_info.clone());
            expected_vals.insert(
                account_id.clone(),
                (Some(backup_service_info), Some(destination_node_info)),
            );
        }
        let destination_node_info = gen_random_destination_info();

        let non_participant_account_id = gen_account_id();
        contract.node_migrations.set_destination_node_info(
            non_participant_account_id.clone(),
            destination_node_info.clone(),
        );
        let backup_service_info = BackupServiceInfo {
            public_key: bogus_ed25519_public_key(),
        };
        contract
            .node_migrations
            .set_backup_service_info(non_participant_account_id.clone(), backup_service_info);

        contract
            .cleanup_orphaned_node_migrations()
            .expect("Cleanup should succeed for valid migrations");

        let result = contract.migration_info();
        assert_eq!(result, expected_vals);
    }
}
