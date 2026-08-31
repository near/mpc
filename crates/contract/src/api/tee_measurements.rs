//! Votes over the measurement sets a node's TEE attestation must match to be
//! accepted by the contract: the MPC node image, the launcher image and its
//! derived compose hashes, and the OS measurements.

use crate::dto_mapping::IntoInterfaceType as _;
use crate::errors::{ConversionError, Error, InvalidState};
use crate::primitives::key_state::AuthenticatedParticipantId;
use crate::state::ProtocolContractState;
use crate::{MpcContract, MpcContractExt};
use near_mpc_contract_interface::types::{self as dtos};
use near_sdk::{env, log, near};
use std::time::Duration;

#[near]
impl MpcContract {
    #[handle_result]
    pub fn vote_code_hash(&mut self, code_hash: dtos::NodeImageHash) -> Result<(), Error> {
        log!(
            "vote_code_hash: signer={}, code_hash={:?}",
            env::signer_account_id(),
            code_hash,
        );
        self.voter_or_panic();

        let threshold_parameters = self.protocol_state.threshold_parameters_or_panic();

        let participant = AuthenticatedParticipantId::new(threshold_parameters.participants())?;
        let count = self.tee_state.vote(code_hash, &participant).count_for(|p| {
            threshold_parameters
                .participants()
                .is_participant_given_participant_id(&p.get())
        });
        let votes = u64::try_from(count).map_err(|e| ConversionError::DataConversion {
            reason: format!("vote count {count} does not fit in u64: {e}"),
        })?;
        log!("total votes for proposal: {}", votes);

        let tee_upgrade_deadline_duration =
            Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds);

        // If the vote threshold is met and the new Docker hash is allowed by the TEE's RTMR3,
        // update the state
        if votes >= self.threshold()?.value() {
            self.tee_state
                .whitelist_tee_proposal(code_hash, tee_upgrade_deadline_duration);
        }

        Ok(())
    }

    /// Vote to add a new launcher image hash to the allowed set. Requires threshold votes.
    /// When the threshold is reached, compose hashes are automatically derived for all
    /// currently allowed MPC image hashes.
    #[handle_result]
    pub fn vote_add_launcher_hash(
        &mut self,
        launcher_hash: dtos::LauncherImageHash,
    ) -> Result<(), Error> {
        log!(
            "vote_add_launcher_hash: signer={}, launcher_hash={:?}",
            env::signer_account_id(),
            launcher_hash,
        );
        self.voter_or_panic();

        let threshold_parameters = self.protocol_state.threshold_parameters_or_panic();

        let participant = AuthenticatedParticipantId::new(threshold_parameters.participants())?;
        let action = dtos::LauncherVoteAction::Add(launcher_hash);
        let count = self
            .tee_state
            .vote_launcher(action, &participant)
            .count_for(|p| {
                threshold_parameters
                    .participants()
                    .is_participant_given_participant_id(&p.get())
            });
        let votes = u64::try_from(count).map_err(|e| ConversionError::DataConversion {
            reason: format!("vote count {count} does not fit in u64: {e}"),
        })?;
        log!("total launcher votes for action: {}", votes);

        let tee_upgrade_deadline_duration =
            Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds);
        let launcher_unused_ttl = Duration::from_secs(self.config.launcher_hash_unused_ttl_seconds);

        if votes >= self.threshold()?.value() {
            let outcome = self.tee_state.add_launcher_image(
                launcher_hash,
                tee_upgrade_deadline_duration,
                launcher_unused_ttl,
            );
            log!("launcher hash {:?}: {:?}", outcome, launcher_hash);
        }

        Ok(())
    }

    /// Vote to remove a launcher image hash from the allowed set. Requires ALL participants
    /// to vote for removal, since this invalidates attestations of nodes running that launcher.
    #[handle_result]
    pub fn vote_remove_launcher_hash(
        &mut self,
        launcher_hash: dtos::LauncherImageHash,
    ) -> Result<(), Error> {
        log!(
            "vote_remove_launcher_hash: signer={}, launcher_hash={:?}",
            env::signer_account_id(),
            launcher_hash,
        );
        self.voter_or_panic();

        let threshold_parameters = self.protocol_state.threshold_parameters_or_panic();

        let participant = AuthenticatedParticipantId::new(threshold_parameters.participants())?;
        let action = dtos::LauncherVoteAction::Remove(launcher_hash);
        let count = self
            .tee_state
            .vote_launcher(action, &participant)
            .count_for(|p| {
                threshold_parameters
                    .participants()
                    .is_participant_given_participant_id(&p.get())
            });
        let votes = u64::try_from(count).map_err(|e| ConversionError::DataConversion {
            reason: format!("vote count {count} does not fit in u64: {e}"),
        })?;
        log!("total launcher votes for action: {}", votes);

        // Removal requires ALL participants to vote
        let total_participants = threshold_parameters.participants().len() as u64;
        if votes >= total_participants {
            let removed = self.tee_state.remove_launcher_image(&launcher_hash);
            log!("launcher hash remove result: {}", removed);
        }

        Ok(())
    }

    /// Vote to add a new OS measurement set to the allowed list. Requires threshold votes.
    #[handle_result]
    pub fn vote_add_os_measurement(
        &mut self,
        measurement: dtos::ExpectedMeasurements,
    ) -> Result<(), Error> {
        log!(
            "vote_add_os_measurement: signer={}, measurement={:?}",
            env::signer_account_id(),
            measurement,
        );
        self.voter_or_panic();

        let threshold_parameters = self.protocol_state.threshold_parameters_or_panic();

        let participant = AuthenticatedParticipantId::new(threshold_parameters.participants())?;
        let action = dtos::MeasurementVoteAction::Add(measurement.clone());
        let count = self
            .tee_state
            .vote_measurement(action, &participant)
            .count_for(|p| {
                threshold_parameters
                    .participants()
                    .is_participant_given_participant_id(&p.get())
            });
        let votes = u64::try_from(count).map_err(|e| ConversionError::DataConversion {
            reason: format!("vote count {count} does not fit in u64: {e}"),
        })?;
        log!("total measurement votes for action: {}", votes);

        if votes >= self.threshold()?.value() {
            let added = self.tee_state.add_measurement(measurement);
            log!("OS measurement add result: {}", added);
        }

        Ok(())
    }

    /// Vote to remove an OS measurement set from the allowed list. Requires ALL participants
    /// to vote for removal.
    #[handle_result]
    pub fn vote_remove_os_measurement(
        &mut self,
        measurement: dtos::ExpectedMeasurements,
    ) -> Result<(), Error> {
        log!(
            "vote_remove_os_measurement: signer={}, measurement={:?}",
            env::signer_account_id(),
            measurement,
        );
        self.voter_or_panic();

        let threshold_parameters = self.protocol_state.threshold_parameters_or_panic();

        let participant = AuthenticatedParticipantId::new(threshold_parameters.participants())?;
        let action = dtos::MeasurementVoteAction::Remove(measurement.clone());
        let count = self
            .tee_state
            .vote_measurement(action, &participant)
            .count_for(|p| {
                threshold_parameters
                    .participants()
                    .is_participant_given_participant_id(&p.get())
            });
        let votes = u64::try_from(count).map_err(|e| ConversionError::DataConversion {
            reason: format!("vote count {count} does not fit in u64: {e}"),
        })?;
        log!("total measurement votes for action: {}", votes);

        // Removal requires ALL participants to vote
        let total_participants = threshold_parameters.participants().len() as u64;
        if votes >= total_participants {
            let removed = self.tee_state.remove_measurement(&measurement);
            log!("OS measurement remove result: {}", removed);
        }

        Ok(())
    }

    /// Pending OS measurement votes, keyed by the proposal hash of the [`dtos::MeasurementVoteAction`].
    pub fn os_measurement_votes(&self) -> dtos::MeasurementVotes {
        log!("os_measurement_votes");
        (&self.tee_state.measurement_votes).into_dto_type()
    }

    /// Returns all currently allowed OS measurements.
    pub fn allowed_os_measurements(&self) -> Vec<dtos::ExpectedMeasurements> {
        log!("allowed_os_measurements");
        self.tee_state.get_allowed_measurements()
    }

    /// Returns all allowed code hashes in descending order of their expiry
    /// date. Note that the expiration depends on the contract configuration
    /// (c.f. [`dtos::Config::tee_upgrade_deadline_duration_seconds`]).
    pub fn allowed_docker_image_hashes(&self) -> Vec<dtos::AllowedMpcDockerImageHash> {
        let tee_upgrade_deadline_duration =
            Duration::from_secs(self.config.tee_upgrade_deadline_duration_seconds);

        let mut entries = self
            .tee_state
            .get_allowed_mpc_docker_images(tee_upgrade_deadline_duration);
        entries.reverse();
        entries
    }

    pub fn allowed_launcher_compose_hashes(&self) -> Vec<dtos::LauncherDockerComposeHash> {
        self.tee_state.get_allowed_launcher_compose_hashes()
    }

    pub fn allowed_launcher_image_hashes(&self) -> Vec<dtos::LauncherImageHash> {
        self.tee_state.get_allowed_launcher_hashes()
    }

    /// Pending launcher hash votes, keyed by the proposal hash of the [`dtos::LauncherVoteAction`].
    pub fn launcher_hash_votes(&self) -> dtos::LauncherHashVotes {
        (&self.tee_state.launcher_votes).into_dto_type()
    }

    /// Pending code hash votes, keyed by the [`dtos::NodeImageHash`] voted for.
    pub fn code_hash_votes(&self) -> dtos::CodeHashesVotes {
        (&self.tee_state.votes).into_dto_type()
    }

    /// Private endpoint to drop votes cast by non-participants after resharing.
    /// Attestation cleanup is handled separately by [`MpcContract::clean_invalid_attestations`].
    #[private]
    #[handle_result]
    pub fn clean_tee_status(&mut self) -> Result<(), Error> {
        log!("clean_tee_status: signer={}", env::signer_account_id());

        let participants = match &self.protocol_state {
            ProtocolContractState::Running(state) => state.parameters.participants(),
            _ => {
                return Err(InvalidState::ProtocolStateNotRunning.into());
            }
        };

        self.tee_state.clean_non_participant_votes(participants);
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use super::{Duration, MpcContract, ProtocolContractState};
    use crate::api::test_utils::{NUM_DOMAINS, NUM_GENERATED_DOMAINS, setup_tee_test_contract};
    use crate::primitives::votes::ProposalHashEncoding;
    use crate::state::test_utils::{
        gen_initializing_state, gen_resharing_state, gen_running_state,
    };
    use crate::tee::proposal::get_docker_compose_hash;
    use mpc_primitives::hash::{KeyProviderEventDigest, MrtdHash, Rtmr0Hash, Rtmr1Hash, Rtmr2Hash};
    use near_mpc_contract_interface::types::{
        self as dtos, ExpectedMeasurements, LauncherVoteAction, MeasurementVoteAction,
    };
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use rstest::rstest;

    #[rstest]
    #[case(ProtocolContractState::Running(gen_running_state(NUM_DOMAINS)))]
    #[case(ProtocolContractState::Resharing(gen_resharing_state(NUM_DOMAINS).1))]
    #[case(ProtocolContractState::Initializing(gen_initializing_state(NUM_DOMAINS, NUM_GENERATED_DOMAINS).1))]
    fn test_contract_stores_allowed_hashes(#[case] protocol_state: ProtocolContractState) {
        const CURRENT_BLOCK_TIME_STAMP: u64 = 10;
        let mut contract = MpcContract::new_from_protocol_state(protocol_state);
        let code_hash = [9; 32];

        let participant_account_ids: Vec<_> = contract
            .protocol_state
            .threshold_parameters()
            .unwrap()
            .participants()
            .participants()
            .iter()
            .map(|(account_id, _, _)| account_id.clone())
            .collect();

        for participant_account_id in participant_account_ids {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(participant_account_id.clone())
                    .predecessor_account_id(participant_account_id.clone())
                    .block_timestamp(CURRENT_BLOCK_TIME_STAMP)
                    .build()
            );

            contract
                .vote_code_hash(code_hash.into())
                .expect("vote succeeds");
        }

        let allowed_docker_image_hashes: Vec<dtos::NodeImageHash> = contract
            .tee_state
            .get_allowed_mpc_docker_images(Duration::from_secs(10))
            .into_iter()
            .map(|allowed_image_hash| allowed_image_hash.image_hash)
            .collect();

        assert_eq!(
            allowed_docker_image_hashes,
            vec![dtos::NodeImageHash::from(code_hash)]
        )
    }

    fn make_launcher_hash(byte: u8) -> dtos::LauncherImageHash {
        dtos::LauncherImageHash::from([byte; 32])
    }

    #[test]
    fn test_vote_add_launcher_hash_reaches_threshold() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let launcher_hash = make_launcher_hash(0xAA);

        // First 2 votes (below threshold of 3) — launcher should NOT be added yet
        for (account_id, _, _) in &participant_list[0..2] {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_add_launcher_hash(launcher_hash)
                .expect("vote should succeed");
        }
        assert!(
            contract.allowed_launcher_image_hashes().is_empty(),
            "launcher hash should not be added before threshold"
        );

        // 3rd vote reaches threshold — launcher should be added
        let (account_id, _, _) = &participant_list[2];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id.clone())
                .build()
        );
        contract
            .vote_add_launcher_hash(launcher_hash)
            .expect("vote should succeed");

        let allowed = contract.allowed_launcher_image_hashes();
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0], launcher_hash);
    }

    #[test]
    fn test_vote_add_launcher_hash_duplicate_vote_is_idempotent() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let launcher_hash = make_launcher_hash(0xBB);

        let (account_id, _, _) = &participant_list[0];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id.clone())
                .build()
        );

        // Same participant votes twice — should count as 1 vote
        contract
            .vote_add_launcher_hash(launcher_hash)
            .expect("vote should succeed");
        contract
            .vote_add_launcher_hash(launcher_hash)
            .expect("duplicate vote should succeed");

        assert!(
            contract.allowed_launcher_image_hashes().is_empty(),
            "duplicate vote should not double-count"
        );
    }

    #[test]
    fn test_vote_remove_launcher_hash_requires_unanimity() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let launcher_hash = make_launcher_hash(0xCC);
        let launcher_hash_2 = make_launcher_hash(0xDD);

        // Add two launcher hashes so removal of one doesn't hit the "last entry" guard
        for hash in [launcher_hash, launcher_hash_2] {
            for (account_id, _, _) in participant_list {
                testing_env!(
                    VMContextBuilder::new()
                        .signer_account_id(account_id.clone())
                        .predecessor_account_id(account_id.clone())
                        .build()
                );
                contract
                    .vote_add_launcher_hash(hash)
                    .expect("add vote should succeed");
            }
        }
        assert_eq!(contract.allowed_launcher_image_hashes().len(), 2);

        // Now vote to remove — first 3 votes (not all 4) should NOT remove
        for (account_id, _, _) in &participant_list[0..3] {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_remove_launcher_hash(launcher_hash)
                .expect("remove vote should succeed");
        }
        assert_eq!(
            contract.allowed_launcher_image_hashes().len(),
            2,
            "launcher hash should not be removed before unanimity"
        );

        // 4th vote — unanimous, should remove
        let (account_id, _, _) = &participant_list[3];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id.clone())
                .build()
        );
        contract
            .vote_remove_launcher_hash(launcher_hash)
            .expect("remove vote should succeed");

        assert_eq!(
            contract.allowed_launcher_image_hashes().len(),
            1,
            "launcher hash should be removed after unanimity"
        );
    }

    #[test]
    fn test_cannot_remove_last_launcher_hash() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let launcher_hash = make_launcher_hash(0xCC);

        // Add a single launcher hash
        for (account_id, _, _) in participant_list {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_add_launcher_hash(launcher_hash)
                .expect("add vote should succeed");
        }
        assert_eq!(contract.allowed_launcher_image_hashes().len(), 1);

        // All 4 vote to remove — should still not remove because it's the last one
        for (account_id, _, _) in participant_list {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_remove_launcher_hash(launcher_hash)
                .expect("remove vote should succeed");
        }
        assert_eq!(
            contract.allowed_launcher_image_hashes().len(),
            1,
            "last launcher hash should not be removable"
        );
    }

    #[test]
    fn test_vote_add_launcher_hash_derives_compose_hashes() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let launcher_hash = make_launcher_hash(0xDD);

        // First approve an MPC image hash so compose hashes can be derived
        let mpc_hash_bytes: [u8; 32] = [0x11; 32];
        let mpc_hash = mpc_primitives::hash::NodeImageHash::from(mpc_hash_bytes);
        let block_ts = 1_000_000_000u64;

        for (account_id, _, _) in participant_list {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .block_timestamp(block_ts)
                    .build()
            );
            contract
                .vote_code_hash(mpc_hash)
                .expect("mpc vote should succeed");
        }

        // Now add a launcher hash — should auto-derive compose hashes
        for (account_id, _, _) in &participant_list[0..3] {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .block_timestamp(block_ts)
                    .build()
            );
            contract
                .vote_add_launcher_hash(launcher_hash)
                .expect("launcher vote should succeed");
        }

        let compose_hashes = contract.allowed_launcher_compose_hashes();
        assert_eq!(
            compose_hashes.len(),
            1,
            "should have 1 compose hash (1 launcher x 1 mpc)"
        );
    }

    #[test]
    fn test_allowed_launcher_image_hashes_view_returns_empty_initially() {
        let (contract, _participants, _first) = setup_tee_test_contract(3, 2);
        assert!(contract.allowed_launcher_image_hashes().is_empty());
    }

    #[test]
    fn test_vote_add_launcher_hash_clears_votes_on_success() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let launcher_hash = make_launcher_hash(0xEE);

        // Vote with 3 participants to reach threshold
        for (account_id, _, _) in &participant_list[0..3] {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_add_launcher_hash(launcher_hash)
                .expect("vote should succeed");
        }
        assert_eq!(contract.allowed_launcher_image_hashes().len(), 1);

        // Votes should be cleared — voting for a second hash should start from 0
        let launcher_hash_2 = make_launcher_hash(0xFF);
        let (account_id, _, _) = &participant_list[0];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id.clone())
                .build()
        );
        contract
            .vote_add_launcher_hash(launcher_hash_2)
            .expect("vote should succeed");

        // Only 1 vote for hash_2, should not be added yet
        assert_eq!(
            contract.allowed_launcher_image_hashes().len(),
            1,
            "second hash should not be added with only 1 vote"
        );
    }

    /// Tests the [`MpcContract::launcher_hash_votes`] view method:
    /// 1. Starts empty
    /// 2. After each vote, reflects the voter count under the proposal hash of the action
    /// 3. After threshold is reached, votes are cleared
    #[test]
    fn test_launcher_hash_votes_view() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let launcher_hash = make_launcher_hash(0xCC);
        let expected_proposal = LauncherVoteAction::Add(launcher_hash).proposal_hash();

        assert!(contract.launcher_hash_votes().is_empty());

        // First vote
        let (account_0, _, _) = &participant_list[0];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_0.clone())
                .predecessor_account_id(account_0.clone())
                .build()
        );
        contract
            .vote_add_launcher_hash(launcher_hash)
            .expect("vote should succeed");

        let votes = contract.launcher_hash_votes();
        assert_eq!(votes.len(), 1);
        assert_eq!(votes[&expected_proposal].len(), 1);

        // Second vote
        let (account_1, _, _) = &participant_list[1];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_1.clone())
                .predecessor_account_id(account_1.clone())
                .build()
        );
        contract
            .vote_add_launcher_hash(launcher_hash)
            .expect("vote should succeed");

        let votes = contract.launcher_hash_votes();
        assert_eq!(votes.len(), 1);
        assert_eq!(votes[&expected_proposal].len(), 2);

        // Third vote reaches threshold — votes should be cleared
        let (account_2, _, _) = &participant_list[2];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_2.clone())
                .predecessor_account_id(account_2.clone())
                .build()
        );
        contract
            .vote_add_launcher_hash(launcher_hash)
            .expect("vote should succeed");

        assert!(
            contract.launcher_hash_votes().is_empty(),
            "votes should be cleared after threshold reached"
        );
    }

    /// Tests the [`MpcContract::code_hash_votes`] view method:
    /// 1. Starts empty
    /// 2. After each vote, reflects the voter count under the proposal hash of the code hash
    /// 3. After threshold is reached, votes are cleared
    #[test]
    fn test_code_hash_votes_view() {
        let num_participants = 4;
        let threshold = 3;
        let (mut contract, participants, _) = setup_tee_test_contract(num_participants, threshold);
        let participant_list = participants.participants();
        let code_hash = dtos::NodeImageHash::from([0xAB; 32]);

        assert!(contract.code_hash_votes().is_empty());

        for (i, (account, _, _)) in participant_list[..threshold as usize].iter().enumerate() {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account.clone())
                    .predecessor_account_id(account.clone())
                    .build()
            );
            contract
                .vote_code_hash(code_hash)
                .expect("vote should succeed");

            let votes = contract.code_hash_votes();
            if i < (threshold - 1) as usize {
                assert_eq!(votes.len(), 1);
                assert_eq!(votes[&code_hash].len(), i + 1);
            } else {
                assert!(
                    votes.is_empty(),
                    "votes should be cleared after threshold reached"
                );
            }
        }
    }

    #[test]
    fn test_new_mpc_image_derives_compose_for_existing_launchers() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let launcher_hash = make_launcher_hash(0xAA);
        let block_ts = 1_000_000_000u64;

        // First approve an MPC image
        let mpc_hash_1 = mpc_primitives::hash::NodeImageHash::from([0x11; 32]);
        for (account_id, _, _) in participant_list {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .block_timestamp(block_ts)
                    .build()
            );
            contract
                .vote_code_hash(mpc_hash_1)
                .expect("mpc vote should succeed");
        }

        // Add a launcher hash
        for (account_id, _, _) in &participant_list[0..3] {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .block_timestamp(block_ts)
                    .build()
            );
            contract
                .vote_add_launcher_hash(launcher_hash)
                .expect("launcher vote should succeed");
        }
        assert_eq!(contract.allowed_launcher_compose_hashes().len(), 1);

        // Now vote in a second MPC image — should auto-derive a new compose hash
        let mpc_hash_2 = mpc_primitives::hash::NodeImageHash::from([0x22; 32]);
        for (account_id, _, _) in participant_list {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .block_timestamp(block_ts)
                    .build()
            );
            contract
                .vote_code_hash(mpc_hash_2)
                .expect("mpc vote 2 should succeed");
        }

        assert_eq!(
            contract.allowed_launcher_compose_hashes().len(),
            2,
            "should have 2 compose hashes (1 launcher x 2 mpc images)"
        );
    }

    /// Tests the full launcher compose hash lifecycle with MPC hash expiry:
    /// 1. Add M1, add L1 → compose: {L1,M1}
    /// 2. Add M2 → compose: {L1,M1}, {L1,M2}
    /// 3. Advance time past M2's deadline so M1 is fully expired
    ///    (allowed_images keeps the last expired entry as cutoff, so M1 only
    ///    drops when M2's grace period also passes)
    /// 4. Stored compose hashes persist — still {L1,M1}, {L1,M2}
    /// 5. Add L2 → paired only with valid M2, not expired M1
    /// 6. Add M3 → paired with both L1 and L2
    /// 7. Final: {L1,M1}, {L1,M2}, {L1,M3}, {L2,M2}, {L2,M3}
    ///    Note: {L2,M1} is NOT present since M1 was expired when L2 was added
    #[test]
    fn test_launcher_compose_lifecycle_with_mpc_expiry() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let sec = 1_000_000_000u64;
        let day = 24 * 60 * 60 * sec;
        let upgrade_deadline = 7 * day;
        let t0 = sec;

        let vote_mpc = |contract: &mut MpcContract, hash: dtos::NodeImageHash, ts: u64| {
            for (account_id, _, _) in participant_list {
                testing_env!(
                    VMContextBuilder::new()
                        .signer_account_id(account_id.clone())
                        .predecessor_account_id(account_id.clone())
                        .block_timestamp(ts)
                        .build()
                );
                contract
                    .vote_code_hash(hash)
                    .expect("mpc vote should succeed");
            }
        };

        let vote_launcher = |contract: &mut MpcContract, hash: dtos::LauncherImageHash, ts: u64| {
            for (account_id, _, _) in &participant_list[0..3] {
                testing_env!(
                    VMContextBuilder::new()
                        .signer_account_id(account_id.clone())
                        .predecessor_account_id(account_id.clone())
                        .block_timestamp(ts)
                        .build()
                );
                contract
                    .vote_add_launcher_hash(hash)
                    .expect("launcher vote should succeed");
            }
        };

        let l1 = make_launcher_hash(0xA1);
        let l2 = make_launcher_hash(0xA2);
        let m1 = dtos::NodeImageHash::from([0x11; 32]);
        let m2 = dtos::NodeImageHash::from([0x22; 32]);
        let m3 = dtos::NodeImageHash::from([0x33; 32]);

        vote_mpc(&mut contract, m1, t0);
        vote_launcher(&mut contract, l1, t0);
        assert_eq!(contract.allowed_launcher_compose_hashes().len(), 1);

        let t1 = t0 + day;
        vote_mpc(&mut contract, m2, t1);
        assert_eq!(contract.allowed_launcher_compose_hashes().len(), 2);

        let t2 = t1 + upgrade_deadline + sec;
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(participant_list[0].0.clone())
                .predecessor_account_id(participant_list[0].0.clone())
                .block_timestamp(t2)
                .build()
        );
        assert_eq!(
            contract.allowed_launcher_compose_hashes().len(),
            2,
            "stored compose hashes persist even after MPC hash expires"
        );

        vote_launcher(&mut contract, l2, t2);
        assert_eq!(
            contract.allowed_launcher_compose_hashes().len(),
            3,
            "L2 paired only with valid M2, not expired M1"
        );

        vote_mpc(&mut contract, m3, t2);
        assert_eq!(
            contract.allowed_launcher_compose_hashes().len(),
            5,
            "M3 paired with both L1 and L2"
        );

        let compose_hashes = contract.allowed_launcher_compose_hashes();
        assert!(compose_hashes.contains(&get_docker_compose_hash(&l1, &m1)));
        assert!(compose_hashes.contains(&get_docker_compose_hash(&l1, &m2)));
        assert!(compose_hashes.contains(&get_docker_compose_hash(&l1, &m3)));
        assert!(compose_hashes.contains(&get_docker_compose_hash(&l2, &m2)));
        assert!(compose_hashes.contains(&get_docker_compose_hash(&l2, &m3)));
        assert!(!compose_hashes.contains(&get_docker_compose_hash(&l2, &m1)));
    }

    fn make_measurement(byte: u8) -> ExpectedMeasurements {
        ExpectedMeasurements {
            mrtd: MrtdHash::from([byte; 48]),
            rtmr0: Rtmr0Hash::from([byte.wrapping_add(1); 48]),
            rtmr1: Rtmr1Hash::from([byte.wrapping_add(2); 48]),
            rtmr2: Rtmr2Hash::from([byte.wrapping_add(3); 48]),
            key_provider_event_digest: KeyProviderEventDigest::from([byte.wrapping_add(4); 48]),
        }
    }

    /// Tests that adding an OS measurement requires threshold votes and that
    /// duplicate measurements are rejected.
    #[test]
    fn test_vote_add_os_measurement_threshold() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let measurement = make_measurement(0xAA);

        // First 2 votes — below threshold (3)
        for (account_id, _, _) in &participant_list[0..2] {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_add_os_measurement(measurement.clone())
                .expect("add vote should succeed");
        }
        assert!(
            contract.allowed_os_measurements().is_empty(),
            "measurement should not be added before threshold"
        );

        // 3rd vote — threshold reached
        let (account_id, _, _) = &participant_list[2];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id.clone())
                .build()
        );
        contract
            .vote_add_os_measurement(measurement.clone())
            .expect("add vote should succeed");
        assert_eq!(contract.allowed_os_measurements().len(), 1);
        assert_eq!(contract.allowed_os_measurements()[0], measurement);

        // Voting for the same measurement again should not duplicate
        for (account_id, _, _) in &participant_list[0..3] {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_add_os_measurement(measurement.clone())
                .expect("add vote should succeed");
        }
        assert_eq!(
            contract.allowed_os_measurements().len(),
            1,
            "duplicate measurement should not be added"
        );
    }

    /// Tests that removing an OS measurement requires unanimity and that
    /// the last measurement cannot be removed.
    #[test]
    fn test_vote_remove_os_measurement_unanimity() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let measurement_1 = make_measurement(0xAA);
        let measurement_2 = make_measurement(0xBB);

        // Add two measurements
        for m in [&measurement_1, &measurement_2] {
            for (account_id, _, _) in participant_list {
                testing_env!(
                    VMContextBuilder::new()
                        .signer_account_id(account_id.clone())
                        .predecessor_account_id(account_id.clone())
                        .build()
                );
                contract
                    .vote_add_os_measurement(m.clone())
                    .expect("add vote should succeed");
            }
        }
        assert_eq!(contract.allowed_os_measurements().len(), 2);

        // 3 votes to remove — not enough (need all 4)
        for (account_id, _, _) in &participant_list[0..3] {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_remove_os_measurement(measurement_1.clone())
                .expect("remove vote should succeed");
        }
        assert_eq!(
            contract.allowed_os_measurements().len(),
            2,
            "measurement should not be removed before unanimity"
        );

        // 4th vote — unanimous, should remove
        let (account_id, _, _) = &participant_list[3];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id.clone())
                .build()
        );
        contract
            .vote_remove_os_measurement(measurement_1.clone())
            .expect("remove vote should succeed");
        assert_eq!(contract.allowed_os_measurements().len(), 1);
        assert_eq!(contract.allowed_os_measurements()[0], measurement_2);
    }

    /// Tests that the last OS measurement cannot be removed.
    #[test]
    fn test_cannot_remove_last_os_measurement() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let measurement = make_measurement(0xAA);

        // Add a single measurement
        for (account_id, _, _) in participant_list {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_add_os_measurement(measurement.clone())
                .expect("add vote should succeed");
        }
        assert_eq!(contract.allowed_os_measurements().len(), 1);

        // All 4 vote to remove — should not remove because it's the last one
        for (account_id, _, _) in participant_list {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_remove_os_measurement(measurement.clone())
                .expect("remove vote should succeed");
        }
        assert_eq!(
            contract.allowed_os_measurements().len(),
            1,
            "last OS measurement should not be removable"
        );
    }

    /// Tests the os_measurement_votes view method returns correct vote data.
    #[test]
    fn test_os_measurement_votes_view() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let measurement = make_measurement(0xCC);

        // Initially empty
        assert!(contract.os_measurement_votes().is_empty());

        // Cast one vote
        let (account_id, _, _) = &participant_list[0];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id.clone())
                .build()
        );
        contract
            .vote_add_os_measurement(measurement.clone())
            .expect("add vote should succeed");

        let votes = contract.os_measurement_votes();
        let expected_proposal = MeasurementVoteAction::Add(measurement).proposal_hash();
        assert_eq!(votes.len(), 1);
        assert_eq!(votes[&expected_proposal].len(), 1);
    }

    /// Tests the allowed_os_measurements view method returns the full structs
    /// with correct field values after adding measurements.
    #[test]
    fn test_allowed_os_measurements_view() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let measurement_1 = make_measurement(0xAA);
        let measurement_2 = make_measurement(0xBB);

        // Initially empty
        assert!(contract.allowed_os_measurements().is_empty());

        // Add first measurement (3 votes = threshold)
        for (account_id, _, _) in &participant_list[0..3] {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_add_os_measurement(measurement_1.clone())
                .expect("add vote should succeed");
        }

        let allowed = contract.allowed_os_measurements();
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0], measurement_1);

        // Add second measurement
        for (account_id, _, _) in &participant_list[0..3] {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_add_os_measurement(measurement_2.clone())
                .expect("add vote should succeed");
        }

        let allowed = contract.allowed_os_measurements();
        assert_eq!(allowed.len(), 2);
        assert_eq!(allowed[0], measurement_1);
        assert_eq!(allowed[1], measurement_2);
    }

    /// Tests that votes are cleared after a successful measurement add,
    /// so a subsequent vote starts from scratch.
    #[test]
    fn test_vote_add_os_measurement_clears_votes_on_success() {
        let (mut contract, participants, _first) = setup_tee_test_contract(4, 3);
        let participant_list = participants.participants();
        let measurement = make_measurement(0xAA);

        // Vote with 3 participants to reach threshold
        for (account_id, _, _) in &participant_list[0..3] {
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );
            contract
                .vote_add_os_measurement(measurement.clone())
                .expect("vote should succeed");
        }
        assert_eq!(contract.allowed_os_measurements().len(), 1);

        // Votes should be cleared — voting for a second measurement should start from 0
        let measurement_2 = make_measurement(0xBB);
        let (account_id, _, _) = &participant_list[0];
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id.clone())
                .build()
        );
        contract
            .vote_add_os_measurement(measurement_2.clone())
            .expect("vote should succeed");

        // Only 1 vote for measurement_2, should not be added yet
        assert_eq!(
            contract.allowed_os_measurements().len(),
            1,
            "second measurement should not be added with only 1 vote"
        );
    }

    /// Tests JSON serialization roundtrip for [`ExpectedMeasurements`].
    /// Verifies hex encoding/decoding of 48-byte fields works correctly.
    #[test]
    fn test_contract_expected_measurements_json_roundtrip() {
        let measurement = make_measurement(0xAA);
        let json = serde_json::to_string(&measurement).expect("serialize to JSON");
        let deserialized: ExpectedMeasurements =
            serde_json::from_str(&json).expect("deserialize from JSON");
        assert_eq!(measurement, deserialized);

        // Verify the JSON contains hex strings, not raw byte arrays
        assert!(json.contains("aa"), "JSON should contain hex-encoded bytes");
        assert!(
            !json.contains('['),
            "JSON should not contain array brackets"
        );
    }
}
