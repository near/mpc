//! Contract-update proposals: proposing, voting, and applying code and config
//! updates, plus sweeping votes from departed participants.

use crate::api::common::refund_to;
use crate::config::Config;
use crate::dto_mapping::IntoInterfaceType;
use crate::errors::{Error, InvalidParameters, InvalidState};
use crate::state::ProtocolContractState;
use crate::update::{ProposedUpdates, Update, UpdateId};
use crate::{MpcContract, MpcContractExt};
use near_mpc_contract_interface::types::{self as dtos, ProposeUpdateArgs};
use near_sdk::{Gas, env, log, near};

#[near]
impl MpcContract {
    /// Propose update to either code or config, but not both of them at the same time.
    #[payable]
    #[handle_result]
    pub fn propose_update(
        &mut self,
        #[serializer(borsh)] args: ProposeUpdateArgs,
    ) -> Result<UpdateId, Error> {
        // Only voters can propose updates:
        let proposer = self.voter_or_panic();
        let payload_bytes =
            args.payload_bytes()
                .map_err(|err| InvalidParameters::MalformedPayload {
                    reason: err.to_string(),
                })?;
        let update: Update = args.try_into()?;

        let attached = env::attached_deposit();
        let required = ProposedUpdates::required_deposit(payload_bytes).map_err(|err| {
            InvalidParameters::MalformedPayload {
                reason: err.to_string(),
            }
        })?;
        if attached < required {
            return Err(InvalidParameters::InsufficientDeposit {
                attached: attached.as_yoctonear(),
                required: required.as_yoctonear(),
            }
            .into());
        }

        let id = self.proposed_updates.propose(update);

        log!(
            "propose_update: signer={}, id={:?}",
            env::signer_account_id(),
            id,
        );

        // Refund the difference if the proposer attached more than required.
        if let Some(diff) = attached.checked_sub(required) {
            refund_to(&proposer, diff);
        }

        Ok(id)
    }

    /// Vote for a proposed update given the [`UpdateId`] of the update.
    ///
    /// Returns `Ok(true)` if the amount of voters surpassed the threshold and the update was
    /// executed. Returns `Ok(false)` if the amount of voters did not surpass the threshold.
    /// Returns [`Error`] if the update was not found or if the voter is not a participant
    /// in the protocol.
    #[handle_result]
    pub fn vote_update(&mut self, id: UpdateId) -> Result<bool, Error> {
        log!(
            "vote_update: signer={}, id={:?}",
            env::signer_account_id(),
            id,
        );

        let ProtocolContractState::Running(running_state) = &self.protocol_state else {
            env::panic_str("protocol must be in running state");
        };

        let threshold = self.threshold()?;

        let voter = self.voter_or_panic();
        if self.proposed_updates.vote(&id, voter).is_none() {
            return Err(InvalidParameters::UpdateNotFound.into());
        }

        // Filter votes to only count current participants voting for this specific update.
        // This ensures correctness even if the cleanup promise in MpcContract::vote_reshared() fails.
        let valid_votes_count = running_state
            .parameters
            .participants()
            .participants()
            .iter()
            .filter(|(account_id, _, _)| {
                self.proposed_updates
                    .vote_by_participant
                    .get(account_id)
                    .is_some_and(|voted_id| *voted_id == id)
            })
            .count();

        // Not enough votes from current participants, wait for more.
        if (valid_votes_count as u64) < threshold.value() {
            return Ok(false);
        }

        let update_gas_deposit = Gas::from_tgas(self.config.contract_upgrade_deposit_tera_gas);

        let Some(_promise) = self.proposed_updates.do_update(&id, update_gas_deposit) else {
            return Err(InvalidParameters::UpdateNotFound.into());
        };

        Ok(true)
    }

    /// returns all proposed updates
    pub fn proposed_updates(&self) -> dtos::ProposedUpdates {
        self.proposed_updates.into_dto_type()
    }

    /// Removes an update vote by the caller
    /// panics if the contract is not in a running state or if the caller is not a participant
    pub fn remove_update_vote(&mut self) {
        log!("remove_update_vote: signer={}", env::signer_account_id(),);
        let ProtocolContractState::Running(_running_state) = &self.protocol_state else {
            env::panic_str("protocol must be in running state");
        };
        let voter = self.voter_or_panic();
        self.proposed_updates.remove_vote(&voter);
    }

    /// Cleans update votes from non-participants after resharing.
    /// Can only be called by participants or by the contract itself.
    #[handle_result]
    pub fn remove_non_participant_update_votes(&mut self) -> Result<(), Error> {
        log!(
            "remove_non_participant_update_votes: signer={}",
            env::signer_account_id()
        );

        let participants = match &self.protocol_state {
            ProtocolContractState::Running(state) => state.parameters.participants(),
            _ => {
                return Err(InvalidState::ProtocolStateNotRunning.into());
            }
        };

        // Authorize the caller: allow self-calls (the cleanup promise spawned after a
        // successful resharing, where the predecessor is the contract account) and
        // direct calls from a current participant. Reject everyone else so that
        // non-participants cannot drive this cleanup.
        let caller = env::predecessor_account_id();
        let is_self_call = caller == env::current_account_id();
        if !is_self_call && !participants.is_participant_given_account_id(&caller) {
            return Err(InvalidState::NotParticipant { account_id: caller }.into());
        }

        self.proposed_updates
            .remove_non_participant_votes(participants);
        Ok(())
    }

    #[private]
    pub fn update_config(&mut self, config: dtos::Config) {
        let new_config: Config =
            Config::try_from(config).unwrap_or_else(|e| env::panic_str(&e.to_string()));
        self.config = new_config;
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::api::test_utils::{NUM_DOMAINS, NUM_GENERATED_DOMAINS};
    use crate::primitives::test_utils::{gen_account_id, gen_participants};
    use crate::primitives::thresholds::{GovernanceThreshold, GovernanceThresholdParameters};
    use crate::state::key_event::tests::Environment;
    use crate::state::test_utils::{
        gen_initializing_state, gen_resharing_state, gen_running_state,
        gen_running_state_with_params,
    };
    use assert_matches::assert_matches;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{AccountId, testing_env};
    use rand::SeedableRng;
    use rand::seq::SliceRandom;
    use rstest::rstest;
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, HashSet};
    use std::panic;
    use test_utils::contract_types::dummy_config;

    fn propose_and_vote(
        contract: &mut MpcContract,
        update: Update,
        expected_update_id: u64,
    ) -> Vec<dtos::AccountId> {
        let update_id = contract.proposed_updates.propose(update.clone());
        assert_eq!(update_id.0, expected_update_id);
        // generate two accounts for voting
        let account_id_0 = gen_account_id();
        let account_id_1 = gen_account_id();
        contract
            .proposed_updates
            .vote(&update_id, account_id_0.clone())
            .unwrap();
        contract
            .proposed_updates
            .vote(&update_id, account_id_1.clone())
            .unwrap();

        let mut expected_votes = vec![account_id_0.clone(), account_id_1.clone()];
        expected_votes.sort();
        expected_votes
    }

    /// Test helper struct that combines update metadata with its votes for convenient comparison.
    /// Used to convert BTreeMap-based [`ProposedUpdates`] into a sortable vector format for assertions.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct TestUpdate {
        update_id: u64,
        update_hash: dtos::UpdateHash,
        votes: Vec<dtos::AccountId>,
    }

    impl TestUpdate {
        fn from_proposed_updates(
            update_id: u64,
            update_hash: dtos::UpdateHash,
            proposed_updates: &dtos::ProposedUpdates,
        ) -> Self {
            let votes: Vec<dtos::AccountId> = proposed_updates
                .votes
                .iter()
                .filter(|&(_, &uid)| uid == update_id)
                .map(|(account, _)| account.clone())
                .collect();
            TestUpdate {
                update_id,
                update_hash,
                votes,
            }
        }
    }

    fn propose_and_vote_code(expected_update_id: u64, contract: &mut MpcContract) -> TestUpdate {
        let code: [u8; 1000] = std::array::from_fn(|_| rand::random());
        let hash = Sha256::digest(code);
        let update = Update::Contract(code.into());
        let expected_update_hash = dtos::UpdateHash::Code(hash.into());
        let expected_votes = propose_and_vote(contract, update, expected_update_id);
        TestUpdate {
            update_id: expected_update_id,
            update_hash: expected_update_hash,
            votes: expected_votes,
        }
    }

    fn assert_proposed_update_has_expected_voters(
        proposed_updates: &ProposedUpdates,
        expected_update_id: UpdateId,
        expected_voters: &HashSet<AccountId>,
    ) {
        let actual_voters: HashSet<_> = proposed_updates.voters().into_iter().collect();
        assert_eq!(actual_voters, *expected_voters);

        let all_updates = proposed_updates.all_updates();
        assert_eq!(all_updates.updates.len(), 1);

        assert!(all_updates.updates.contains_key(&expected_update_id));
        let update = all_updates.updates.get(&expected_update_id).unwrap();
        assert_matches!(update, dtos::UpdateHash::Code(_));

        let actual_voters: HashSet<_> = all_updates
            .votes
            .iter()
            .filter(|&(_, &update_id)| update_id == expected_update_id)
            .map(|(account, _)| account.clone())
            .collect();
        assert_eq!(actual_voters, *expected_voters);
    }

    fn test_proposed_updates_case_given_state(protocol_contract_state: ProtocolContractState) {
        let mut contract = MpcContract::new_from_protocol_state(protocol_contract_state);

        let empty_result = contract.proposed_updates();
        assert_eq!(empty_result.votes, BTreeMap::new());
        assert_eq!(empty_result.updates, BTreeMap::new());

        // Propose and vote for code update
        let code_update_id = 0;
        let mut code_update = propose_and_vote_code(code_update_id, &mut contract);

        // Propose and vote for config update
        let mut config_update = {
            let update_config = dummy_config(1);
            let config_hash = Sha256::digest(serde_json::to_vec(&update_config).unwrap());
            let config_update_obj = Update::Config(update_config.clone());
            let config_update_id = 1;
            let config_votes = propose_and_vote(&mut contract, config_update_obj, config_update_id);
            TestUpdate {
                update_id: config_update_id,
                update_hash: dtos::UpdateHash::Config(config_hash.into()),
                votes: config_votes,
            }
        };

        // Sort votes for consistent comparison
        code_update.votes.sort();
        config_update.votes.sort();

        let mut expected = vec![code_update, config_update];
        // sorting to have consistent order
        expected.sort();

        let res = contract.proposed_updates();

        // Convert result to vector of TestUpdate for comparison
        let mut actual: Vec<TestUpdate> = res
            .updates
            .iter()
            .map(|(update_id, update_hash)| {
                TestUpdate::from_proposed_updates(*update_id, update_hash.clone(), &res)
            })
            .collect();

        // Sort votes within each update
        actual.iter_mut().for_each(|update| update.votes.sort());
        // sorting to have consistent order
        actual.sort();

        assert_eq!(expected, actual);
    }

    #[test]
    pub fn test_proposed_updates_interface_running() {
        let protocol_contract_state =
            ProtocolContractState::Running(gen_running_state(NUM_DOMAINS));
        test_proposed_updates_case_given_state(protocol_contract_state);
    }

    #[test]
    pub fn test_proposed_updates_interface_resharing() {
        let protocol_contract_state =
            ProtocolContractState::Resharing(gen_resharing_state(NUM_DOMAINS).1);
        test_proposed_updates_case_given_state(protocol_contract_state);
    }

    #[test]
    pub fn test_proposed_updates_interface_initialzing() {
        let protocol_contract_state = ProtocolContractState::Initializing(
            gen_initializing_state(NUM_DOMAINS, NUM_GENERATED_DOMAINS).1,
        );
        test_proposed_updates_case_given_state(protocol_contract_state);
    }

    #[test]
    pub fn test_remove_update_vote_running() {
        let running_state = gen_running_state(NUM_DOMAINS);
        let participants = running_state.parameters.participants().clone();
        let protocol_contract_state = ProtocolContractState::Running(running_state);
        let mut contract = MpcContract::new_from_protocol_state(protocol_contract_state);

        // Propose and vote for code update
        let update_id_u64 = 0;
        let test_update = propose_and_vote_code(update_id_u64, &mut contract);
        let update_id = UpdateId::from(update_id_u64);

        for (account_id, _, _) in participants.participants() {
            contract
                .proposed_updates
                .vote(&update_id, account_id.clone());

            let proposed_updates = contract.proposed_updates();
            assert_eq!(proposed_updates.updates.len(), 1);
            assert_eq!(
                *proposed_updates.updates.get(&update_id.0).unwrap(),
                test_update.update_hash
            );

            // Check that participant vote was added
            let mut expected_voters: Vec<_> = test_update.votes.to_vec();
            expected_voters.push(account_id.clone());
            let actual_voters: Vec<_> = proposed_updates
                .votes
                .iter()
                .filter(|&(_, &uid)| uid == update_id.0)
                .map(|(voter, _)| voter.clone())
                .collect();
            assert_eq!(actual_voters.len(), expected_voters.len());
            for voter in &actual_voters {
                assert!(expected_voters.contains(voter));
            }

            // Remove the vote
            testing_env!(
                VMContextBuilder::new()
                    .signer_account_id(account_id.clone())
                    .predecessor_account_id(account_id.clone())
                    .build()
            );

            contract.remove_update_vote();

            let res = contract.proposed_updates();
            assert_eq!(res.updates.len(), 1);

            // Check that participant vote was removed
            let actual_voters: Vec<_> = res
                .votes
                .iter()
                .filter(|&(_, &uid)| uid == update_id.0)
                .map(|(voter, _)| voter.clone())
                .collect();
            assert_eq!(actual_voters.len(), test_update.votes.len());
            for voter in &actual_voters {
                assert!(test_update.votes.contains(voter));
            }
        }
    }

    #[test]
    #[should_panic(expected = "not a voter")]
    fn test_remove_update_vote_panics_if_non_voter() {
        let running_state = gen_running_state(NUM_DOMAINS);
        let protocol_contract_state = ProtocolContractState::Running(running_state);
        let mut contract = MpcContract::new_from_protocol_state(protocol_contract_state);

        // Propose and vote for code update
        let update_id = 0;
        let test_update = propose_and_vote_code(update_id, &mut contract);

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let account_id = test_update.votes.choose(&mut rng).unwrap();
        let account_id: AccountId = account_id.clone();
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id)
                .build()
        );

        contract.remove_update_vote();
    }

    #[test]
    #[should_panic(expected = "protocol must be in running state")]
    pub fn test_remove_update_vote_resharing() {
        let protocol_contract_state =
            ProtocolContractState::Resharing(gen_resharing_state(NUM_DOMAINS).1);
        let mut contract = MpcContract::new_from_protocol_state(protocol_contract_state);
        let account_id = gen_account_id();
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id)
                .build()
        );
        contract.remove_update_vote();
    }

    #[test]
    #[should_panic(expected = "protocol must be in running state")]
    pub fn test_remove_update_vote_initializing() {
        let protocol_contract_state = ProtocolContractState::Initializing(
            gen_initializing_state(NUM_DOMAINS, NUM_GENERATED_DOMAINS).1,
        );
        let mut contract = MpcContract::new_from_protocol_state(protocol_contract_state);
        let account_id = gen_account_id();
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(account_id.clone())
                .predecessor_account_id(account_id)
                .build()
        );
        contract.remove_update_vote();
    }

    /// Test that `vote_update` correctly filters out non-participant votes when checking threshold.
    ///
    /// This is a regression test for a bug where votes from accounts that were no longer
    /// participants (e.g., after resharing) were still counted toward the update threshold.
    ///
    /// The test verifies that only votes from current participants are counted:
    /// - With threshold=2 and 3 participants, we need 2 valid participant votes
    /// - Adding 2 non-participant votes + 1 participant vote should NOT meet threshold (returns false)
    /// - Adding a 2nd participant vote should meet threshold (returns true)
    #[test]
    pub fn test_vote_update_filters_non_participant_votes() {
        // given: a running state with 3 participants and threshold of 2
        let mut running_state = gen_running_state(1);
        running_state.parameters =
            GovernanceThresholdParameters::new(gen_participants(3), GovernanceThreshold::new(2))
                .unwrap();

        let participants = running_state.parameters.participants().participants();
        let participant_1 = participants[0].0.clone();
        let participant_2 = participants[1].0.clone();

        let mut contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running_state));

        let update_id = contract
            .proposed_updates
            .propose(Update::Contract([0; 1000].into()));

        // given: 2 non-participant votes + 1 participant vote (simulating old voters from before resharing)
        contract.proposed_updates.vote(&update_id, gen_account_id());
        contract.proposed_updates.vote(&update_id, gen_account_id());
        contract
            .proposed_updates
            .vote(&update_id, participant_1.clone());

        // when: first participant calls vote_update (only 1 valid participant vote out of 3 total)
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(participant_1.clone())
                .predecessor_account_id(participant_1)
                .build()
        );
        // then: threshold not met (need 2 valid votes, have only 1)
        assert!(!contract.vote_update(update_id).unwrap());

        // given: a 2nd participant vote is added
        contract
            .proposed_updates
            .vote(&update_id, participant_2.clone());

        // when: second participant calls vote_update (2 valid participant votes out of 4 total)
        testing_env!(
            VMContextBuilder::new()
                .signer_account_id(participant_2.clone())
                .predecessor_account_id(participant_2)
                .build()
        );
        // then: threshold met (have 2 valid votes, need 2)
        assert!(contract.vote_update(update_id).unwrap());
    }

    #[test]
    fn propose_update__should_charge_a_deposit_covering_the_worst_case_storage_cost() {
        // Given
        let running_state = gen_running_state_with_params(1, 129, 129);
        let voters: Vec<AccountId> = running_state
            .parameters
            .participants()
            .participants()
            .iter()
            .map(|(account_id, _, _)| account_id.clone())
            .collect();
        let mut contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running_state));
        let code = vec![0xff; 4096];
        let required_deposit = ProposedUpdates::required_deposit(
            u128::try_from(code.len()).expect("usize always fits in u128"),
        )
        .expect("the deposit for a 4 KiB payload fits in u128");

        // When
        let mut environment = Environment::new(None, Some(voters[0].clone()), None);
        environment.set_deposit(required_deposit);
        let storage_before = env::storage_usage();
        let id = contract
            .propose_update(ProposeUpdateArgs {
                code: Some(code),
                config: None,
            })
            .unwrap();
        for voter in &voters[1..] {
            Environment::new(None, Some(voter.clone()), None);
            assert!(!contract.vote_update(id).unwrap());
        }
        // near-sdk `store` collections write their cached changes to storage
        // in `Drop`; dropping the contract persists the entry and the votes.
        drop(contract);
        let bytes_grown = u128::from(env::storage_usage() - storage_before);
        let storage_cost = env::storage_byte_cost().saturating_mul(bytes_grown);

        // Then
        assert!(
            required_deposit >= storage_cost,
            "deposit {required_deposit} does not cover {storage_cost} of storage"
        );
    }

    /// Callers authorized to drive `remove_non_participant_update_votes`.
    enum AuthorizedCaller {
        /// The contract calling itself (the cleanup promise spawned after resharing).
        ContractItself,
        /// A current participant calling directly.
        Participant,
    }

    /// An authorized caller (the contract itself or a current participant) drives the cleanup,
    /// leaving only the participant votes (simulating post-resharing cleanup).
    #[rstest]
    #[case::contract_itself(AuthorizedCaller::ContractItself)]
    #[case::participant(AuthorizedCaller::Participant)]
    fn remove_non_participant_update_votes__should_clean_when_called_by_authorized_caller(
        #[case] caller_kind: AuthorizedCaller,
    ) {
        // Given: a running state with update votes from both participants and non-participants.
        let running_state = gen_running_state(NUM_DOMAINS);
        let participants = running_state.parameters.participants().clone();
        let mut contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running_state));

        // propose_and_vote_code adds 2 non-participant votes.
        let update_id_u64 = 0;
        let _ = propose_and_vote_code(update_id_u64, &mut contract);
        let update_id: UpdateId = update_id_u64.into();

        // Add votes from 2 current participants.
        let participants = participants.participants();
        let (p1, p2) = (participants[0].0.clone(), participants[1].0.clone());
        contract.proposed_updates.vote(&update_id, p1.clone());
        contract.proposed_updates.vote(&update_id, p2.clone());

        // Resolve the caller account for this case. The contract account differs from any
        // participant account, so the self-call and participant branches are distinct.
        let caller = match caller_kind {
            AuthorizedCaller::ContractItself => env::current_account_id(),
            AuthorizedCaller::Participant => p1.clone(),
        };

        // When: the authorized caller invokes the cleanup directly.
        testing_env!(
            VMContextBuilder::new()
                .current_account_id(env::current_account_id())
                .predecessor_account_id(caller.clone())
                .signer_account_id(caller)
                .build()
        );
        contract.remove_non_participant_update_votes().unwrap();

        // Then: only the 2 participant votes remain.
        let participant_voters = HashSet::from([p1, p2]);
        assert_proposed_update_has_expected_voters(
            &contract.proposed_updates,
            update_id,
            &participant_voters,
        );
    }

    /// A caller that is neither the contract itself nor a current participant is rejected with
    /// [`NotParticipant`], and the votes are left untouched.
    #[test]
    fn remove_non_participant_update_votes__should_reject_unauthorized_caller() {
        // Given: a running state with update votes from both participants and non-participants.
        let running_state = gen_running_state(NUM_DOMAINS);
        let participants = running_state.parameters.participants().clone();
        let mut contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running_state));

        let update_id_u64 = 0;
        let test_update = propose_and_vote_code(update_id_u64, &mut contract);
        let update_id: UpdateId = update_id_u64.into();
        let non_participants: HashSet<AccountId> = test_update.votes.iter().cloned().collect();

        let participants = participants.participants();
        let (p1, p2) = (participants[0].0.clone(), participants[1].0.clone());
        contract.proposed_updates.vote(&update_id, p1.clone());
        contract.proposed_updates.vote(&update_id, p2.clone());

        let voters_before: HashSet<_> = [p1, p2].into_iter().chain(non_participants).collect();

        // When: an account that is neither the contract nor a participant calls the cleanup.
        let outsider = gen_account_id();
        testing_env!(
            VMContextBuilder::new()
                .current_account_id(env::current_account_id())
                .predecessor_account_id(outsider.clone())
                .signer_account_id(outsider.clone())
                .build()
        );
        let result = contract.remove_non_participant_update_votes();

        // Then: the call is rejected with NotParticipant and the votes are left untouched.
        assert_matches!(
            result,
            Err(Error::InvalidState(InvalidState::NotParticipant { account_id }))
                if account_id == outsider
        );
        assert_proposed_update_has_expected_voters(
            &contract.proposed_updates,
            update_id,
            &voters_before,
        );
    }
}
