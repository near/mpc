//! Contract updates: voting, submitting and applying code and config updates, plus sweeping
//! votes from departed participants.

use crate::{
    MpcContract, MpcContractExt,
    config::Config,
    errors::{Error, InvalidParameters, InvalidState},
    primitives::{key_state::AuthenticatedAccountId, proposal_hash::ProposalHash},
    state::ProtocolContractState,
    update::update_promise,
};
use near_mpc_contract_interface::types::{self as dtos};
use near_sdk::{Gas, env, log, near};
use std::collections::{BTreeMap, BTreeSet};

#[near]
impl MpcContract {
    /// Submits an update and applies it. Fails if the update doesn't yet have enough
    /// participant votes.
    #[payable]
    #[handle_result]
    pub fn submit_update(
        &mut self,
        #[serializer(borsh)] update: dtos::Update,
    ) -> Result<(), Error> {
        let ProtocolContractState::Running(running_state) = &self.protocol_state else {
            env::panic_str("protocol must be in running state");
        };
        // Anyone could submit an approved update without harm; we guard the endpoint to keep
        // control over _when_ it is applied.
        self.voter_or_panic();

        let update_hash =
            near_mpc_sdk::update::hash_with(&update, |bytes| env::sha256_array(bytes));
        log!(
            "submit_update: signer={}, update_hash={:?}",
            env::signer_account_id(),
            update_hash,
        );
        if !self
            .contract_update_votes
            .take_if_approved(&update_hash, &running_state.parameters)
        {
            return Err(InvalidParameters::UpdateNotApproved.into());
        }
        let gas = Gas::from_tgas(self.config.contract_upgrade_deposit_tera_gas);
        update_promise(update, gas)?.detach();
        Ok(())
    }

    /// Replaces the caller's earlier vote, if any. Returns whether `update_hash` is approved.
    #[handle_result]
    pub fn vote_update(&mut self, update_hash: dtos::UpdateHash) -> Result<bool, Error> {
        log!(
            "vote_update: signer={}, update_hash={:?}",
            env::signer_account_id(),
            update_hash,
        );
        let ProtocolContractState::Running(running_state) = &self.protocol_state else {
            env::panic_str("protocol must be in running state");
        };
        self.voter_or_panic();
        let voter = AuthenticatedAccountId::new(running_state.parameters.participants())?;

        Ok(self
            .contract_update_votes
            .vote(&update_hash, voter, &running_state.parameters))
    }

    /// Voters per [`dtos::UpdateHash`], keyed by `sha256sum <<< '{"Code":"<hex>"}'` so that a
    /// voter can find their own vote.
    pub fn contract_update_votes(&self) -> BTreeMap<ProposalHash, BTreeSet<dtos::AccountId>> {
        self.contract_update_votes
            .pending()
            .into_iter()
            .map(|(proposal, voters)| {
                (
                    proposal,
                    voters.iter().map(|voter| voter.get().clone()).collect(),
                )
            })
            .collect()
    }

    /// Withdraws the caller's update vote, un-approving the hash they backed if it falls below
    /// the governance threshold.
    #[handle_result]
    pub fn remove_update_vote(&mut self) -> Result<(), Error> {
        log!("remove_update_vote: signer={}", env::signer_account_id());
        let ProtocolContractState::Running(running_state) = &self.protocol_state else {
            env::panic_str("protocol must be in running state");
        };
        self.voter_or_panic();
        let voter = AuthenticatedAccountId::new(running_state.parameters.participants())?;

        self.contract_update_votes.remove_vote(&voter);
        Ok(())
    }

    /// Cleans update votes from non-participants after resharing.
    /// Can only be called by participants or by the contract itself.
    #[handle_result]
    pub fn remove_non_participant_contract_update_votes(&mut self) -> Result<(), Error> {
        log!(
            "remove_non_participant_contract_update_votes: signer={}",
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
        if !is_self_call && !participants.is_participant(&caller) {
            return Err(InvalidState::NotParticipant { account_id: caller }.into());
        }

        self.contract_update_votes.retain(participants);
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
    use crate::MpcContract;
    use crate::api::test_utils::{
        NUM_DOMAINS, NUM_GENERATED_DOMAINS, participant_account_ids, setup_tee_test_contract,
    };
    use crate::errors::{Error, InvalidParameters, InvalidState};
    use crate::primitives::proposal_hash::{ProposalHash, ToProposalHash};
    use crate::primitives::test_utils::{
        authenticate_account_as, gen_account_id, gen_participants,
    };
    use crate::state::ProtocolContractState;
    use crate::state::test_utils::{
        gen_initializing_state, gen_resharing_state, gen_running_state,
    };
    use crate::tee::test_utils::Environment;
    use assert_matches::assert_matches;
    use near_mpc_contract_interface::types as dtos;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{AccountId, env, testing_env};
    use rstest::rstest;
    use std::collections::{BTreeMap, BTreeSet};

    const NUM_PARTICIPANTS: usize = 3;
    const THRESHOLD: u64 = 2;

    fn update_hash(byte: u8) -> dtos::UpdateHash {
        dtos::UpdateHash::Code(dtos::Hash256([byte; 32]))
    }

    fn expected_votes(
        buckets: &[(u8, &[AccountId])],
    ) -> BTreeMap<ProposalHash, BTreeSet<AccountId>> {
        buckets
            .iter()
            .map(|(hash, voters)| {
                (
                    update_hash(*hash).to_proposal_hash(),
                    voters.iter().cloned().collect::<BTreeSet<_>>(),
                )
            })
            .collect()
    }

    /// Votes without the running-state check the entrypoint applies.
    fn record_vote(contract: &mut MpcContract, hash: u8, account_id: &AccountId) {
        let parameters = contract
            .protocol_state
            .threshold_parameters()
            .unwrap()
            .clone();
        let voter = authenticate_account_as(account_id, parameters.participants());
        contract
            .contract_update_votes
            .vote(&update_hash(hash), voter, &parameters);
    }

    fn test_proposed_updates_case_given_state(protocol_contract_state: ProtocolContractState) {
        let mut contract = MpcContract::new_from_protocol_state(protocol_contract_state);
        assert_eq!(contract.contract_update_votes(), BTreeMap::new());

        let voters = participant_account_ids(&contract);
        record_vote(&mut contract, 0, &voters[0]);
        record_vote(&mut contract, 1, &voters[1]);

        assert_eq!(
            contract.contract_update_votes(),
            expected_votes(&[(0, &[voters[0].clone()]), (1, &[voters[1].clone()]),])
        );
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

        for (account_id, _, _) in participants.participants() {
            Environment::new(None, Some(account_id.clone()), None);
            contract.vote_update(update_hash(0)).unwrap();
            assert_eq!(
                contract.contract_update_votes(),
                expected_votes(&[(0, std::slice::from_ref(account_id))])
            );

            contract.remove_update_vote().unwrap();
            assert_eq!(contract.contract_update_votes(), BTreeMap::new());
        }
    }

    #[test]
    #[should_panic(expected = "not a voter")]
    fn test_remove_update_vote_panics_if_non_voter() {
        let running_state = gen_running_state(NUM_DOMAINS);
        let protocol_contract_state = ProtocolContractState::Running(running_state);
        let mut contract = MpcContract::new_from_protocol_state(protocol_contract_state);
        Environment::new(None, Some(gen_account_id()), None);

        let _ = contract.remove_update_vote();
    }

    #[test]
    #[should_panic(expected = "protocol must be in running state")]
    pub fn test_remove_update_vote_resharing() {
        let protocol_contract_state =
            ProtocolContractState::Resharing(gen_resharing_state(NUM_DOMAINS).1);
        let mut contract = MpcContract::new_from_protocol_state(protocol_contract_state);
        Environment::new(None, Some(gen_account_id()), None);

        let _ = contract.remove_update_vote();
    }

    #[test]
    #[should_panic(expected = "protocol must be in running state")]
    pub fn test_remove_update_vote_initializing() {
        let protocol_contract_state = ProtocolContractState::Initializing(
            gen_initializing_state(NUM_DOMAINS, NUM_GENERATED_DOMAINS).1,
        );
        let mut contract = MpcContract::new_from_protocol_state(protocol_contract_state);
        Environment::new(None, Some(gen_account_id()), None);

        let _ = contract.remove_update_vote();
    }

    /// Regression test: votes from accounts that are no longer participants used to count
    /// towards the threshold.
    #[test]
    pub fn test_vote_update_filters_non_participant_votes() {
        // given: two stale votes and one from a current participant, which is not a threshold
        let (mut contract, participants, _) = contract_with_stale_votes();

        // when: a second current participant votes
        Environment::new(None, Some(participants[1].clone()), None);

        // then: threshold met
        assert!(contract.vote_update(update_hash(1)).unwrap());
    }

    /// Callers authorized to drive `remove_non_participant_contract_update_votes`.
    enum AuthorizedCaller {
        /// The contract calling itself (the cleanup promise spawned after resharing).
        ContractItself,
        /// A current participant calling directly.
        Participant,
    }

    /// Two votes from accounts that are no longer participants, plus one from a current one.
    fn contract_with_stale_votes() -> (MpcContract, Vec<AccountId>, Vec<AccountId>) {
        let (mut contract, ..) = setup_tee_test_contract(NUM_PARTICIPANTS, THRESHOLD);
        let participants = participant_account_ids(&contract);
        let former_set = gen_participants(2);
        let former: Vec<AccountId> = former_set
            .participants()
            .iter()
            .map(|(account_id, _, _)| account_id.clone())
            .collect();
        let parameters = contract
            .protocol_state
            .threshold_parameters()
            .unwrap()
            .clone();
        for account_id in &former {
            contract.contract_update_votes.vote(
                &update_hash(1),
                authenticate_account_as(account_id, &former_set),
                &parameters,
            );
        }
        Environment::new(None, Some(participants[0].clone()), None);
        assert!(!contract.vote_update(update_hash(1)).unwrap());
        (contract, participants, former)
    }

    #[rstest]
    #[case::contract_itself(AuthorizedCaller::ContractItself)]
    #[case::participant(AuthorizedCaller::Participant)]
    fn remove_non_participant_contract_update_votes__should_clean_when_called_by_authorized_caller(
        #[case] caller_kind: AuthorizedCaller,
    ) {
        // Given
        let (mut contract, participants, _) = contract_with_stale_votes();
        let caller = match caller_kind {
            AuthorizedCaller::ContractItself => env::current_account_id(),
            AuthorizedCaller::Participant => participants[0].clone(),
        };

        // When
        testing_env!(
            VMContextBuilder::new()
                .current_account_id(env::current_account_id())
                .predecessor_account_id(caller.clone())
                .signer_account_id(caller)
                .build()
        );
        contract
            .remove_non_participant_contract_update_votes()
            .unwrap();

        // Then
        assert_eq!(
            contract.contract_update_votes(),
            expected_votes(&[(1, &[participants[0].clone()])])
        );
    }

    #[test]
    fn remove_non_participant_contract_update_votes__should_reject_unauthorized_caller() {
        // Given
        let (mut contract, participants, former) = contract_with_stale_votes();
        let before = contract.contract_update_votes();
        let all_voters: Vec<AccountId> = former
            .iter()
            .chain(std::iter::once(&participants[0]))
            .cloned()
            .collect();
        assert_eq!(before, expected_votes(&[(1, &all_voters)]));

        // When
        let outsider = gen_account_id();
        testing_env!(
            VMContextBuilder::new()
                .current_account_id(env::current_account_id())
                .predecessor_account_id(outsider.clone())
                .signer_account_id(outsider.clone())
                .build()
        );
        let result = contract.remove_non_participant_contract_update_votes();

        // Then
        assert_matches!(
            result,
            Err(Error::InvalidState(InvalidState::NotParticipant { account_id }))
                if account_id == outsider
        );
        assert_eq!(contract.contract_update_votes(), before);
    }

    #[rstest]
    #[case::resharing(ProtocolContractState::Resharing(gen_resharing_state(NUM_DOMAINS).1))]
    #[case::initializing(ProtocolContractState::Initializing(
        gen_initializing_state(NUM_DOMAINS, NUM_GENERATED_DOMAINS).1
    ))]
    #[should_panic(expected = "protocol must be in running state")]
    fn submit_update__should_panic_when_not_running(#[case] state: ProtocolContractState) {
        let mut contract = MpcContract::new_from_protocol_state(state);
        Environment::new(None, Some(gen_account_id()), None);

        let _ = contract.submit_update(dtos::Update::Code(vec![1, 2, 3]));
    }

    #[test]
    #[should_panic(expected = "not a voter")]
    fn vote_update__should_panic_for_non_participants() {
        let (mut contract, ..) = setup_tee_test_contract(NUM_PARTICIPANTS, THRESHOLD);
        Environment::new(None, Some(gen_account_id()), None);

        let _ = contract.vote_update(update_hash(1));
    }

    fn approve(contract: &mut MpcContract, participants: &[AccountId], update: &dtos::Update) {
        for participant in &participants[..THRESHOLD as usize] {
            Environment::new(None, Some(participant.clone()), None);
            contract
                .vote_update(near_mpc_sdk::update::hash(update))
                .unwrap();
        }
    }

    #[test]
    fn remove_update_vote__should_take_back_an_approval_and_block_submission() {
        // Given
        let (mut contract, ..) = setup_tee_test_contract(NUM_PARTICIPANTS, THRESHOLD);
        let participants = participant_account_ids(&contract);
        let code = vec![1, 2, 3];
        approve(
            &mut contract,
            &participants,
            &dtos::Update::Code(code.clone()),
        );

        // When
        Environment::new(None, Some(participants[0].clone()), None);
        contract.remove_update_vote().unwrap();

        // Then
        Environment::new(None, Some(participants[2].clone()), None);
        let refused = contract.submit_update(dtos::Update::Code(code.clone()));
        assert_matches!(
            refused,
            Err(Error::InvalidParameters(
                InvalidParameters::UpdateNotApproved
            ))
        );

        Environment::new(None, Some(participants[2].clone()), None);
        assert!(
            contract
                .vote_update(near_mpc_sdk::update::hash(&dtos::Update::Code(
                    code.clone()
                )))
                .unwrap()
        );
        contract
            .submit_update(dtos::Update::Code(code))
            .expect("restoring the threshold makes the update submittable again");
    }

    #[test]
    fn submit_update__should_reject_a_hash_that_is_not_approved() {
        // Given
        let (mut contract, ..) = setup_tee_test_contract(NUM_PARTICIPANTS, THRESHOLD);
        let participants = participant_account_ids(&contract);
        Environment::new(None, Some(participants[0].clone()), None);

        // When
        let result = contract.submit_update(dtos::Update::Code(vec![1, 2, 3]));

        // Then
        assert_matches!(
            result,
            Err(Error::InvalidParameters(
                InvalidParameters::UpdateNotApproved
            ))
        );
    }

    #[test]
    fn submit_update__should_apply_the_approved_update_once() {
        // Given
        let (mut contract, ..) = setup_tee_test_contract(NUM_PARTICIPANTS, THRESHOLD);
        let participants = participant_account_ids(&contract);
        let code = vec![1, 2, 3];
        approve(
            &mut contract,
            &participants,
            &dtos::Update::Code(code.clone()),
        );
        assert_eq!(contract.contract_update_votes().len(), 1);

        // When
        Environment::new(None, Some(participants[2].clone()), None);
        let first = contract.submit_update(dtos::Update::Code(code.clone()));
        let second = contract.submit_update(dtos::Update::Code(code));

        // Then
        first.unwrap();
        assert_eq!(contract.contract_update_votes(), BTreeMap::new());
        assert_matches!(
            second,
            Err(Error::InvalidParameters(
                InvalidParameters::UpdateNotApproved
            ))
        );
    }

    #[test]
    fn submit_update__should_reject_an_approved_but_invalid_config() {
        // Given
        let (mut contract, ..) = setup_tee_test_contract(NUM_PARTICIPANTS, THRESHOLD);
        let participants = participant_account_ids(&contract);
        let mut config = test_utils::contract_types::dummy_config(1);
        config.launcher_hash_unused_ttl_seconds = 0;
        let update = dtos::Update::Config(config);
        approve(&mut contract, &participants, &update);

        // When
        let result = contract.submit_update(update);

        // Then
        let err = result.expect_err("invalid config must be rejected");
        assert!(
            format!("{err:?}").contains("launcher_hash_unused_ttl_seconds"),
            "error should point at the invalid field, got: {err:?}"
        );
    }
}
