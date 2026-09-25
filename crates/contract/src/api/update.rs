//! Contract-update proposals: proposing, voting, and applying code and config
//! updates, plus sweeping votes from departed participants.

use crate::api::common::refund_to;
use crate::config::Config;
use crate::dto_mapping::IntoInterfaceType;
use crate::errors::{Error, InvalidParameters, InvalidState};
use crate::primitives::key_state::AuthenticatedAccountId;
use crate::primitives::proposal_hash::{ProposalHash, ToProposalHash};
use crate::{MpcContract, MpcContractExt};
use near_mpc_contract_interface::deposits::{
    propose_update_required_deposit_yoctonear, update_payload_bytes,
};
use near_mpc_contract_interface::method_names;
use near_mpc_contract_interface::types::{self as dtos};
use near_sdk::{Gas, NearToken, Promise, env, log, near};
use std::collections::{BTreeMap, BTreeSet};

#[near]
impl MpcContract {
    /// Submits an update and applies it. Fails if the update doesn't yet have enough
    /// participant votes.
    #[payable]
    #[handle_result]
    pub fn submit_contract_update(
        &mut self,
        #[serializer(borsh)] update: dtos::Update,
    ) -> Result<(), Error> {
        // Anyone could submit an approved update without risk to the MPC service,
        // but we guard the endpoint to keep control over _when_ it is applied.
        let submitter = self.voter_or_panic();

        let payload_bytes =
            update_payload_bytes(&update).map_err(|err| InvalidParameters::MalformedPayload {
                reason: err.to_string(),
            })?;
        let attached = env::attached_deposit();
        let required = propose_update_required_deposit_yoctonear(
            payload_bytes,
            env::storage_byte_cost().as_yoctonear(),
        )
        .map(NearToken::from_yoctonear)
        .map_err(|err| InvalidParameters::MalformedPayload {
            reason: err.to_string(),
        })?;
        if attached < required {
            return Err(InvalidParameters::InsufficientDeposit {
                attached: attached.as_yoctonear(),
                required: required.as_yoctonear(),
            }
            .into());
        }

        let update_hash =
            near_mpc_sdk::update::hash_with(&update, |bytes| env::sha256_array(bytes));
        log!(
            "submit_contract_update: signer={}, update_hash={:?}",
            env::signer_account_id(),
            update_hash,
        );
        let parameters = self.protocol_state.threshold_parameters_or_panic();
        let num_votes = self
            .contract_update_votes
            .voters_for(&update_hash.to_proposal_hash())
            .map(|voters| voters.count_participants(parameters.participants()))
            .unwrap_or(0);
        if num_votes < parameters.threshold().value() {
            return Err(InvalidParameters::UpdateNotApproved.into());
        }
        self.contract_update_votes.clear();
        match update {
            dtos::Update::Code(code) => Promise::new(env::current_account_id())
                .deploy_contract(code)
                .function_call(
                    method_names::MIGRATE,
                    Vec::new(),
                    NearToken::from_near(0),
                    Gas::from_tgas(self.config.contract_upgrade_deposit_tera_gas),
                ),
            dtos::Update::Config(config) => {
                let config: Config = config.try_into()?;
                Self::ext_self()
                    .with_static_gas(Gas::from_tgas(config.contract_upgrade_deposit_tera_gas))
                    .update_config(config.into_dto_type())
            }
        }
        .detach();
        refund_to(&submitter, attached.saturating_sub(required));
        Ok(())
    }

    /// Replaces the caller's earlier vote, if any. Returns whether `update_hash` is approved.
    #[handle_result]
    pub fn vote_contract_update(&mut self, update_hash: dtos::UpdateHash) -> Result<bool, Error> {
        log!(
            "vote_contract_update: signer={}, update_hash={:?}",
            env::signer_account_id(),
            update_hash,
        );
        let parameters = self.protocol_state.threshold_parameters_or_panic();
        self.voter_or_panic();
        let voter = AuthenticatedAccountId::new(parameters.participants())?;
        let num_votes = self
            .contract_update_votes
            .vote(voter, update_hash.to_proposal_hash())
            .count_participants(parameters.participants());
        Ok(num_votes >= parameters.threshold().value())
    }

    /// Returns all currently stored votes.
    pub fn contract_update_votes(&self) -> BTreeMap<ProposalHash, BTreeSet<dtos::AccountId>> {
        self.contract_update_votes
            .all()
            .into_iter()
            .map(|(proposal, voters)| {
                (
                    proposal,
                    voters.iter().map(|voter| voter.get().clone()).collect(),
                )
            })
            .collect()
    }

    /// Withdraws the caller's update vote.
    #[handle_result]
    pub fn remove_contract_update_vote(&mut self) -> Result<(), Error> {
        log!(
            "remove_contract_update_vote: signer={}",
            env::signer_account_id()
        );
        let parameters = self.protocol_state.threshold_parameters_or_panic();
        self.voter_or_panic();
        let voter = AuthenticatedAccountId::new(parameters.participants())?;

        self.contract_update_votes.remove_vote(&voter);
        Ok(())
    }

    /// Removes update votes from non-participants.
    /// Can only be called by participants or by the contract itself.
    #[handle_result]
    pub fn remove_non_participant_contract_update_votes(&mut self) -> Result<(), Error> {
        log!(
            "remove_non_participant_contract_update_votes: signer={}",
            env::signer_account_id()
        );

        let participants = self
            .protocol_state
            .threshold_parameters_or_panic()
            .participants();

        let caller = env::predecessor_account_id();
        let is_self_call = caller == env::current_account_id();
        if !is_self_call && !participants.is_participant(&caller) {
            return Err(InvalidState::NotParticipant { account_id: caller }.into());
        }

        self.contract_update_votes
            .retain_votes(|voter| participants.is_participant(voter));
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
    use crate::api::test_utils::{
        contract_with_participants, initializing_state, resharing_state, running_state,
    };
    use crate::primitives::proposal_hash::ToProposalHash;
    use crate::primitives::test_utils::{
        authenticate_account_as, gen_account_id, gen_participants,
    };
    use crate::state::ProtocolContractState;
    use crate::state::key_event::tests::Environment;
    use assert_matches::assert_matches;
    use near_sdk::{AccountId, env};
    use rstest::rstest;
    use std::collections::{BTreeMap, BTreeSet};
    use std::panic;
    use test_utils::contract_types::dummy_config;

    fn update_hash(byte: u8) -> dtos::UpdateHash {
        dtos::UpdateHash::Code(dtos::Hash256([byte; 32]))
    }

    fn code_update() -> dtos::Update {
        dtos::Update::Code(vec![1, 2, 3])
    }

    fn config_update() -> dtos::Update {
        dtos::Update::Config(dummy_config(1))
    }

    fn expected_votes(
        votes_by_update_hash: &[(u8, &[AccountId])],
    ) -> BTreeMap<ProposalHash, BTreeSet<AccountId>> {
        votes_by_update_hash
            .iter()
            .map(|(hash, voters)| {
                (
                    update_hash(*hash).to_proposal_hash(),
                    voters.iter().cloned().collect::<BTreeSet<_>>(),
                )
            })
            .collect()
    }

    fn required_deposit(update: &dtos::Update) -> NearToken {
        NearToken::from_yoctonear(
            propose_update_required_deposit_yoctonear(
                update_payload_bytes(update).unwrap(),
                env::storage_byte_cost().as_yoctonear(),
            )
            .unwrap(),
        )
    }

    fn threshold(contract: &MpcContract) -> usize {
        contract.protocol_state.threshold().unwrap().value() as usize
    }

    /// A threshold of votes from accounts that are no longer participants, plus one from a
    /// current one.
    fn contract_with_stale_votes(
        env: &mut Environment,
        state: ProtocolContractState,
    ) -> (MpcContract, Vec<AccountId>, Vec<AccountId>) {
        let (mut contract, participants) = contract_with_participants(state);
        let former_set = gen_participants(threshold(&contract));
        let former: Vec<AccountId> = former_set
            .participants()
            .iter()
            .map(|(account_id, _, _)| account_id.clone())
            .collect();
        for account_id in &former {
            contract.contract_update_votes.vote(
                authenticate_account_as(account_id, &former_set),
                update_hash(1).to_proposal_hash(),
            );
        }
        env.set_signer(&participants[0]);
        assert!(!contract.vote_contract_update(update_hash(1)).unwrap());
        (contract, participants, former)
    }

    fn approve(
        env: &mut Environment,
        contract: &mut MpcContract,
        participants: &[AccountId],
        update: &dtos::Update,
    ) {
        for participant in &participants[..threshold(contract)] {
            env.set_signer(participant);
            contract
                .vote_contract_update(near_mpc_sdk::update::hash(update))
                .unwrap();
        }
    }

    #[rstest]
    fn submit_contract_update__should_apply_an_approved_update_in_any_active_state(
        #[values(running_state(), resharing_state(), initializing_state())]
        state: ProtocolContractState,
        #[values(code_update(), config_update())] update: dtos::Update,
    ) {
        // Given
        let mut env = Environment::new(None, None, None);
        let (mut contract, participants) = contract_with_participants(state);
        approve(&mut env, &mut contract, &participants, &update);

        // When
        env.set_signer(&participants[0]);
        env.set_deposit(required_deposit(&update));
        let result = contract.submit_contract_update(update);

        // Then
        result.unwrap();
        assert_eq!(contract.contract_update_votes(), BTreeMap::new());
    }

    #[rstest]
    #[should_panic(expected = "not a voter")]
    fn submit_contract_update__should_panic_for_non_participants(
        #[values(running_state(), resharing_state(), initializing_state())]
        state: ProtocolContractState,
    ) {
        // Given
        let mut env = Environment::new(None, None, None);
        let mut contract = MpcContract::new_from_protocol_state(state);
        env.set_signer(&gen_account_id());

        // When
        let _ = contract.submit_contract_update(code_update());
    }

    #[rstest]
    fn submit_contract_update__should_reject_an_insufficient_deposit(
        #[values(running_state(), resharing_state(), initializing_state())]
        state: ProtocolContractState,
    ) {
        // Given
        let mut env = Environment::new(None, None, None);
        let (mut contract, participants) = contract_with_participants(state);
        approve(&mut env, &mut contract, &participants, &code_update());
        let required = required_deposit(&code_update());

        // When
        env.set_signer(&participants[0]);
        env.set_deposit(required.saturating_sub(NearToken::from_yoctonear(1)));
        let result = contract.submit_contract_update(code_update());

        // Then
        assert_matches!(
            result,
            Err(Error::InvalidParameters(InvalidParameters::InsufficientDeposit {
                attached,
                required: expected,
            })) if attached == required.as_yoctonear() - 1 && expected == required.as_yoctonear()
        );
    }

    #[rstest]
    fn submit_contract_update__should_reject_a_hash_that_is_not_approved(
        #[values(running_state(), resharing_state(), initializing_state())]
        state: ProtocolContractState,
    ) {
        // Given
        let mut env = Environment::new(None, None, None);
        let (mut contract, participants) = contract_with_participants(state);
        env.set_signer(&participants[0]);
        env.set_deposit(required_deposit(&code_update()));

        // When
        let result = contract.submit_contract_update(code_update());

        // Then
        assert_matches!(
            result,
            Err(Error::InvalidParameters(
                InvalidParameters::UpdateNotApproved
            ))
        );
    }

    #[rstest]
    fn submit_contract_update__should_clear_the_votes_after_applying(
        #[values(running_state(), resharing_state(), initializing_state())]
        state: ProtocolContractState,
    ) {
        // Given
        let mut env = Environment::new(None, None, None);
        let (mut contract, participants) = contract_with_participants(state);
        approve(&mut env, &mut contract, &participants, &code_update());
        assert_eq!(contract.contract_update_votes().len(), 1);

        // When
        env.set_signer(&participants[0]);
        env.set_deposit(required_deposit(&code_update()));
        let first = contract.submit_contract_update(code_update());
        let second = contract.submit_contract_update(code_update());

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

    #[rstest]
    fn submit_contract_update__should_reject_an_approved_but_invalid_config(
        #[values(running_state(), resharing_state(), initializing_state())]
        state: ProtocolContractState,
    ) {
        // Given
        let mut env = Environment::new(None, None, None);
        let (mut contract, participants) = contract_with_participants(state);
        let mut config = test_utils::contract_types::dummy_config(1);
        config.launcher_hash_unused_ttl_seconds = 0;
        let update = dtos::Update::Config(config);
        approve(&mut env, &mut contract, &participants, &update);

        // When
        env.set_signer(&participants[0]);
        env.set_deposit(required_deposit(&update));
        let result = contract.submit_contract_update(update);

        // Then
        let err = result.expect_err("invalid config must be rejected");
        assert!(
            format!("{err:?}").contains("launcher_hash_unused_ttl_seconds"),
            "error should point at the invalid field, got: {err:?}"
        );
    }

    #[rstest]
    fn vote_contract_update__should_count_only_current_participants(
        #[values(running_state(), resharing_state(), initializing_state())]
        state: ProtocolContractState,
    ) {
        // Given
        let mut env = Environment::new(None, None, None);
        let (mut contract, participants, _) = contract_with_stale_votes(&mut env, state);
        let threshold = threshold(&contract);

        // When
        for participant in &participants[1..threshold - 1] {
            env.set_signer(participant);
            assert!(!contract.vote_contract_update(update_hash(1)).unwrap());
        }

        // Then
        env.set_signer(&participants[threshold - 1]);
        assert!(contract.vote_contract_update(update_hash(1)).unwrap());
    }

    #[rstest]
    fn vote_contract_update__should_replace_the_callers_earlier_vote(
        #[values(running_state(), resharing_state(), initializing_state())]
        state: ProtocolContractState,
    ) {
        // Given
        let mut env = Environment::new(None, None, None);
        let (mut contract, participants) = contract_with_participants(state);
        env.set_signer(&participants[0]);
        contract.vote_contract_update(update_hash(1)).unwrap();

        // When
        contract.vote_contract_update(update_hash(2)).unwrap();

        // Then
        assert_eq!(
            contract.contract_update_votes(),
            expected_votes(&[(2, &[participants[0].clone()])])
        );
    }

    #[rstest]
    #[should_panic(expected = "not a voter")]
    fn vote_contract_update__should_panic_for_non_participants(
        #[values(running_state(), resharing_state(), initializing_state())]
        state: ProtocolContractState,
    ) {
        // Given
        let mut env = Environment::new(None, None, None);
        let mut contract = MpcContract::new_from_protocol_state(state);
        env.set_signer(&gen_account_id());

        // When
        let _ = contract.vote_contract_update(update_hash(1));
    }

    #[rstest]
    fn contract_update_votes__should_report_the_votes(
        #[values(running_state(), resharing_state(), initializing_state())]
        state: ProtocolContractState,
    ) {
        // Given
        let mut env = Environment::new(None, None, None);
        let (mut contract, voters) = contract_with_participants(state);
        assert_eq!(contract.contract_update_votes(), BTreeMap::new());

        // When
        env.set_signer(&voters[0]);
        contract.vote_contract_update(update_hash(0)).unwrap();
        env.set_signer(&voters[1]);
        contract.vote_contract_update(update_hash(1)).unwrap();

        // Then
        assert_eq!(
            contract.contract_update_votes(),
            expected_votes(&[(0, &[voters[0].clone()]), (1, &[voters[1].clone()])])
        );
    }

    #[rstest]
    fn remove_contract_update_vote__should_drop_the_hash_below_the_threshold(
        #[values(running_state(), resharing_state(), initializing_state())]
        state: ProtocolContractState,
    ) {
        // Given
        let mut env = Environment::new(None, None, None);
        let (mut contract, participants) = contract_with_participants(state);
        approve(&mut env, &mut contract, &participants, &code_update());

        // When
        env.set_signer(&participants[0]);
        contract.remove_contract_update_vote().unwrap();

        // Then
        env.set_deposit(required_deposit(&code_update()));
        assert_matches!(
            contract.submit_contract_update(code_update()),
            Err(Error::InvalidParameters(
                InvalidParameters::UpdateNotApproved
            ))
        );
    }

    #[rstest]
    #[should_panic(expected = "not a voter")]
    fn remove_contract_update_vote__should_panic_for_non_participants(
        #[values(running_state(), resharing_state(), initializing_state())]
        state: ProtocolContractState,
    ) {
        // Given
        let mut env = Environment::new(None, None, None);
        let mut contract = MpcContract::new_from_protocol_state(state);
        env.set_signer(&gen_account_id());

        // When
        let _ = contract.remove_contract_update_vote();
    }

    enum CallerKind {
        ContractItself,
        Participant,
        Outsider,
    }

    #[rstest]
    #[case::contract_itself(CallerKind::ContractItself, true)]
    #[case::participant(CallerKind::Participant, true)]
    #[case::outsider(CallerKind::Outsider, false)]
    fn remove_non_participant_contract_update_votes__should_clean_only_for_authorized_callers(
        #[case] caller_kind: CallerKind,
        #[case] authorized: bool,
        #[values(running_state(), resharing_state(), initializing_state())]
        state: ProtocolContractState,
    ) {
        // Given
        let mut env = Environment::new(None, None, None);
        let (mut contract, participants, former) = contract_with_stale_votes(&mut env, state);
        let all_voters: Vec<AccountId> = former
            .iter()
            .chain(std::iter::once(&participants[0]))
            .cloned()
            .collect();
        assert_eq!(
            contract.contract_update_votes(),
            expected_votes(&[(1, &all_voters)])
        );
        let caller = match caller_kind {
            CallerKind::ContractItself => env::current_account_id(),
            CallerKind::Participant => participants[0].clone(),
            CallerKind::Outsider => gen_account_id(),
        };

        // When
        env.set_signer(&caller);
        let result = contract.remove_non_participant_contract_update_votes();

        // Then
        if authorized {
            result.unwrap();
            assert_eq!(
                contract.contract_update_votes(),
                expected_votes(&[(1, &[participants[0].clone()])])
            );
        } else {
            assert_matches!(
                result,
                Err(Error::InvalidState(InvalidState::NotParticipant { account_id }))
                    if account_id == caller
            );
            assert_eq!(
                contract.contract_update_votes(),
                expected_votes(&[(1, &all_voters)])
            );
        }
    }
}
