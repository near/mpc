//! Contract updates: participants vote for the hash of the next code or config update; once a
//! hash crosses the governance threshold, a participant submits the matching payload and the
//! contract applies it.

use crate::config::Config;
use crate::errors::{Error, InvalidParameters, InvalidState};
use crate::primitives::key_state::AuthenticatedAccountId;
use crate::primitives::proposal_hash::ProposalHash;
use crate::state::ProtocolContractState;
use crate::update::Update;
use crate::{MpcContract, MpcContractExt};
use near_mpc_contract_interface::types::{self as dtos};
use near_sdk::{Gas, env, log, near};
use std::collections::{BTreeMap, BTreeSet};

#[near]
impl MpcContract {
    /// Applies `update` if a governance threshold of current participants currently backs its
    /// hash, consuming every update vote. Code updates deploy the code and call `migrate`;
    /// config updates call `update_config`. An attached deposit stays with the contract to cover
    /// the storage staking of code larger than the deployed one.
    #[payable]
    #[handle_result]
    pub fn submit_update(
        &mut self,
        #[serializer(borsh)] update: dtos::Update,
    ) -> Result<(), Error> {
        let update_hash =
            near_mpc_sdk::update::hash_with(&update, |bytes| env::sha256_array(bytes));
        log!(
            "submit_update: signer={}, update_hash={:?}",
            env::signer_account_id(),
            update_hash,
        );
        let ProtocolContractState::Running(running_state) = &self.protocol_state else {
            env::panic_str("protocol must be in running state");
        };
        self.voter_or_panic();

        if !self
            .update_votes
            .take_if_approved(&update_hash, &running_state.parameters)
        {
            return Err(InvalidParameters::UpdateNotApproved.into());
        }
        let update: Update = update.try_into()?;
        update
            .into_promise(Gas::from_tgas(
                self.config.contract_upgrade_deposit_tera_gas,
            ))
            .detach();
        Ok(())
    }

    /// Votes for `update_hash` as the next update to apply; a participant holds one vote at a
    /// time, so a new vote replaces the previous one. Returns whether the hash is now approved,
    /// i.e. whether [`Self::submit_update`] would accept the matching payload.
    ///
    /// Approval is not permanent: it lasts only while a governance threshold of current
    /// participants backs the hash, so [`Self::remove_update_vote`] takes it back.
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
            .update_votes
            .vote(&update_hash, voter, &running_state.parameters))
    }

    /// Update votes keyed by proposal: the SHA-256 of the compact JSON encoding of the voted
    /// [`dtos::UpdateHash`], e.g. `sha256sum <<< '{"Code":"<hex>"}'`. The hash backed by a
    /// governance threshold of current participants is the one [`Self::submit_update`] accepts.
    pub fn update_votes(&self) -> BTreeMap<ProposalHash, BTreeSet<dtos::AccountId>> {
        self.update_votes
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
    /// the governance threshold. Panics outside the running state or when the caller is not a
    /// participant.
    #[handle_result]
    pub fn remove_update_vote(&mut self) -> Result<(), Error> {
        log!("remove_update_vote: signer={}", env::signer_account_id());
        let ProtocolContractState::Running(running_state) = &self.protocol_state else {
            env::panic_str("protocol must be in running state");
        };
        self.voter_or_panic();
        let voter = AuthenticatedAccountId::new(running_state.parameters.participants())?;

        self.update_votes.remove_vote(&voter);
        Ok(())
    }

    /// Drops update votes from non-participants after resharing.
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
        if !is_self_call && !participants.is_participant(&caller) {
            return Err(InvalidState::NotParticipant { account_id: caller }.into());
        }

        self.update_votes.retain(participants);
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
    use crate::api::test_utils::NUM_DOMAINS;
    use crate::errors::{Error, InvalidParameters, InvalidState};
    use crate::primitives::key_state::AuthenticatedAccountId;
    use crate::primitives::participants::Participants;
    use crate::primitives::proposal_hash::{ProposalHash, ToProposalHash};
    use crate::primitives::test_utils::{gen_account_id, gen_participants};
    use crate::state::ProtocolContractState;
    use crate::state::test_utils::{gen_resharing_state, gen_running_state_with_params};
    use crate::tee::test_utils::Environment;
    use assert_matches::assert_matches;
    use near_mpc_contract_interface::types as dtos;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{AccountId, env, testing_env};
    use rstest::rstest;
    use std::collections::{BTreeMap, BTreeSet};

    const THRESHOLD: u64 = 2;

    /// A running contract with three participants and governance threshold two.
    fn running_contract() -> (MpcContract, Vec<AccountId>) {
        let running_state = gen_running_state_with_params(1, 3, THRESHOLD);
        let participants: Vec<AccountId> = running_state
            .parameters
            .participants()
            .participants()
            .iter()
            .map(|(account_id, _, _)| account_id.clone())
            .collect();
        let contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Running(running_state));
        (contract, participants)
    }

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

    /// Authenticates `account_id` against `participants`, a set it may no longer belong to.
    fn authenticated(
        participants: &Participants,
        account_id: &AccountId,
    ) -> AuthenticatedAccountId {
        Environment::new(None, Some(account_id.clone()), None);
        AuthenticatedAccountId::new(participants).unwrap()
    }

    #[test]
    fn vote_update__should_approve_the_hash_once_threshold_participants_voted() {
        // Given
        let (mut contract, participants) = running_contract();

        // When
        Environment::new(None, Some(participants[0].clone()), None);
        let first = contract.vote_update(update_hash(1)).unwrap();
        let after_first = contract.update_votes();
        Environment::new(None, Some(participants[1].clone()), None);
        let second = contract.vote_update(update_hash(1)).unwrap();

        // Then the approving vote is reported, and both votes stay on record so that a later
        // withdrawal can take the approval back.
        assert!(!first);
        assert_eq!(
            after_first,
            expected_votes(&[(1, &[participants[0].clone()])])
        );
        assert!(second);
        assert_eq!(
            contract.update_votes(),
            expected_votes(&[(1, &[participants[0].clone(), participants[1].clone()])])
        );
    }

    #[test]
    fn remove_update_vote__should_take_back_an_approval_and_block_submission() {
        // Given an approved update.
        let (mut contract, participants) = running_contract();
        let code = vec![1, 2, 3];
        let approved_hash = near_mpc_sdk::update::hash(&dtos::Update::Code(code.clone()));
        for participant in &participants[..THRESHOLD as usize] {
            Environment::new(None, Some(participant.clone()), None);
            contract.vote_update(approved_hash.clone()).unwrap();
        }

        // When one of its backers withdraws.
        Environment::new(None, Some(participants[0].clone()), None);
        contract.remove_update_vote().unwrap();

        // Then the payload is refused until the threshold is restored.
        Environment::new(None, Some(participants[2].clone()), None);
        let refused = contract.submit_update(dtos::Update::Code(code.clone()));
        assert_matches!(
            refused,
            Err(Error::InvalidParameters(
                InvalidParameters::UpdateNotApproved
            ))
        );

        Environment::new(None, Some(participants[2].clone()), None);
        assert!(contract.vote_update(approved_hash).unwrap());
        contract
            .submit_update(dtos::Update::Code(code))
            .expect("restoring the threshold makes the update submittable again");
    }

    #[test]
    fn vote_update__should_replace_the_voters_previous_vote() {
        // Given
        let (mut contract, participants) = running_contract();
        Environment::new(None, Some(participants[0].clone()), None);
        contract.vote_update(update_hash(1)).unwrap();

        // When
        contract.vote_update(update_hash(2)).unwrap();

        // Then
        assert_eq!(
            contract.update_votes(),
            expected_votes(&[(2, &[participants[0].clone()])])
        );
    }

    #[test]
    #[should_panic(expected = "protocol must be in running state")]
    fn vote_update__should_panic_when_not_running() {
        let (_, resharing_state) = gen_resharing_state(NUM_DOMAINS);
        let mut contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Resharing(resharing_state));
        Environment::new(None, Some(gen_account_id()), None);

        let _ = contract.vote_update(update_hash(1));
    }

    #[test]
    #[should_panic(expected = "not a voter")]
    fn vote_update__should_panic_for_non_participants() {
        let (mut contract, _) = running_contract();
        Environment::new(None, Some(gen_account_id()), None);

        let _ = contract.vote_update(update_hash(1));
    }

    #[test]
    fn submit_update__should_reject_a_hash_that_is_not_approved() {
        // Given
        let (mut contract, participants) = running_contract();
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
        let (mut contract, participants) = running_contract();
        let code = vec![1, 2, 3];
        let approved_hash = near_mpc_sdk::update::hash(&dtos::Update::Code(code.clone()));
        for participant in &participants[..THRESHOLD as usize] {
            Environment::new(None, Some(participant.clone()), None);
            contract.vote_update(approved_hash.clone()).unwrap();
        }
        assert_eq!(
            contract.update_votes(),
            BTreeMap::from([(
                approved_hash.to_proposal_hash(),
                participants[..THRESHOLD as usize]
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>()
            )])
        );

        // When
        Environment::new(None, Some(participants[2].clone()), None);
        let first = contract.submit_update(dtos::Update::Code(code.clone()));
        let second = contract.submit_update(dtos::Update::Code(code));

        // Then applying it consumes every vote, so it cannot be applied twice.
        first.unwrap();
        assert_eq!(contract.update_votes(), BTreeMap::new());
        assert_matches!(
            second,
            Err(Error::InvalidParameters(
                InvalidParameters::UpdateNotApproved
            ))
        );
    }

    #[test]
    fn submit_update__should_reject_an_approved_but_invalid_config() {
        // Given an approved config whose launcher TTL is below the attestation validity window.
        let (mut contract, participants) = running_contract();
        let mut config = test_utils::contract_types::dummy_config(1);
        config.launcher_hash_unused_ttl_seconds = 0;
        let update = dtos::Update::Config(config);
        for participant in &participants[..THRESHOLD as usize] {
            Environment::new(None, Some(participant.clone()), None);
            contract
                .vote_update(near_mpc_sdk::update::hash(&update))
                .unwrap();
        }

        // When
        let result = contract.submit_update(update);

        // Then
        let err = result.expect_err("invalid config must be rejected");
        assert!(
            format!("{err:?}").contains("launcher_hash_unused_ttl_seconds"),
            "error should point at the invalid field, got: {err:?}"
        );
    }

    #[test]
    fn remove_update_vote__should_drop_the_callers_vote() {
        // Given
        let (mut contract, participants) = running_contract();
        Environment::new(None, Some(participants[0].clone()), None);
        contract.vote_update(update_hash(1)).unwrap();
        Environment::new(None, Some(participants[1].clone()), None);
        contract.vote_update(update_hash(2)).unwrap();

        // When
        Environment::new(None, Some(participants[0].clone()), None);
        contract.remove_update_vote().unwrap();

        // Then
        assert_eq!(
            contract.update_votes(),
            expected_votes(&[(2, &[participants[1].clone()])])
        );
    }

    #[test]
    #[should_panic(expected = "protocol must be in running state")]
    fn remove_update_vote__should_panic_when_not_running() {
        let (_, resharing_state) = gen_resharing_state(NUM_DOMAINS);
        let mut contract =
            MpcContract::new_from_protocol_state(ProtocolContractState::Resharing(resharing_state));
        Environment::new(None, Some(gen_account_id()), None);

        let _ = contract.remove_update_vote();
    }

    /// Callers authorized to drive `remove_non_participant_update_votes`.
    enum AuthorizedCaller {
        /// The contract calling itself (the cleanup promise spawned after resharing).
        ContractItself,
        /// A current participant calling directly.
        Participant,
    }

    /// Votes from two accounts that are no longer participants plus one from a current one.
    fn contract_with_stale_votes() -> (MpcContract, Vec<AccountId>, Vec<AccountId>) {
        let (mut contract, participants) = running_contract();
        let former_set = gen_participants(2);
        let former: Vec<AccountId> = former_set
            .participants()
            .iter()
            .map(|(account_id, _, _)| account_id.clone())
            .collect();
        let ProtocolContractState::Running(running_state) = &contract.protocol_state else {
            unreachable!("running_contract builds a running state")
        };
        let threshold_parameters = running_state.parameters.clone();
        for account_id in &former {
            contract.update_votes.vote(
                &update_hash(1),
                authenticated(&former_set, account_id),
                &threshold_parameters,
            );
        }
        Environment::new(None, Some(participants[0].clone()), None);
        contract.vote_update(update_hash(1)).unwrap();
        (contract, participants, former)
    }

    #[rstest]
    #[case::contract_itself(AuthorizedCaller::ContractItself)]
    #[case::participant(AuthorizedCaller::Participant)]
    fn remove_non_participant_update_votes__should_keep_only_participant_votes(
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
        contract.remove_non_participant_update_votes().unwrap();

        // Then
        assert_eq!(
            contract.update_votes(),
            expected_votes(&[(1, &[participants[0].clone()])])
        );
    }

    #[test]
    fn remove_non_participant_update_votes__should_reject_unauthorized_caller() {
        // Given
        let (mut contract, participants, former) = contract_with_stale_votes();
        let before = contract.update_votes();
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
        let result = contract.remove_non_participant_update_votes();

        // Then
        assert_matches!(
            result,
            Err(Error::InvalidState(InvalidState::NotParticipant { account_id }))
                if account_id == outsider
        );
        assert_eq!(contract.update_votes(), before);
    }

    #[test]
    fn update_votes__should_start_empty() {
        // Given
        let (contract, _) = running_contract();

        // When
        let votes = contract.update_votes();

        // Then
        assert_eq!(votes, BTreeMap::new());
    }
}
