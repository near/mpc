use super::initializing::InitializingContractState;
use super::key_event::KeyEvent;
use super::resharing::ResharingContractState;
use crate::errors::{DomainError, Error, InvalidParameters, VoteError};
use crate::primitives::{
    domain::{AddDomainsVotes, DomainConfig, DomainRegistry},
    key_state::{AuthenticatedAccountId, AuthenticatedParticipantId, EpochId, Keyset},
    thresholds::ThresholdParameters,
    votes::ThresholdParametersVotes,
};
use near_sdk::{near, AccountId};
use std::collections::{BTreeSet, HashSet};

/// In this state, the contract is ready to process signature requests.
///
/// Proposals can be submitted to modify the state:
///  - vote_add_domains, upon threshold agreement, transitions into the
///    Initializing state to generate keys for new domains.
///  - vote_new_parameters, upon threshold agreement, transitions into the
///    Resharing state to reshare keys for new participants and also change the
///    threshold if desired.
#[near(serializers=[borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunningContractState {
    /// The domains for which we have a key ready for signature processing.
    pub domains: DomainRegistry,
    /// The keys that are currently in use; for each domain provides an unique identifier for a
    /// distributed key, so that the nodes can identify which local keyshare to use.
    pub keyset: Keyset,
    /// The current participants and threshold.
    pub parameters: ThresholdParameters,
    /// Votes for proposals for a new set of participants and threshold.
    pub parameters_votes: ThresholdParametersVotes,
    /// Votes for proposals to add new domains.
    pub add_domains_votes: AddDomainsVotes,
    /// The previous epoch id for a resharing state that was cancelled.
    /// This epoch id is tracked, as the next time the state transitions to resharing,
    /// we can't reuse a previously cancelled epoch id.
    pub previously_cancelled_resharing_epoch_id: Option<EpochId>,
}

impl RunningContractState {
    pub fn new(domains: DomainRegistry, keyset: Keyset, parameters: ThresholdParameters) -> Self {
        RunningContractState {
            domains,
            keyset,
            parameters,
            parameters_votes: ThresholdParametersVotes::default(),
            add_domains_votes: AddDomainsVotes::default(),
            previously_cancelled_resharing_epoch_id: None,
        }
    }

    pub fn transition_to_resharing_no_checks(
        &mut self,
        proposal: &ThresholdParameters,
    ) -> Option<ResharingContractState> {
        if let Some(first_domain) = self.domains.get_domain_by_index(0) {
            let epoch_id = self.prospective_epoch_id();

            Some(ResharingContractState {
                previous_running_state: RunningContractState::new(
                    self.domains.clone(),
                    self.keyset.clone(),
                    self.parameters.clone(),
                ),
                reshared_keys: Vec::new(),
                resharing_key: KeyEvent::new(epoch_id, first_domain.clone(), proposal.clone()),
                cancellation_requests: HashSet::new(),
            })
        } else {
            // A new ThresholdParameters was proposed, but we have no keys, so directly
            // transition into Running state but bump the EpochId.
            *self = RunningContractState::new(
                self.domains.clone(),
                Keyset::new(self.keyset.epoch_id.next(), Vec::new()),
                proposal.clone(),
            );
            None
        }
    }

    /// Casts a vote for `proposal` to the current state, propagating any errors.
    /// Returns ResharingContractState if the proposal is accepted.
    pub fn vote_new_parameters(
        &mut self,
        prospective_epoch_id: EpochId,
        proposal: &ThresholdParameters,
    ) -> Result<Option<ResharingContractState>, Error> {
        let expected_prospective_epoch_id = self.prospective_epoch_id();

        if prospective_epoch_id != expected_prospective_epoch_id {
            return Err(InvalidParameters::EpochMismatch {
                expected: expected_prospective_epoch_id,
                provided: prospective_epoch_id,
            }
            .into());
        }

        if self.process_new_parameters_proposal(proposal)? {
            return Ok(self.transition_to_resharing_no_checks(proposal));
        }
        Ok(None)
    }

    pub fn prospective_epoch_id(&self) -> EpochId {
        match self.previously_cancelled_resharing_epoch_id {
            // If `cancelled_epoch_id`, then a resharing has already
            // been attempted but was cancelled.
            // We must make sure to not reuse previously used prospective epoch ids,
            // and continue from the last prospective epoch id for the previous resharing attempt.
            Some(cancelled_epoch_id) => cancelled_epoch_id,
            // No resharing has been attempted for this running state.
            None => self.keyset.epoch_id,
        }
        .next()
    }

    /// Casts a vote for `proposal`, removing any previous votes by `env::signer_account_id()`.
    /// Fails if the proposal is invalid or the signer is not a proposed participant.
    /// Returns true if all participants of the proposed parameters voted for it.
    pub(super) fn process_new_parameters_proposal(
        &mut self,
        proposal: &ThresholdParameters,
    ) -> Result<bool, Error> {
        // ensure the proposal is valid against the current parameters
        self.parameters.validate_incoming_proposal(proposal)?;

        // ensure the signer is a proposed participant
        let candidate = AuthenticatedAccountId::new(proposal.participants())?;

        // If the signer is not a participant of the current epoch, they can only vote after
        // `threshold` participant of the current epoch have casted their vote to admit them.
        if AuthenticatedAccountId::new(self.parameters.participants()).is_err() {
            let n_votes = self
                .parameters_votes
                .n_votes(proposal, self.parameters.participants());
            if n_votes < self.parameters.threshold().value() {
                return Err(VoteError::VoterPending.into());
            }
        }

        // finally, vote.
        let n_votes = self.parameters_votes.vote(proposal, candidate);
        Ok(proposal.participants().len() as u64 == n_votes)
    }

    /// Casts a vote for the signer participant to add new domains, replacing any previous vote.
    /// If the number of votes for the same set of new domains reaches the number of participants,
    /// returns the InitializingContractState we should transition into to generate keys for these
    /// new domains.
    pub fn vote_add_domains(
        &mut self,
        domains: Vec<DomainConfig>,
    ) -> Result<Option<InitializingContractState>, Error> {
        if domains.is_empty() {
            return Err(DomainError::AddDomainsMustAddAtLeastOneDomain.into());
        }
        let participant = AuthenticatedParticipantId::new(self.parameters.participants())?;
        let n_votes = self.add_domains_votes.vote(domains.clone(), &participant);
        if self.parameters.participants().len() as u64 == n_votes {
            let new_domains = self.domains.add_domains(domains.clone())?;
            Ok(Some(InitializingContractState {
                generated_keys: self.keyset.domains.clone(),
                domains: new_domains,
                epoch_id: self.keyset.epoch_id,
                generating_key: KeyEvent::new(
                    self.keyset.epoch_id,
                    domains[0].clone(),
                    self.parameters.clone(),
                ),
                cancel_votes: BTreeSet::new(),
            }))
        } else {
            Ok(None)
        }
    }

    pub fn is_participant(&self, account_id: &AccountId) -> bool {
        self.parameters.participants().is_participant(account_id)
    }
}

#[cfg(test)]
pub mod running_tests {
    use crate::primitives::domain::AddDomainsVotes;
    use crate::primitives::test_utils::gen_threshold_params;
    use crate::state::key_event::tests::Environment;
    use crate::state::test_utils::gen_valid_params_proposal;
    use crate::{
        primitives::votes::ThresholdParametersVotes, state::test_utils::gen_running_state,
    };

    fn test_running_for(num_domains: usize) {
        let mut state = gen_running_state(num_domains);
        println!(
            "Participants: {}, threshold: {}",
            state.parameters.participants().len(),
            state.parameters.threshold().value()
        );
        let mut env = Environment::new(None, None, None);
        let participants = state.parameters.participants().clone();
        // Assert that random proposals get rejected.
        for (account_id, _, _) in participants.participants() {
            let ksp = gen_threshold_params(30);
            env.set_signer(account_id);
            assert!(state
                .vote_new_parameters(state.keyset.epoch_id.next(), &ksp)
                .is_err());
        }
        // Assert that proposals of the wrong epoch ID get rejected.
        {
            let ksp = gen_valid_params_proposal(&state.parameters);
            env.set_signer(&participants.participants()[0].0);
            assert!(state
                .vote_new_parameters(state.keyset.epoch_id, &ksp)
                .is_err());
            assert!(state
                .vote_new_parameters(state.keyset.epoch_id.next().next(), &ksp)
                .is_err());
        }
        // Assert that disagreeing proposals do not reach consensus.
        // Generate an extra proposal for the next step.
        let mut proposals = Vec::new();
        for i in 0..participants.participants().len() + 1 {
            loop {
                let proposal = gen_valid_params_proposal(&state.parameters);
                if proposals.contains(&proposal) {
                    continue;
                }
                if i < participants.participants().len()
                    && !proposal
                        .participants()
                        .is_participant(&participants.participants()[i].0)
                {
                    continue;
                }
                proposals.push(proposal.clone());
                break;
            }
        }
        for (i, (account_id, _, _)) in participants.participants().iter().enumerate() {
            env.set_signer(account_id);
            assert!(state
                .vote_new_parameters(state.keyset.epoch_id.next(), &proposals[i])
                .unwrap()
                .is_none());
        }

        // Now let's vote for agreeing proposals.
        let proposal = proposals.last().unwrap().clone();

        let original_epoch_id = state.keyset.epoch_id;
        let mut resharing = None;
        // existing participants vote
        let mut n_votes = 0;
        for (account_id, _, _) in participants.participants().iter() {
            if !proposal.participants().is_participant(account_id) {
                continue;
            }
            n_votes += 1;
            env.set_signer(account_id);
            let res = state
                .vote_new_parameters(state.keyset.epoch_id.next(), &proposal)
                .unwrap();
            if n_votes < proposal.participants().len() || num_domains == 0 {
                assert!(res.is_none());
            } else {
                resharing = Some(res.unwrap());
            }
        }
        // candidates vote
        for (account_id, _, _) in proposal.participants().participants().iter() {
            if participants.is_participant(account_id) {
                continue;
            }
            n_votes += 1;
            env.set_signer(account_id);
            let res = state
                .vote_new_parameters(state.keyset.epoch_id.next(), &proposal)
                .unwrap();
            if n_votes < proposal.participants().len() || num_domains == 0 {
                assert!(res.is_none());
            } else {
                resharing = Some(res.unwrap());
            }
        }
        if num_domains == 0 {
            // If there are no domains, we should transition directly to Running with a higher
            // epoch ID, not resharing.
            assert_eq!(state.keyset.epoch_id, original_epoch_id.next());
            assert_eq!(state.parameters_votes, ThresholdParametersVotes::default());
            assert_eq!(state.add_domains_votes, AddDomainsVotes::default());
        } else {
            let resharing = resharing.unwrap();
            assert_eq!(
                resharing.previous_running_state.parameters,
                state.parameters
            );
            assert_eq!(
                resharing.prospective_epoch_id(),
                state.keyset.epoch_id.next(),
            );
            assert_eq!(resharing.resharing_key.proposed_parameters(), &proposal);
        }
    }

    #[test]
    fn test_running_0() {
        test_running_for(0);
    }

    #[test]
    fn test_running_1() {
        test_running_for(1);
    }

    #[test]
    fn test_running_2() {
        test_running_for(2);
    }

    #[test]
    fn test_running_3() {
        test_running_for(3);
    }

    #[test]
    fn test_running_4() {
        test_running_for(4);
    }
}
