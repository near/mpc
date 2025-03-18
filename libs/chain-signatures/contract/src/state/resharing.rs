use super::key_event::KeyEvent;
use super::running::RunningContractState;
use crate::errors::Error;
use crate::primitives::domain::AddDomainsVotes;
use crate::primitives::key_state::{EpochId, KeyEventId, KeyForDomain, Keyset};
use crate::primitives::thresholds::ThresholdParameters;
use crate::primitives::votes::ThresholdParametersVotes;
use near_sdk::near;

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct ResharingContractState {
    pub previous_running_state: RunningContractState,
    pub reshared_keys: Vec<KeyForDomain>,
    pub resharing_key: KeyEvent,
}

impl From<&legacy_contract::ResharingContractState> for ResharingContractState {
    fn from(_state: &legacy_contract::ResharingContractState) -> Self {
        unimplemented!("Cannot migrate from Resharing state")
    }
}

impl ResharingContractState {
    pub fn previous_keyset(&self) -> &Keyset {
        &self.previous_running_state.keyset
    }
    pub fn prospective_epoch_id(&self) -> EpochId {
        self.resharing_key.epoch_id()
    }
    /// Casts a vote for `proposal`, removing any exiting votes by `signer_account_id()`.
    /// Returns an error if `proposal` is invalid or signer not in the old partipicant set.
    /// Returns ResharingContract state if the proposal is accepted.
    pub fn vote_new_parameters(
        &mut self,
        proposal: &ThresholdParameters,
    ) -> Result<Option<ResharingContractState>, Error> {
        if self
            .previous_running_state
            .process_new_parameters_proposal(proposal)?
        {
            return Ok(Some(ResharingContractState {
                previous_running_state: RunningContractState::new(
                    self.previous_running_state.domains.clone(),
                    self.previous_running_state.keyset.clone(),
                    self.previous_running_state.parameters.clone(),
                ),
                reshared_keys: Vec::new(),
                resharing_key: KeyEvent::new(
                    self.prospective_epoch_id().next(),
                    self.previous_running_state
                        .domains
                        .get_domain_by_index(0)
                        .unwrap()
                        .clone(),
                    proposal.clone(),
                ),
            }));
        }
        Ok(None)
    }
}

// Leader API. Below functions shall only be called by a leader account
impl ResharingContractState {
    /// Starts a new reshare instance if there is no active reshare instance
    pub fn start(&mut self, event_max_idle_blocks: u64) -> Result<(), Error> {
        self.resharing_key.start(event_max_idle_blocks)
    }

    /// Casts a vote for `public_key` in `key_event_id`.
    /// Fails if `signer` is not a candidate, if the candidate already voted or if there is no active key event.
    /// Returns `RunningContractState` if `public_key` reaches the required votes.
    pub fn vote_reshared(
        &mut self,
        key_event_id: KeyEventId,
    ) -> Result<Option<RunningContractState>, Error> {
        let previous_key = self.previous_keyset().domains[self.reshared_keys.len()].clone();
        if self
            .resharing_key
            .vote_success(&key_event_id, previous_key.key.clone())?
        {
            let new_key = KeyForDomain {
                domain_id: key_event_id.domain_id,
                attempt: key_event_id.attempt_id,
                key: previous_key.key,
            };
            self.reshared_keys.push(new_key);
            if let Some(next_domain) = self
                .previous_running_state
                .domains
                .get_domain_by_index(self.reshared_keys.len())
            {
                self.resharing_key = KeyEvent::new(
                    self.prospective_epoch_id(),
                    next_domain.clone(),
                    self.resharing_key.proposed_parameters().clone(),
                );
            } else {
                return Ok(Some(RunningContractState::new(
                    self.previous_running_state.domains.clone(),
                    Keyset::new(self.prospective_epoch_id(), self.reshared_keys.clone()),
                    self.resharing_key.proposed_parameters().clone(),
                )));
            }
        }
        Ok(None)
    }

    /// Casts a vote to abort the current keygen instance.
    pub fn vote_abort(&mut self, key_event_id: KeyEventId) -> Result<(), Error> {
        self.resharing_key.vote_abort(key_event_id)
    }
}
#[cfg(test)]
mod tests {
    use crate::primitives::key_state::{AttemptId, KeyEventId};
    use crate::primitives::test_utils::gen_account_id;
    use crate::primitives::test_utils::gen_legacy_resharing_state;
    use crate::primitives::votes::ThresholdParametersVotes;
    use crate::state::key_event::tests::{find_leader, Environment};
    use crate::state::key_event::{InstanceStatus, KeyEvent};
    use crate::state::resharing::ResharingContractState;
    use crate::state::running::running_tests::{gen_running_state, gen_valid_ksp};
    use crate::state::running::RunningContractState;
    use near_sdk::AccountId;
    use std::collections::BTreeSet;

    fn gen_resharing_state() -> (Environment, ResharingContractState) {
        let env = Environment::new(Some(100), None, None);
        let current_state = gen_running_state();
        let proposal = gen_valid_ksp(&current_state.key_state);
        let key_id = KeyEventId::new(current_state.epoch_id(), AttemptId::new());
        let event_state = KeyEvent::new(key_id.epoch_id(), proposal);
        (
            env,
            ResharingContractState {
                current_state,
                event_state,
            },
        )
    }

    #[test]
    fn test_resharing_contract_state() {
        let (mut env, mut state) = gen_resharing_state();
        let candidates: BTreeSet<AccountId> = state
            .event_state
            .proposed_threshold_parameters()
            .participants()
            .participants()
            .iter()
            .map(|(aid, _, _)| aid.clone())
            .collect();
        let key_event = state.event_state.current_key_event_id();
        let leader = find_leader(&key_event.attempt(), &state.event_state);
        for c in &candidates {
            env.set_signer(c);
            // verify that each candidate is authorized
            assert!(state.event_state.authenticate_candidate().is_ok());
            // verify that no votes are casted before the reshare started.
            assert!(state.vote_reshared(key_event.clone(), 100).is_err());
            assert!(state.vote_abort(key_event.clone(), 100).is_err());
            if *c != leader.0 {
                assert!(state.start(100).is_err());
            }
        }
        // check that some randos can't vote
        for _ in 0..20 {
            env.set_signer(&gen_account_id());
            assert!(state.event_state.authenticate_candidate().is_err());
            assert!(state.vote_reshared(key_event.clone(), 100).is_err());
            assert!(state.vote_abort(key_event.clone(), 100).is_err());
            assert!(state.start(100).is_err());
        }
        // start the keygen:
        env.set_signer(&leader.0);
        assert!(state.start(0).is_ok());

        // assert that timed out votes do not count
        env.advance_block_height(1);
        for c in &candidates {
            env.set_signer(c);
            assert!(state.vote_reshared(key_event.clone(), 0).is_err());
            assert!(state.vote_abort(key_event.clone(), 0).is_err());
        }

        // check that some randos can't vote
        env.block_height -= 1;
        env.set();
        for _ in 0..20 {
            env.set_signer(&gen_account_id());
            assert!(state.event_state.authenticate_candidate().is_err());
            assert!(state.vote_reshared(key_event.clone(), 100).is_err());
            assert!(state.vote_abort(key_event.clone(), 100).is_err());
            assert!(state.start(100).is_err());
        }

        // assert that votes for a different reshare do not count
        let ke = KeyEventId::new(key_event.epoch_id(), key_event.attempt().next());
        for c in &candidates {
            env.set_signer(c);
            assert!(state.vote_reshared(ke.clone(), 10).is_err());
            assert!(state.vote_abort(ke.clone(), 10).is_err());
        }
        let ke = KeyEventId::new(key_event.epoch_id().next(), key_event.attempt());
        for c in &candidates {
            env.set_signer(c);
            assert!(state.vote_reshared(ke.clone(), 10).is_err());
            assert!(state.vote_abort(ke.clone(), 10).is_err());
        }

        // find leader for next attempt
        env.advance_block_height(100);
        let leader = find_leader(&key_event.attempt().next(), &state.event_state);
        env.set_signer(&leader.0);
        assert!(state.start(0).is_ok());
        let key_event = KeyEventId::new(key_event.epoch_id(), key_event.attempt().next());
        assert_eq!(key_event, state.event_state.current_key_event_id());

        // assert that valid votes get counted correctly:
        let mut res: Option<RunningContractState> = None;
        for (i, c) in candidates.clone().into_iter().enumerate() {
            env.set_signer(&c);
            res = state.vote_reshared(key_event.clone(), 0).unwrap();
            // everybody voting for the same key
            if ((i + 1) as u64) < state.event_state.event_threshold().value() {
                assert!(res.is_none());
            } else {
                assert!(res.is_some());
                break;
            }
            // assert we can't abort after voting
            assert!(state.vote_abort(key_event.clone(), 0).is_err());
        }
        // assert running state is correct
        let running_state = res.unwrap();
        assert_eq!(
            running_state.key_state.threshold(),
            state.event_state.proposed_threshold(),
        );
        assert_eq!(
            *running_state.key_state.participants(),
            *state
                .event_state
                .proposed_threshold_parameters()
                .participants()
        );
        assert_eq!(
            *running_state.public_key(),
            *state.current_state.public_key()
        );
        assert_eq!(running_state.key_state.key_event_id(), key_event);
        assert_eq!(
            running_state.key_state_votes,
            ThresholdParametersVotes::new()
        );

        // assert that the instance resets after a timeout
        env.advance_block_height(100);
        let leader = find_leader(&key_event.attempt().next(), &state.event_state);
        env.set_signer(&leader.0);
        assert!(state.start(0).is_ok());
        let key_event = KeyEventId::new(key_event.epoch_id(), key_event.attempt().next());
        assert_eq!(key_event, state.event_state.current_key_event_id());
        // assert that valid aborts get counted correctly:
        for (i, c) in candidates.clone().into_iter().enumerate() {
            env.set_signer(&c);
            // assert we can abort
            let x = state.vote_abort(key_event.clone(), 0).unwrap();
            if state
                .event_state
                .proposed_threshold_parameters()
                .participants()
                .count()
                - ((i + 1) as u64)
                < state.event_state.event_threshold().value()
            {
                assert_eq!(x, InstanceStatus::Replaced);
                let key_event = KeyEventId::new(key_event.epoch_id(), key_event.attempt().next());
                assert_eq!(state.event_state.current_key_event_id(), key_event);
                break;
            } else {
                assert_eq!(x, InstanceStatus::Pending);
            }
            // assert we can't abort after aborting
            assert!(state.vote_abort(key_event.clone(), 0).is_err());
            // assert we can't vote after aborting
            assert!(state.vote_reshared(key_event.clone(), 0).is_err());
        }
        // restart the keygen
        let attempt = key_event.attempt().next();
        let leader = find_leader(&attempt, &state.event_state);
        println!("{:?}", state.event_state.current_key_event_id());
        println!("{:?}", attempt);
        env.set_signer(&leader.0);
        let res = state.start(0);
        println!("{:?}", res);
        println!("{:?}", state.event_state.current_key_event_id());
        assert!(res.is_ok());
    }
}
