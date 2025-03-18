use super::key_event::KeyEvent;
use super::running::RunningContractState;
use crate::errors::Error;
use crate::primitives::domain::DomainRegistry;
use crate::primitives::key_state::{
    AuthenticatedParticipantId, EpochId, KeyEventId, KeyForDomain, Keyset,
};
use near_sdk::{near, PublicKey};
use std::collections::BTreeSet;

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct InitializingContractState {
    pub domains: DomainRegistry,
    pub epoch_id: EpochId,
    pub generated_keys: Vec<KeyForDomain>,
    pub generating_key: KeyEvent,
    pub cancel_votes: BTreeSet<AuthenticatedParticipantId>,
}

impl InitializingContractState {
    /// Starts a new keygen instance.
    /// Returns an Error if the signer is not the leader.
    pub fn start(&mut self, event_max_idle_blocks: u64) -> Result<(), Error> {
        self.generating_key.start(event_max_idle_blocks)
    }

    /// Casts a vote for `public_key` in `key_event_id`.
    /// Fails if `signer` is not a candidate, if the candidate already voted or if there is no active key event.
    /// Returns `RunningContractState` if `public_key` reaches the required votes.
    pub fn vote_pk(
        &mut self,
        key_event_id: KeyEventId,
        public_key: PublicKey,
    ) -> Result<Option<RunningContractState>, Error> {
        if self
            .generating_key
            .vote_success(&key_event_id, public_key.clone())?
        {
            self.generated_keys.push(KeyForDomain {
                domain_id: key_event_id.domain_id,
                key: public_key.clone(),
                attempt: key_event_id.attempt_id,
            });
            if let Some(next_domain) = self.domains.get_domain_by_index(self.generated_keys.len()) {
                self.generating_key = KeyEvent::new(
                    self.epoch_id,
                    next_domain.clone(),
                    self.generating_key.proposed_parameters().clone(),
                );
            } else {
                return Ok(Some(RunningContractState::new(
                    self.domains.clone(),
                    Keyset::new(self.epoch_id, self.generated_keys.clone()),
                    self.generating_key.proposed_parameters().clone(),
                )));
            }
        }
        Ok(None)
    }

    /// Casts a vote to abort the current keygen instance.
    pub fn vote_abort(&mut self, key_event_id: KeyEventId) -> Result<(), Error> {
        self.generating_key.vote_abort(key_event_id)
    }

    /// Casts a vote to cancel key generation. Any keys that have already been generated
    /// are kept and we transition into Running state; remaining domains are deleted.
    pub fn vote_cancel(&mut self) -> Result<Option<RunningContractState>, Error> {
        let participant = AuthenticatedParticipantId::new(
            self.generating_key.proposed_parameters().participants(),
        )?;
        if self.cancel_votes.insert(participant) {
            if self.cancel_votes.len()
                >= self
                    .generating_key
                    .proposed_parameters()
                    .threshold()
                    .value() as usize
            {
                let mut domains = self.domains.clone();
                domains.retain_domains(self.generated_keys.len());
                return Ok(Some(RunningContractState::new(
                    domains,
                    Keyset::new(self.epoch_id, self.generated_keys.clone()),
                    self.generating_key.proposed_parameters().clone(),
                )));
            }
        }
        Ok(None)
    }
}

impl From<&legacy_contract::InitializingContractState> for InitializingContractState {
    fn from(_state: &legacy_contract::InitializingContractState) -> Self {
        unimplemented!("Cannot upgrade from legacy Initializing state")
    }
}

#[cfg(test)]
mod tests {
    use super::InitializingContractState;
    use crate::primitives::domain::tests::{gen_domain_registry, gen_domains_to_add};
    use crate::primitives::domain::DomainId;
    use crate::primitives::key_state::{tests::gen_parameters_proposal, EpochId};
    use crate::primitives::key_state::{AttemptId, KeyEventId};
    use crate::primitives::test_utils::{
        gen_account_id, gen_legacy_initializing_state, gen_pk, gen_threshold_params,
    };
    use crate::primitives::votes::ThresholdParametersVotes;
    use crate::state::key_event::tests::{find_leader, Environment};
    use crate::state::key_event::{InstanceStatus, KeyEvent};
    use crate::state::running::running_tests::gen_running_state;
    use crate::state::running::RunningContractState;
    use near_sdk::AccountId;
    use rand::Rng;
    use std::collections::BTreeSet;

    #[test]
    fn test_migration() {
        let n = 200;
        let k = 2;
        let legacy_state = gen_legacy_initializing_state(n, k);
        let state: InitializingContractState = (&legacy_state).into();
        assert_eq!(
            state
                .keygen
                .proposed_threshold_parameters()
                .threshold()
                .value(),
            k as u64
        );
        assert_eq!(state.keygen.event_threshold().value(), n as u64);
        assert_eq!(state.keygen.current_key_event_id().epoch_id().get(), 0u64);
        assert_eq!(state.keygen.current_key_event_id().attempt().get(), 0u64);
    }

    fn gen_initializing_state(
        num_domains: usize,
        num_generated: usize,
    ) -> (Environment, InitializingContractState) {
        let mut env = Environment::new(None, None, None);
        let mut running = gen_running_state(num_generated);
        let domains_to_add = gen_domains_to_add(&running.domains, num_domains - num_generated);

        let mut initializing_state = None;
        for (account, _, _) in &running.parameters.participants().participants()
            [0..running.parameters.threshold().value() as usize]
        {
            env.set_signer(account);
            assert!(initializing_state.is_none());
            initializing_state = running.vote_add_domains(domains_to_add).unwrap();
        }
        let initializing_state = initializing_state
            .expect("Enough votes to add domains should transition into initializing");
        (env, initializing_state)
    }

    fn test_initializing_contract_state(num_domains: usize, num_already_generated: usize) {
        let (mut env, mut state) = gen_initializing_state(num_domains, num_already_generated);
        let candidates: BTreeSet<AccountId> = state
            .generating_key
            .proposed_parameters()
            .participants()
            .participants()
            .iter()
            .map(|(aid, _, _)| aid.clone())
            .collect();

        let mut resulting_running_state: Option<RunningContractState> = None;
        for i in num_already_generated..num_domains {
            println!("Testing domain {}", i);
            assert!(!state.generating_key.is_active());
            let first_key_event_id = KeyEventId {
                attempt_id: AttemptId::new(),
                domain_id: state.domains.get_domain_by_index(i).unwrap().id,
                epoch_id: state.epoch_id,
            };
            let leader = find_leader(&state.generating_key);
            for c in &candidates {
                env.set_signer(c);
                // verify that no votes can be cast before the keygen started.
                assert!(state.vote_pk(first_key_event_id.clone(), gen_pk()).is_err());
                assert!(state.vote_abort(first_key_event_id.clone()).is_err());
                if *c != leader.0 {
                    assert!(state.start(1).is_err());
                }
            }
            // start the keygen; verify that the keygen is for the right epoch and domain ID.
            env.set_signer(&leader.0);
            assert!(state.start(0).is_ok());
            let key_event = state.generating_key.current_key_event_id();
            assert_eq!(key_event, first_key_event_id);

            // check that randos can't vote.
            for _ in 0..20 {
                env.set_signer(&gen_account_id());
                assert!(state.vote_pk(key_event.clone(), gen_pk()).is_err());
                assert!(state.vote_abort(key_event.clone()).is_err());
            }

            // check that timing out will abort the instance
            env.advance_block_height(1);
            for c in &candidates {
                env.set_signer(c);
                assert!(state.vote_pk(key_event.clone(), gen_pk()).is_err());
                assert!(state.vote_abort(key_event.clone()).is_err());
                assert!(!state.generating_key.is_active());
            }

            // assert that votes for a different keygen do not count
            env.set_signer(&leader.0);
            assert!(state.start(0).is_ok());
            let key_event = state.generating_key.current_key_event_id();
            let bad_key_events = [
                KeyEventId::new(
                    key_event.epoch_id,
                    key_event.domain_id,
                    key_event.attempt_id.next(),
                ),
                KeyEventId::new(
                    key_event.epoch_id,
                    DomainId(key_event.domain_id.0),
                    key_event.attempt_id,
                ),
                KeyEventId::new(
                    key_event.epoch_id.next(),
                    key_event.domain_id,
                    key_event.attempt_id,
                ),
            ];
            for bad_key_event in bad_key_events {
                for c in &candidates {
                    env.set_signer(c);
                    assert!(state.vote_pk(bad_key_event.clone(), gen_pk()).is_err());
                    assert!(state.vote_abort(bad_key_event.clone()).is_err());
                }
            }

            // assert that voting for different keys will fail
            for (j, account) in candidates.iter().enumerate() {
                env.set_signer(account);
                let res = state.vote_pk(key_event.clone(), gen_pk());
                // the first vote goes through, the second vote resets the instance; the third and subsequent ones fail.
                if j < 2 {
                    assert!(res.expect("Should not fail").is_none());
                } else {
                    assert!(!state.generating_key.is_active());
                    assert!(res.is_err());
                }
            }

            // check that vote_abort immediately causes failure.
            env.set_signer(&leader.0);
            assert!(state.start(0).is_ok());
            let key_event = state.generating_key.current_key_event_id();
            env.set_signer(candidates.iter().next().unwrap());
            assert!(state.vote_abort(key_event.clone()).is_ok());
            assert!(!state.generating_key.is_active());

            // assert that valid votes get counted correctly
            env.set_signer(&leader.0);
            assert!(state.start(0).is_ok());
            let key_event = state.generating_key.current_key_event_id();
            let pk = gen_pk();
            for (i, c) in candidates.clone().into_iter().enumerate() {
                env.set_signer(&c);
                assert!(resulting_running_state.is_none());
                resulting_running_state = state.vote_pk(key_event.clone(), pk.clone()).unwrap();
                assert!(state.vote_abort(key_event.clone()).is_err());
            }
        }

        // assert that the final running state is correct
        let running_state = resulting_running_state.unwrap();
        assert_eq!(
            &running_state.parameters,
            state.generating_key.proposed_parameters(),
        );
        assert_eq!(running_state.keyset.epoch_id, state.epoch_id);
        assert_eq!(running_state.keyset.domains, state.generated_keys);
        assert_eq!(running_state.keyset.domains.len(), num_domains);
        assert_eq!(running_state.domains, state.domains);
        assert_eq!(
            running_state.key_state_votes,
            ThresholdParametersVotes::new()
        );
    }
}
