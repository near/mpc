use crate::errors::Error;
use crate::errors::KeyEventError;
use crate::errors::VoteError;
use crate::primitives::domain::DomainConfig;
use crate::primitives::key_state::KeyEventId;
use crate::primitives::key_state::{AttemptId, EpochId};
use crate::primitives::thresholds::ThresholdParameters;
use crate::state::AuthenticatedParticipantId;
use near_sdk::{env, log, near};
use near_sdk::{BlockHeight, PublicKey};
use std::collections::BTreeSet;

/// Stores the information for the current key event:
/// - the epoch_id for which the new keyshares shall be valid.
/// - the proposed threshold parameters
/// - the key event threshold
/// - the current instance of the key event
/// - a leader order, pseudo-randomly generated from `env::random_seed()` and `epoch_id`.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct KeyEvent {
    epoch_id: EpochId,
    domain: DomainConfig,
    parameters: ThresholdParameters,
    instance: Option<KeyEventInstance>,
    next_attempt_id: AttemptId,
}

impl KeyEvent {
    pub fn new(
        epoch_id: EpochId,
        domain: DomainConfig,
        proposed_parameters: ThresholdParameters,
    ) -> Self {
        KeyEvent {
            epoch_id,
            domain,
            parameters: proposed_parameters,
            instance: None,
            next_attempt_id: AttemptId::new(),
        }
    }

    // Start a new key event instance as the leader, if one isn't already active.
    pub fn start(&mut self, timeout_blocks: u64) -> Result<(), Error> {
        self.cleanup_if_timed_out();
        if self.instance.is_some() {
            return Err(KeyEventError::ActiveKeyEvent.into());
        }
        self.verify_leader()?;
        self.instance = Some(KeyEventInstance::new(self.next_attempt_id, timeout_blocks));
        self.next_attempt_id = self.next_attempt_id.next();
        Ok(())
    }

    /// Ensures that the signer account matches the leader participant.
    /// The leader is the one with the lowest participant ID.
    pub fn verify_leader(&self) -> Result<(), Error> {
        if &self
            .parameters
            .participants()
            .participants()
            .iter()
            .min_by_key(|(_, participant_id, _)| participant_id)
            .unwrap()
            .0
            != &env::signer_account_id()
        {
            return Err(VoteError::VoterNotLeader.into());
        }
        Ok(())
    }

    pub fn epoch_id(&self) -> EpochId {
        self.epoch_id
    }

    pub fn proposed_parameters(&self) -> &ThresholdParameters {
        &self.parameters
    }

    /// Casts a vote for `public_key` in `key_event_id`.
    /// Fails if `signer` is not a candidate, if the candidate already voted or if there is no active key event.
    /// Returns KeyEventId if all participants have reached consensus, None otherwise.
    pub fn vote_success(
        &mut self,
        key_event_id: &KeyEventId,
        public_key: PublicKey,
    ) -> Result<bool, Error> {
        let candidate = self.verify_vote(key_event_id)?;
        match self
            .instance
            .as_mut()
            .unwrap()
            .vote_success(candidate, public_key)?
        {
            VoteSuccessResult::Voted(count) => {
                if count == self.parameters.participants().len() {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            VoteSuccessResult::PublicKeyDisagreement => {
                log!("Public key disagreement; aborting key event instance.");
                self.instance = None;
                Ok(false)
            }
        }
    }

    /// Casts a vote to abort the current keygen instance.
    /// A new instance needs to be started later to start a new keygen attempt.
    pub fn vote_abort(&mut self, key_event_id: KeyEventId) -> Result<(), Error> {
        self.verify_vote(&key_event_id)?;
        self.instance = None;
        Ok(())
    }

    fn cleanup_if_timed_out(&mut self) {
        if let Some(instance) = self.instance.as_ref() {
            if !instance.active() {
                self.instance = None;
            }
        }
    }

    fn verify_vote(
        &mut self,
        key_event_id: &KeyEventId,
    ) -> Result<AuthenticatedParticipantId, Error> {
        let candidate = AuthenticatedParticipantId::new(&self.parameters.participants())?;
        self.cleanup_if_timed_out();
        let Some(instance) = self.instance.as_ref() else {
            return Err(KeyEventError::NoActiveKeyEvent.into());
        };
        if key_event_id.epoch_id != self.epoch_id
            || key_event_id.domain_id != self.domain.id
            || key_event_id.attempt_id != instance.attempt_id
        {
            return Err(KeyEventError::KeyEventIdMismatch.into());
        }
        Ok(candidate)
    }

    #[cfg(test)]
    pub fn current_key_event_id(&self) -> KeyEventId {
        let instance = self.instance.as_ref().unwrap();
        KeyEventId::new(self.epoch_id, self.domain.id, instance.attempt_id)
    }

    #[cfg(test)]
    pub fn is_active(&self) -> bool {
        self.instance.is_some()
    }
}

#[derive(Debug, PartialEq)]
enum VoteSuccessResult {
    /// Voted successfully, returning the number of votes.
    Voted(usize),
    /// Participants disagreed on the public key, vote failed.
    PublicKeyDisagreement,
}

#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Default)]
pub struct KeyEventInstance {
    attempt_id: AttemptId,
    started_in: BlockHeight,
    expires_on: BlockHeight,
    completed: BTreeSet<AuthenticatedParticipantId>,
    public_key: Option<PublicKey>,
}

impl KeyEventInstance {
    pub fn new(attempt_id: AttemptId, timeout_blocks: u64) -> Self {
        KeyEventInstance {
            attempt_id,
            started_in: env::block_height(),
            expires_on: env::block_height() + timeout_blocks,
            completed: BTreeSet::new(),
            public_key: None,
        }
    }

    pub fn active(&self) -> bool {
        env::block_height() < self.expires_on
    }

    /// Commits the vote of `candidate` to `public_key`, returning the total number of votes for `public_key`.
    /// Fails if the candidate already submitted a vote.
    pub fn vote_success(
        &mut self,
        candidate: AuthenticatedParticipantId,
        public_key: PublicKey,
    ) -> Result<VoteSuccessResult, Error> {
        if let Some(existing_public_key) = &self.public_key {
            if existing_public_key != &public_key {
                return Ok(VoteSuccessResult::PublicKeyDisagreement);
            }
        } else {
            self.public_key = Some(public_key);
        }
        // return error if the candidate alredy submitted a vote.
        if self.completed.contains(&candidate) {
            return Err(VoteError::VoteAlreadySubmitted.into());
        }
        // label candidate as complete
        self.completed.insert(candidate.clone());
        Ok(VoteSuccessResult::Voted(self.completed.len()))
    }
}

#[cfg(test)]
pub mod tests {
    use super::AuthenticatedLeader;
    use crate::primitives::key_state::tests::gen_parameters_proposal;
    use crate::primitives::key_state::{AttemptId, EpochId, KeyEventId};
    use crate::primitives::participants::{AuthenticatedParticipantId, ParticipantId};
    use crate::primitives::test_utils::{gen_account_id, gen_seed};
    use crate::state::key_event::{InstanceStatus, KeyEvent, KeyEventInstance, Tally};
    use near_sdk::{test_utils::VMContextBuilder, testing_env, AccountId, BlockHeight};
    use rand::Rng;
    use std::collections::BTreeSet;
    use std::mem;

    pub struct Environment {
        pub signer: AccountId,
        pub block_height: BlockHeight,
        pub seed: [u8; 32],
    }
    impl Environment {
        pub fn new(
            block_height: Option<BlockHeight>,
            signer: Option<AccountId>,
            seed: Option<[u8; 32]>,
        ) -> Self {
            let seed = seed.unwrap_or(gen_seed());
            let mut ctx = VMContextBuilder::new();
            let block_height = block_height.unwrap_or(rand::thread_rng().gen());
            ctx.block_height(block_height);
            ctx.random_seed(seed);
            let signer = signer.unwrap_or(gen_account_id());
            ctx.signer_account_id(signer.clone());
            testing_env!(ctx.build());
            Environment {
                signer,
                block_height,
                seed,
            }
        }
        pub fn set_signer(&mut self, signer: &AccountId) {
            self.signer = signer.clone();
            self.set();
        }
        pub fn set(&self) {
            let mut ctx = VMContextBuilder::new();
            ctx.block_height(self.block_height);
            ctx.random_seed(self.seed);
            ctx.signer_account_id(self.signer.clone());
            testing_env!(ctx.build());
        }
        pub fn set_block_height(&mut self, block_height: BlockHeight) {
            self.block_height = block_height;
            self.set();
        }
        pub fn advance_block_height(&mut self, delta: BlockHeight) {
            self.block_height += delta;
            self.set();
        }
    }

    pub fn find_leader(kes: &KeyEvent) -> (AccountId, ParticipantId) {
        let (account_id, participant_id, _) = kes
            .proposed_parameters()
            .participants()
            .participants()
            .iter()
            .min_by_key(|(_, id, _)| id)
            .unwrap();
        (account_id.clone(), participant_id.clone())
    }
}
