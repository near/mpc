use super::domain::DomainId;
use super::participants::{ParticipantId, Participants};
use crate::errors::{DomainError, Error, InvalidState};
use near_sdk::{env, near, PublicKey};

#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct EpochId(u64);

impl EpochId {
    pub fn next(&self) -> Self {
        EpochId(self.0 + 1)
    }
    pub fn new(epoch_id: u64) -> Self {
        EpochId(epoch_id)
    }
    pub fn get(&self) -> u64 {
        self.0
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct AttemptId(u64);

impl AttemptId {
    pub fn new() -> Self {
        AttemptId(0)
    }
    pub fn next(&self) -> Self {
        AttemptId(&self.0 + 1)
    }
    pub fn get(&self) -> u64 {
        self.0
    }
    pub fn legacy_attempt_id() -> Self {
        AttemptId(0)
    }
}

impl Default for AttemptId {
    fn default() -> Self {
        Self::new()
    }
}

/// A unique identifier for a key event:
/// `epoch_id` the epoch for which the key is supposed to be active.
/// `attempt`: an identifier for the attempt during the epoch.
/// Note: `attempt` is just a counter.
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyEventId {
    pub epoch_id: EpochId,
    pub domain_id: DomainId,
    pub attempt_id: AttemptId,
}

impl KeyEventId {
    pub fn new(epoch_id: EpochId, domain_id: DomainId, attempt_id: AttemptId) -> Self {
        KeyEventId {
            epoch_id,
            domain_id,
            attempt_id,
        }
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyForDomain {
    pub domain_id: DomainId,
    pub key: PublicKey,
    pub attempt: AttemptId,
}

#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Keyset {
    pub epoch_id: EpochId,
    pub domains: Vec<KeyForDomain>,
}

impl Keyset {
    pub fn new(epoch_id: EpochId, domains: Vec<KeyForDomain>) -> Self {
        Keyset { epoch_id, domains }
    }

    pub fn public_key(&self, domain_id: DomainId) -> Result<PublicKey, Error> {
        Ok(self
            .domains
            .iter()
            .find(|k| k.domain_id == domain_id)
            .ok_or_else(|| DomainError::NoSuchDomain)?
            .key
            .clone())
    }
}

/// This struct is supposed to contain the participant id associated to the account `env::signer_account_id()`
/// It is supposed to be constructed only by DKState.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuthenticatedParticipantId(ParticipantId);
impl AuthenticatedParticipantId {
    pub fn get(&self) -> ParticipantId {
        self.0.clone()
    }
    pub fn new(participants: &Participants) -> Result<Self, Error> {
        let signer = env::signer_account_id();
        participants
            .participants()
            .iter()
            .find(|(a_id, _, _)| *a_id == signer)
            .map(|(_, p_id, _)| AuthenticatedParticipantId(p_id.clone()))
            .ok_or_else(|| InvalidState::NotParticipant.into())
    }
}

#[cfg(test)]
pub mod tests {
    use super::DKState;
    use crate::primitives::key_state::AttemptId;
    use crate::primitives::key_state::EpochId;
    use crate::primitives::key_state::KeyEventId;
    use crate::primitives::key_state::KeyStateProposal;
    use crate::primitives::participants::tests::assert_candidate_migration;
    use crate::primitives::participants::tests::assert_participant_migration;
    use crate::primitives::test_utils::gen_account_id;
    use crate::primitives::test_utils::gen_legacy_initializing_state;
    use crate::primitives::test_utils::gen_legacy_resharing_state;
    use crate::primitives::test_utils::gen_legacy_running_state;
    use crate::primitives::test_utils::min_thrershold;
    use crate::primitives::test_utils::{gen_key_event_id, gen_pk, gen_threshold_params};
    use crate::primitives::thresholds::DKGThreshold;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use rand::Rng;

    const MAX_N: usize = 900;
    #[test]
    fn test_epoch_id() {
        let id = rand::thread_rng().gen();
        let epoch_id = EpochId::new(id);
        assert_eq!(epoch_id.get(), id);
        assert_eq!(epoch_id.next().get(), id + 1);
    }

    #[test]
    fn test_attempt_id() {
        let attempt_id = AttemptId::new();
        assert_eq!(attempt_id.get(), 0);
        assert_eq!(attempt_id.next().get(), 1);
    }

    #[test]
    fn test_key_event_id() {
        let id = rand::thread_rng().gen();
        let epoch_id = EpochId::new(id);
        let key_event_id = KeyEventId::new(epoch_id.clone(), AttemptId::new());
        assert_eq!(epoch_id, key_event_id.epoch_id());
        assert_eq!(id, key_event_id.epoch_id().get());
        assert_eq!(AttemptId::new(), key_event_id.attempt());
        assert_eq!(0, key_event_id.attempt().get());
        assert_eq!(KeyEventId::new_migrated_key(5).epoch_id(), EpochId::new(5));
        assert_eq!(KeyEventId::new_migrated_key(5).attempt().get(), 0);
    }

    #[test]
    fn test_key_state_proposal() {
        let proposed_threshold_parameters = gen_threshold_params(MAX_N);
        for i in 0..proposed_threshold_parameters.participants().len() {
            let key_event_threshold = DKGThreshold::new(i);
            assert!(KeyStateProposal::new(
                proposed_threshold_parameters.clone(),
                key_event_threshold
            )
            .is_err());
        }
        let candidates = proposed_threshold_parameters.participants();
        let i = proposed_threshold_parameters.participants().len();
        let key_event_threshold = DKGThreshold::new(i);
        let ksp = KeyStateProposal::new(proposed_threshold_parameters.clone(), key_event_threshold);
        assert!(ksp.is_ok());
        let ksp = ksp.unwrap();
        assert!(ksp.validate().is_ok());
        assert_eq!(ksp.key_event_threshold().value(), i);
        // test authentication:
        KeyStateProposal::new(
            proposed_threshold_parameters.clone(),
            DKGThreshold::new(proposed_threshold_parameters.participants().len()),
        )
        .unwrap();
        for (account_id, _, _) in candidates.participants() {
            let mut context = VMContextBuilder::new();
            context.signer_account_id(account_id.clone());
            testing_env!(context.build());
            let mut context = VMContextBuilder::new();
            context.signer_account_id(gen_account_id());
            testing_env!(context.build());
        }
    }

    #[test]
    fn test_key_state_proposal_migration_initializing() {
        let n = rand::thread_rng().gen_range(2..MAX_N);
        let min_k = min_thrershold(n);
        // we must allow previously invalid parameters as well
        let k_invalid = rand::thread_rng().gen_range(1..min_k);
        let k_valid = rand::thread_rng().gen_range(min_k..n + 1);
        for k in [k_invalid, k_valid] {
            let legacy_state = gen_legacy_initializing_state(n, k);
            let migrated_ksp: KeyStateProposal = (&legacy_state).into();
            assert_eq!(migrated_ksp.key_event_threshold().value(), n as u64);
            let found = migrated_ksp.proposed_threshold_parameters();
            assert_eq!(found.threshold().value(), k as u64);
            assert_eq!(found.participants().len(), n as u64);
            assert_candidate_migration(&legacy_state.candidates, found.participants());
        }
    }

    #[test]
    fn test_dkstate_migration_running() {
        let n = rand::thread_rng().gen_range(2..MAX_N);
        let min_k = min_thrershold(n);
        // we must allow previously invalid parameters as well
        let k_invalid = rand::thread_rng().gen_range(1..min_k);
        let k_valid = rand::thread_rng().gen_range(min_k..n + 1);
        for k in [k_invalid, k_valid] {
            let legacy_state = gen_legacy_running_state(n, k);
            let migrated_dkg: DKState = (&legacy_state).into();
            assert_eq!(migrated_dkg.threshold().value(), k as u64);
            assert_eq!(*migrated_dkg.public_key(), legacy_state.public_key);
            assert_eq!(migrated_dkg.epoch_id().get(), legacy_state.epoch);
            assert_participant_migration(&legacy_state.participants, migrated_dkg.participants());
        }
    }

    #[test]
    fn test_dkstate_key_state_proposal_migration_resharing() {
        let n = rand::thread_rng().gen_range(2..MAX_N);
        let min_k = min_thrershold(n);
        // we must allow previously invalid paramters as well
        let k_invalid = rand::thread_rng().gen_range(1..min_k);
        let k_valid = rand::thread_rng().gen_range(min_k..n + 1);
        for k in [k_invalid, k_valid] {
            let legacy_state = gen_legacy_resharing_state(n, k);
            let migrated_dkg: DKState = (&legacy_state).into();
            assert_eq!(migrated_dkg.threshold().value(), k as u64);
            assert_eq!(*migrated_dkg.public_key(), legacy_state.public_key);
            assert_eq!(migrated_dkg.epoch_id().get(), legacy_state.old_epoch);
            assert_participant_migration(
                &legacy_state.old_participants,
                migrated_dkg.participants(),
            );
            let migrated_ksp: KeyStateProposal = (&legacy_state).into();
            let found = migrated_ksp.proposed_threshold_parameters();
            assert_eq!(found.threshold().value(), k as u64);
            assert_eq!(migrated_ksp.key_event_threshold().value(), n as u64);
            assert_eq!(found.participants().len(), n as u64);
            assert_participant_migration(&legacy_state.new_participants, found.participants());
        }
    }
}
