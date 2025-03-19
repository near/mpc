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
    use crate::primitives::domain::DomainId;
    use crate::primitives::key_state::{AttemptId, AuthenticatedParticipantId, KeyForDomain};
    use crate::primitives::key_state::{EpochId, Keyset};
    use crate::primitives::test_utils::gen_account_id;
    use crate::primitives::test_utils::{gen_pk, gen_threshold_params};
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
    fn test_keyset() {
        let domain_id0 = DomainId(0);
        let domain_id1 = DomainId(3);
        let key0 = gen_pk();
        let key1 = gen_pk();
        let keyset = Keyset::new(
            EpochId::new(5),
            vec![
                KeyForDomain {
                    domain_id: domain_id0,
                    key: key0.clone(),
                    attempt: AttemptId::new(),
                },
                KeyForDomain {
                    domain_id: domain_id1,
                    key: key1.clone(),
                    attempt: AttemptId::new(),
                },
            ],
        );
        assert_eq!(keyset.public_key(domain_id0).unwrap(), key0);
        assert_eq!(keyset.public_key(domain_id1).unwrap(), key1);
        assert!(keyset.public_key(DomainId(1)).is_err());
    }

    #[test]
    fn test_authenticated_participant_id() {
        let proposed_parameters = gen_threshold_params(MAX_N);
        assert!(proposed_parameters.validate().is_ok());
        for (account_id, _, _) in proposed_parameters.participants().participants() {
            let mut context = VMContextBuilder::new();
            context.signer_account_id(account_id.clone());
            testing_env!(context.build());
            assert!(AuthenticatedParticipantId::new(proposed_parameters.participants()).is_ok());
            let mut context = VMContextBuilder::new();
            context.signer_account_id(gen_account_id());
            testing_env!(context.build());
            assert!(AuthenticatedParticipantId::new(proposed_parameters.participants()).is_err());
        }
    }
}
