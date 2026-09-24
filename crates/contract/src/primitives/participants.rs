use crate::errors::{Error, InvalidCandidateSet, InvalidParameters};

use near_account_id::AccountId;
use near_mpc_contract_interface::types::Ed25519PublicKey;
use near_sdk::near;
use std::collections::BTreeSet;

pub use near_mpc_contract_interface::types::{
    MAX_PARTICIPANT_URL_BYTES, ParticipantId, ParticipantUrl,
};

pub mod hpke {
    pub type PublicKey = [u8; 32];
}

#[near(serializers=[borsh])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ParticipantInfo {
    pub url: ParticipantUrl,
    /// The Ed25519 public key used for P2P TLS.
    pub tls_public_key: Ed25519PublicKey,
}

#[near(serializers=[borsh])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Participants {
    next_id: ParticipantId,
    participants: Vec<(AccountId, ParticipantId, ParticipantInfo)>,
}

impl Default for Participants {
    fn default() -> Self {
        Self::new()
    }
}

impl Participants {
    pub fn new() -> Self {
        Participants {
            next_id: ParticipantId(0),
            participants: Vec::new(),
        }
    }

    #[expect(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.participants.len()
    }

    pub fn insert_with_id(
        &mut self,
        account_id: AccountId,
        info: ParticipantInfo,
        id: ParticipantId,
    ) -> Result<(), Error> {
        if self
            .participants
            .iter()
            .any(|(a_id, p_id, _)| *a_id == account_id || *p_id == id)
        {
            return Err(InvalidParameters::ParticipantAlreadyInSet.into());
        }
        if id < self.next_id() {
            return Err(InvalidParameters::ParticipantAlreadyUsed.into());
        }
        self.participants.push((account_id.clone(), id, info));
        self.next_id.0 = id.0 + 1;
        Ok(())
    }

    pub fn insert(&mut self, account_id: AccountId, info: ParticipantInfo) -> Result<(), Error> {
        self.insert_with_id(account_id, info, self.next_id)
    }

    pub fn participants(&self) -> &Vec<(AccountId, ParticipantId, ParticipantInfo)> {
        &self.participants
    }

    pub fn next_id(&self) -> ParticipantId {
        self.next_id
    }

    /// Validates that the fields are coherent:
    ///  - All participant IDs are unique.
    ///  - All account IDs are unique.
    ///  - All TLS public keys are unique.
    ///  - The next_id is greater than all participant IDs.
    pub fn validate(&self) -> Result<(), Error> {
        let mut ids: BTreeSet<ParticipantId> = BTreeSet::new();
        let mut accounts: BTreeSet<AccountId> = BTreeSet::new();
        let mut tls_public_keys: BTreeSet<&Ed25519PublicKey> = BTreeSet::new();
        for (acc_id, pid, info) in &self.participants {
            accounts.insert(acc_id.clone());
            ids.insert(*pid);
            tls_public_keys.insert(&info.tls_public_key);
            if self.next_id.get() <= pid.get() {
                return Err(InvalidCandidateSet::ParticipantIdNotLessThanNextId {
                    id: pid.get(),
                    next_id: self.next_id.get(),
                }
                .into());
            }
        }
        if ids.len() != self.len() {
            return Err(InvalidCandidateSet::DuplicateParticipantIds.into());
        }
        if accounts.len() != self.len() {
            return Err(InvalidCandidateSet::DuplicateAccountIds.into());
        }
        if tls_public_keys.len() != self.len() {
            return Err(InvalidCandidateSet::DuplicateTlsPublicKeys.into());
        }
        Ok(())
    }

    pub fn is_participant<K: IdentifiesParticipant>(&self, id: &K) -> bool {
        id.identifies_participant_in(self)
    }

    pub fn init(
        next_id: ParticipantId,
        participants: Vec<(AccountId, ParticipantId, ParticipantInfo)>,
    ) -> Self {
        Self {
            next_id,
            participants,
        }
    }

    /// The account registered under `tls_public_key`, if any. The contract keys TEE
    /// attestations and foreign-chain configuration by TLS public key, so callers that
    /// introduce a key into the set use this to keep that mapping injective.
    pub fn account_with_tls_key(&self, tls_public_key: &Ed25519PublicKey) -> Option<&AccountId> {
        self.participants
            .iter()
            .find(|(_, _, info)| info.tls_public_key == *tls_public_key)
            .map(|(account_id, _, _)| account_id)
    }

    pub fn info(&self, account_id: &AccountId) -> Option<&ParticipantInfo> {
        self.participants
            .iter()
            .find(|(a_id, _, _)| a_id == account_id)
            .map(|(_, _, info)| info)
    }

    pub fn update_info(
        &mut self,
        account_id: AccountId,
        new_info: ParticipantInfo,
    ) -> Result<(), Error> {
        for (participant_account_id, _, participant_info) in self.participants.iter_mut() {
            if *participant_account_id == account_id {
                *participant_info = new_info.clone();
                return Ok(());
            }
        }
        Err(crate::errors::InvalidState::NotParticipant { account_id }.into())
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Participants {
    pub fn id(&self, account_id: &AccountId) -> Result<ParticipantId, Error> {
        self.participants
            .iter()
            .find(|(a_id, _, _)| a_id == account_id)
            .map(|(_, p_id, _)| *p_id)
            .ok_or_else(|| {
                crate::errors::InvalidState::NotParticipant {
                    account_id: account_id.clone(),
                }
                .into()
            })
    }

    pub fn account_id(&self, id: &ParticipantId) -> Result<AccountId, Error> {
        self.participants
            .iter()
            .find(|(_, p_id, _)| p_id == id)
            .map(|(a_id, _, _)| a_id.clone())
            .ok_or_else(|| crate::errors::InvalidState::ParticipantIndexOutOfRange.into())
    }

    /// Returns a subset of the participants according to the given range of indices.
    pub fn subset(&self, range: std::ops::Range<usize>) -> Participants {
        let participants = self.participants[range]
            .iter()
            .map(|(a, p, i)| (a.clone(), *p, i.clone()));
        Participants {
            next_id: self.next_id,
            participants: participants.collect(),
        }
    }

    pub fn add_random_participants_till_n(&mut self, n: usize) {
        let mut rng = rand::thread_rng();
        while self.len() < n {
            let (account, pinfo) =
                crate::primitives::test_utils::gen_participant(rand::Rng::r#gen(&mut rng));
            self.insert(account, pinfo).unwrap();
        }
    }

    pub fn remove(&mut self, account: &AccountId) {
        if let Some(pos) = self
            .participants
            .iter()
            .position(|(a_id, _, _)| a_id == account)
        {
            self.participants.remove(pos);
        }
    }
}

pub trait IdentifiesParticipant {
    fn identifies_participant_in(&self, participants: &Participants) -> bool;
}

impl IdentifiesParticipant for AccountId {
    fn identifies_participant_in(&self, participants: &Participants) -> bool {
        participants
            .participants
            .iter()
            .any(|(a_id, _, _)| a_id == self)
    }
}

impl IdentifiesParticipant for ParticipantId {
    fn identifies_participant_in(&self, participants: &Participants) -> bool {
        participants
            .participants
            .iter()
            .any(|(_, p_id, _)| p_id == self)
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
pub mod tests {
    use crate::{
        errors::{Error, InvalidCandidateSet},
        primitives::{
            participants::{ParticipantId, Participants},
            test_utils::{gen_accounts_and_info, gen_participant, gen_participants},
        },
    };
    use rand::Rng;

    #[test]
    fn validate__should_reject_participants_sharing_a_tls_public_key() {
        // Given
        let mut participants = gen_participants(3);
        let shared_tls_key = participants.participants()[0].2.tls_public_key.clone();
        participants.participants[2].2.tls_public_key = shared_tls_key;

        // When
        let result = participants.validate();

        // Then
        assert_eq!(
            result.unwrap_err(),
            Error::from(InvalidCandidateSet::DuplicateTlsPublicKeys)
        );
    }

    #[test]
    fn account_with_tls_key__should_find_the_holder_of_a_key() {
        // Given
        let participants = gen_participants(3);
        let (expected_account, _, info) = participants.participants()[1].clone();

        // When
        let found = participants.account_with_tls_key(&info.tls_public_key);

        // Then
        assert_eq!(found, Some(&expected_account));
    }

    #[test]
    fn test_participants() {
        let n = rand::thread_rng().gen_range(1..800);
        let expected = gen_accounts_and_info(n);
        let mut participants = Participants::new();
        for (idx, (account_id, info)) in expected.iter().enumerate() {
            participants
                .insert(account_id.clone(), info.clone())
                .unwrap();
            assert_eq!(*participants.info(account_id).unwrap(), info.clone());
            assert_eq!(
                participants.account_id(&ParticipantId(idx as u32)).unwrap(),
                *account_id
            );
            assert_eq!(
                participants.id(account_id).unwrap(),
                ParticipantId(idx as u32)
            );
            assert!(participants.is_participant(account_id));
        }
        assert_eq!(participants.len(), n);
        for i in 0..n {
            let _ = participants.account_id(&ParticipantId(i as u32)).unwrap();
        }
        participants
            .validate()
            .expect("Participants should validate after inserts");
    }

    #[test]
    fn test_validate_duplicate_participant_ids() {
        let (account1, info1) = gen_participant(0);
        let (account2, info2) = gen_participant(1);
        let participants = Participants::init(
            ParticipantId(2),
            vec![
                (account1, ParticipantId(0), info1),
                (account2, ParticipantId(0), info2), // same ID
            ],
        );
        assert_eq!(
            participants.validate().unwrap_err(),
            Error::from(InvalidCandidateSet::DuplicateParticipantIds)
        );
    }

    #[test]
    fn test_validate_duplicate_account_ids() {
        let (account, info1) = gen_participant(0);
        let (_, info2) = gen_participant(1);
        let participants = Participants::init(
            ParticipantId(2),
            vec![
                (account.clone(), ParticipantId(0), info1),
                (account, ParticipantId(1), info2), // same account
            ],
        );
        assert_eq!(
            participants.validate().unwrap_err(),
            Error::from(InvalidCandidateSet::DuplicateAccountIds)
        );
    }

    #[test]
    fn test_validate_participant_id_not_less_than_next_id() {
        let (account, info) = gen_participant(0);
        let participants = Participants::init(
            ParticipantId(0), // next_id = 0, but participant has id = 0
            vec![(account, ParticipantId(0), info)],
        );
        assert_eq!(
            participants.validate().unwrap_err(),
            Error::from(InvalidCandidateSet::ParticipantIdNotLessThanNextId { id: 0, next_id: 0 })
        );

        // Also test with id > next_id
        let (account2, info2) = gen_participant(1);
        let participants =
            Participants::init(ParticipantId(3), vec![(account2, ParticipantId(5), info2)]);
        assert_eq!(
            participants.validate().unwrap_err(),
            Error::from(InvalidCandidateSet::ParticipantIdNotLessThanNextId { id: 5, next_id: 3 })
        );
    }
}
