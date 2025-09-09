use crate::errors::{Error, InvalidCandidateSet, InvalidParameters};
use attestation::attestation::Attestation;
use near_sdk::{near, AccountId, PublicKey};
use std::{
    collections::{BTreeSet, HashSet},
    fmt::Display,
};

pub mod hpke {
    pub type PublicKey = [u8; 32];
}

#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, Clone)]
// TODO: Implement (de)serialization in backwards compatible way.
pub struct ParticipantInfo {
    pub url: String,
    /// The public key used for verifying messages.
    pub sign_pk: PublicKey,
    pub account_id: AccountId,
    pub participant_id: ParticipantId,
    pub attestation: Attestation,
}

#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ParticipantId(pub u32);
impl ParticipantId {
    pub fn get(&self) -> u32 {
        self.0
    }
    pub fn next(&self) -> Self {
        ParticipantId(self.0 + 1)
    }
}

impl Display for ParticipantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Participants {
    next_id: ParticipantId,
    participants: Vec<ParticipantInfo>,
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
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.participants.len()
    }
    pub fn insert(&mut self, participant_info: ParticipantInfo) -> Result<(), Error> {
        let next_id = self.next_id();

        if self.participants.iter().any(
            |ParticipantInfo {
                 participant_id,
                 account_id: a_id,
                 ..
             }| *a_id == participant_info.account_id || *participant_id == next_id,
        ) {
            return Err(InvalidParameters::ParticipantAlreadyInSet.into());
        }

        self.participants.push(participant_info);

        self.next_id.0 = next_id.0 + 1;

        Ok(())
    }

    pub fn participants(&self) -> &[ParticipantInfo] {
        &self.participants
    }

    pub fn next_id(&self) -> ParticipantId {
        self.next_id.clone()
    }

    /// Validates that the fields are coherent:
    ///  - All participant IDs are unique.
    ///  - All account IDs are unique.
    ///  - The next_id is greater than all participant IDs.
    pub fn validate(&self) -> Result<(), Error> {
        let participants = self.participants();

        let unique_participant_ids: BTreeSet<&ParticipantId> =
            participants.iter().map(|p| &p.participant_id).collect();

        let unique_account_ids: HashSet<&AccountId> =
            participants.iter().map(|p| &p.account_id).collect();

        let participants_ids_are_unique = unique_participant_ids.len() == participants.len();
        let account_ids_are_unique = unique_account_ids.len() == participants.len();
        let next_id_is_greater_than_all_participant_ids = participants
            .iter()
            .all(|p| p.participant_id.get() < self.next_id.get());

        let fields_are_coherent = account_ids_are_unique
            && participants_ids_are_unique
            && next_id_is_greater_than_all_participant_ids;

        if fields_are_coherent {
            Ok(())
        } else {
            Err(InvalidCandidateSet::IncoherentParticipantIds.into())
        }
    }

    pub fn is_participant(&self, account_id: &AccountId) -> bool {
        self.participants
            .iter()
            .any(|p| &p.account_id == account_id)
    }

    pub fn init(next_id: ParticipantId, participants: Vec<ParticipantInfo>) -> Self {
        Self {
            next_id,
            participants,
        }
    }
}

// #[cfg(any(test, feature = "test-utils"))]
// impl Participants {
//     pub fn id(&self, account_id: &AccountId) -> Result<ParticipantId, Error> {
//         self.participants
//             .iter()
//             .find(|(a_id, _, _)| a_id == account_id)
//             .map(|(_, p_id, _)| p_id.clone())
//             .ok_or_else(|| crate::errors::InvalidState::NotParticipant.into())
//     }
//     pub fn info(&self, account_id: &AccountId) -> Option<&ParticipantInfo> {
//         self.participants
//             .iter()
//             .find(|(a_id, _, _)| a_id == account_id)
//             .map(|(_, _, info)| info)
//     }
//     pub fn account_id(&self, id: &ParticipantId) -> Result<AccountId, Error> {
//         self.participants
//             .iter()
//             .find(|(_, p_id, _)| p_id == id)
//             .map(|(a_id, _, _)| a_id.clone())
//             .ok_or_else(|| crate::errors::InvalidState::ParticipantIndexOutOfRange.into())
//     }
//     pub fn is_participant(&self, account_id: &AccountId) -> bool {
//         self.participants
//             .iter()
//             .any(|(a_id, _, _)| a_id == account_id)
//     }
//     /// Returns a subset of the participants according to the given range of indices.
//     pub fn subset(&self, range: std::ops::Range<usize>) -> Participants {
//         let participants = self.participants[range]
//             .iter()
//             .map(|(a, p, i)| (a.clone(), p.clone(), i.clone()));
//         Participants {
//             next_id: self.next_id.clone(),
//             participants: participants.collect(),
//         }
//     }
//     pub fn add_random_participants_till_n(&mut self, n: usize) {
//         let mut rng = rand::thread_rng();
//         while self.len() < n {
//             let (account, pinfo) =
//                 crate::primitives::test_utils::gen_participant(rand::Rng::gen(&mut rng));
//             self.insert(account, pinfo).unwrap();
//         }
//     }
//     pub fn remove(&mut self, account: &AccountId) {
//         if let Some(pos) = self
//             .participants
//             .iter()
//             .position(|(a_id, _, _)| a_id == account)
//         {
//             self.participants.remove(pos);
//         }
//     }
// }

// #[cfg(test)]
// pub mod tests {
//     use crate::primitives::{
//         participants::{ParticipantId, Participants},
//         test_utils::gen_accounts_and_info,
//     };
//     use rand::Rng;

//     #[test]
//     fn test_participants() {
//         let n = rand::thread_rng().gen_range(1..800);
//         let expected = gen_accounts_and_info(n);
//         let mut participants = Participants::new();
//         for (idx, (account_id, info)) in expected.iter().enumerate() {
//             participants
//                 .insert(account_id.clone(), info.clone())
//                 .unwrap();
//             assert_eq!(*participants.info(account_id).unwrap(), info.clone());
//             assert_eq!(
//                 participants.account_id(&ParticipantId(idx as u32)).unwrap(),
//                 *account_id
//             );
//             assert_eq!(
//                 participants.id(account_id).unwrap(),
//                 ParticipantId(idx as u32)
//             );
//             assert!(participants.is_participant(account_id));
//         }
//         assert_eq!(participants.len(), n);
//         for i in 0..n {
//             assert!(participants.account_id(&ParticipantId(i as u32)).is_ok());
//         }
//         assert!(participants.validate().is_ok());
//     }
// }
