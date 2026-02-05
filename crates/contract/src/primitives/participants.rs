use crate::errors::{Error, InvalidCandidateSet, InvalidParameters};

use near_account_id::AccountId;
use near_sdk::{near, PublicKey};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt::Display};

#[cfg(any(test, feature = "test-utils"))]
use {crate::tee::tee_state::NodeId, std::collections::BTreeSet};

pub mod hpke {
    pub type PublicKey = [u8; 32];
}

#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ParticipantInfo {
    pub url: String,
    /// The public key used for verifying messages.
    pub sign_pk: PublicKey,
}

#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
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

/// The data stored for each participant.
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ParticipantData {
    /// Unique identifier assigned to the participant, used for threshold signing.
    pub id: ParticipantId,
    /// Connection and verification info (URL and public key) for this participant.
    pub info: ParticipantInfo,
}

/// Helper type for JSON serialization that matches the old Vec-based format.
#[derive(Serialize)]
struct ParticipantsJson {
    next_id: ParticipantId,
    participants: Vec<(AccountId, ParticipantId, ParticipantInfo)>,
}

/// Helper enum for deserializing both old Vec and new Map formats.
#[derive(Deserialize)]
#[serde(untagged)]
enum ParticipantsField {
    /// Old format: array of [AccountId, ParticipantId, ParticipantInfo] tuples
    Vec(Vec<(AccountId, ParticipantId, ParticipantInfo)>),
    /// New format: map of AccountId -> ParticipantData
    Map(BTreeMap<AccountId, ParticipantData>),
}

/// Helper for deserializing Participants from either Vec or Map format.
#[derive(Deserialize)]
struct ParticipantsJsonDeserialize {
    next_id: ParticipantId,
    participants: ParticipantsField,
}

impl From<ParticipantsJsonDeserialize> for Participants {
    fn from(json: ParticipantsJsonDeserialize) -> Self {
        let participants = match json.participants {
            ParticipantsField::Vec(vec) => vec
                .into_iter()
                .map(|(account_id, id, info)| (account_id, ParticipantData { id, info }))
                .collect(),
            ParticipantsField::Map(map) => map,
        };
        Participants {
            next_id: json.next_id,
            participants,
        }
    }
}

impl From<Participants> for ParticipantsJson {
    fn from(p: Participants) -> Self {
        let participants = p
            .participants
            .into_iter()
            .map(|(account_id, data)| (account_id, data.id, data.info))
            .collect();
        ParticipantsJson {
            next_id: p.next_id,
            participants,
        }
    }
}

/// Stores participants indexed by [`AccountId`] for O(log n) lookups.
///
/// # Serialization
/// For JSON backward compatibility with the old `Vec`-based format, this struct
/// serializes `participants` as an array of `[AccountId, ParticipantId, ParticipantInfo]` tuples.
/// Deserialization supports both the old Vec format and the new Map format.
#[near(serializers=[borsh])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
#[serde(into = "ParticipantsJson", from = "ParticipantsJsonDeserialize")]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub struct Participants {
    /// The next [`ParticipantId`] to assign when inserting a new participant.
    /// Always greater than all existing participant IDs.
    next_id: ParticipantId,
    /// Primary storage mapping [`AccountId`] to [`ParticipantData`].
    participants: BTreeMap<AccountId, ParticipantData>,
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
            participants: BTreeMap::new(),
        }
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.participants.len()
    }

    pub fn insert_with_id(
        &mut self,
        account_id: AccountId,
        info: ParticipantInfo,
        id: ParticipantId,
    ) -> Result<(), Error> {
        if self.participants.contains_key(&account_id) {
            return Err(InvalidParameters::ParticipantAlreadyInSet.into());
        }
        // ID uniqueness guaranteed by next_id invariant:
        // - All existing IDs are < next_id (enforced by validate())
        // - If id >= next_id, it's new; if id < next_id, rejected below
        if id < self.next_id() {
            return Err(InvalidParameters::ParticipantAlreadyUsed.into());
        }
        self.participants
            .insert(account_id, ParticipantData { id, info });
        self.next_id.0 = id.0 + 1;
        Ok(())
    }

    pub fn insert(&mut self, account_id: AccountId, info: ParticipantInfo) -> Result<(), Error> {
        self.insert_with_id(account_id, info, self.next_id)
    }

    /// Returns an iterator over participants as tuples.
    /// The iteration order is by [`AccountId`] (lexicographic).
    pub fn participants(
        &self,
    ) -> impl Iterator<Item = (&AccountId, &ParticipantId, &ParticipantInfo)> {
        self.participants
            .iter()
            .map(|(account_id, data)| (account_id, &data.id, &data.info))
    }

    pub fn next_id(&self) -> ParticipantId {
        self.next_id
    }

    /// Validates that the fields are coherent:
    ///  - All account IDs are unique (enforced by [`BTreeMap`] key).
    ///  - The next_id is greater than all participant IDs.
    pub fn validate(&self) -> Result<(), Error> {
        // Uniqueness of `AccountId` is guaranteed by `BTreeMap`
        // Verify next_id invariant: `next_id` must be greater than all participant IDs
        for data in self.participants.values() {
            if self.next_id.get() <= data.id.get() {
                return Err(InvalidCandidateSet::IncoherentParticipantIds.into());
            }
        }
        Ok(())
    }

    /// O(log n) lookup to check if an account is a participant.
    pub fn is_participant(&self, account_id: &AccountId) -> bool {
        self.participants.contains_key(account_id)
    }

    pub fn init(
        next_id: ParticipantId,
        participants: Vec<(AccountId, ParticipantId, ParticipantInfo)>,
    ) -> Self {
        let expected_len = participants.len();
        let map: BTreeMap<_, _> = participants
            .into_iter()
            .map(|(account_id, id, info)| (account_id, ParticipantData { id, info }))
            .collect();
        assert_eq!(
            map.len(),
            expected_len,
            "Participants::init received duplicate AccountIds"
        );
        Self {
            next_id,
            participants: map,
        }
    }

    /// O(log n) lookup to get participant info by account ID.
    pub fn info(&self, account_id: &AccountId) -> Option<&ParticipantInfo> {
        self.participants.get(account_id).map(|data| &data.info)
    }

    /// O(log n) update of participant info.
    pub fn update_info(
        &mut self,
        account_id: AccountId,
        new_info: ParticipantInfo,
    ) -> Result<(), Error> {
        if let Some(data) = self.participants.get_mut(&account_id) {
            data.info = new_info;
            Ok(())
        } else {
            Err(crate::errors::InvalidState::NotParticipant.into())
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Participants {
    /// O(log n) lookup - test only. Returns ParticipantId by AccountId.
    pub fn id(&self, account_id: &AccountId) -> Result<ParticipantId, Error> {
        self.participants
            .get(account_id)
            .map(|data| data.id)
            .ok_or_else(|| crate::errors::InvalidState::NotParticipant.into())
    }

    /// O(n) reverse lookup - test only. Returns AccountId by ParticipantId.
    pub fn account_id(&self, id: &ParticipantId) -> Result<AccountId, Error> {
        self.participants
            .iter()
            .find(|(_, data)| data.id == *id)
            .map(|(a_id, _)| a_id.clone())
            .ok_or_else(|| crate::errors::InvalidState::ParticipantIndexOutOfRange.into())
    }

    /// Returns a subset of the participants according to the given range of indices.
    /// Note: Since [`BTreeMap`] iteration is by [`AccountId`] order, this may differ from [`Vec`] order.
    pub fn subset(&self, range: std::ops::Range<usize>) -> Participants {
        let map: BTreeMap<_, _> = self
            .participants
            .iter()
            .skip(range.start)
            .take(range.end - range.start)
            .map(|(a, data)| (a.clone(), data.clone()))
            .collect();
        Participants {
            next_id: self.next_id,
            participants: map,
        }
    }

    pub fn add_random_participants_till_n(&mut self, n: usize) {
        let mut rng = rand::thread_rng();
        while self.len() < n {
            let (account, pinfo) =
                crate::primitives::test_utils::gen_participant(rand::Rng::gen(&mut rng));
            self.insert(account, pinfo).unwrap();
        }
    }

    pub fn remove(&mut self, account: &AccountId) {
        self.participants.remove(account);
    }

    /// Returns the set of [`NodeId`]s corresponding to the participants.
    /// Note that the `account_public_key` field in [`NodeId`] is `None`.
    /// This is because [`NodeId`] is used in contexts where `account_public_key` is not needed (only TLS key is needed).  
    pub fn get_node_ids(&self) -> BTreeSet<NodeId> {
        self.participants()
            .map(|(account_id, _, p_info)| NodeId {
                account_id: account_id.clone(),
                tls_public_key: p_info.sign_pk.clone(),
                account_public_key: None,
            })
            .collect()
    }
}

#[cfg(test)]
pub mod tests {
    use crate::primitives::{
        participants::{ParticipantId, Participants},
        test_utils::gen_accounts_and_info,
    };
    use rand::Rng;

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
}
