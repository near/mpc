use crate::errors::{Error, InvalidCandidateSet, InvalidParameters};

use near_account_id::AccountId;
use near_sdk::{near, PublicKey};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
};

#[cfg(any(test, feature = "test-utils"))]
use crate::tee::tee_state::NodeId;

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

/// A named entry for a participant, replacing the tuple `(AccountId, ParticipantId, ParticipantInfo)`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ParticipantEntry {
    pub account_id: AccountId,
    pub id: ParticipantId,
    pub info: ParticipantInfo,
}

/// Stores participants indexed by `AccountId` for O(log n) lookups.
///
/// Internally uses a `BTreeMap` but serializes as a `Vec` for backward compatibility
/// with existing contract state.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Participants {
    next_id: ParticipantId,
    /// Primary storage: AccountId -> (ParticipantId, ParticipantInfo)
    participants: BTreeMap<AccountId, (ParticipantId, ParticipantInfo)>,
    /// Secondary index to track used ParticipantIds for uniqueness validation
    used_ids: BTreeSet<ParticipantId>,
}

// Custom Borsh serialization to maintain wire compatibility with Vec-based format
mod borsh_impl {
    use super::*;
    use borsh::{BorshDeserialize, BorshSerialize};
    use std::io::{Read, Write};

    impl BorshSerialize for Participants {
        fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
            // Serialize next_id
            self.next_id.serialize(writer)?;
            // Convert BTreeMap to Vec for serialization (maintains original format)
            let vec: Vec<(AccountId, ParticipantId, ParticipantInfo)> = self
                .participants
                .iter()
                .map(|(account_id, (participant_id, info))| {
                    (account_id.clone(), *participant_id, info.clone())
                })
                .collect();
            vec.serialize(writer)?;
            Ok(())
        }
    }

    impl BorshDeserialize for Participants {
        fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
            let next_id = ParticipantId::deserialize_reader(reader)?;
            let vec: Vec<(AccountId, ParticipantId, ParticipantInfo)> =
                Vec::deserialize_reader(reader)?;

            let mut participants = BTreeMap::new();
            let mut used_ids = BTreeSet::new();
            for (account_id, participant_id, info) in vec {
                used_ids.insert(participant_id);
                participants.insert(account_id, (participant_id, info));
            }

            Ok(Participants {
                next_id,
                participants,
                used_ids,
            })
        }
    }

    #[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
    impl borsh::BorshSchema for Participants {
        fn declaration() -> borsh::schema::Declaration {
            "Participants".to_string()
        }

        fn add_definitions_recursively(
            definitions: &mut std::collections::BTreeMap<
                borsh::schema::Declaration,
                borsh::schema::Definition,
            >,
        ) {
            <ParticipantId as borsh::BorshSchema>::add_definitions_recursively(definitions);
            <Vec<(AccountId, ParticipantId, ParticipantInfo)> as borsh::BorshSchema>::add_definitions_recursively(definitions);

            let fields = borsh::schema::Fields::NamedFields(vec![
                ("next_id".to_string(), <ParticipantId as borsh::BorshSchema>::declaration()),
                ("participants".to_string(), <Vec<(AccountId, ParticipantId, ParticipantInfo)> as borsh::BorshSchema>::declaration()),
            ]);
            let definition = borsh::schema::Definition::Struct { fields };
            definitions.insert(Self::declaration(), definition);
        }
    }
}

// Custom JSON serialization to maintain wire compatibility
mod serde_impl {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    #[cfg_attr(
        all(feature = "abi", not(target_arch = "wasm32")),
        derive(schemars::JsonSchema)
    )]
    pub struct ParticipantsJson {
        next_id: ParticipantId,
        participants: Vec<(AccountId, ParticipantId, ParticipantInfo)>,
    }

    impl Serialize for Participants {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let vec: Vec<(AccountId, ParticipantId, ParticipantInfo)> = self
                .participants
                .iter()
                .map(|(account_id, (participant_id, info))| {
                    (account_id.clone(), *participant_id, info.clone())
                })
                .collect();
            ParticipantsJson {
                next_id: self.next_id,
                participants: vec,
            }
            .serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Participants {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let json = ParticipantsJson::deserialize(deserializer)?;
            let mut participants = BTreeMap::new();
            let mut used_ids = BTreeSet::new();
            for (account_id, participant_id, info) in json.participants {
                used_ids.insert(participant_id);
                participants.insert(account_id, (participant_id, info));
            }
            Ok(Participants {
                next_id: json.next_id,
                participants,
                used_ids,
            })
        }
    }

    #[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
    impl schemars::JsonSchema for Participants {
        fn schema_name() -> String {
            "Participants".to_string()
        }

        fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
            ParticipantsJson::json_schema(gen)
        }
    }
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
            used_ids: BTreeSet::new(),
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
        // O(log n) check for duplicate account
        if self.participants.contains_key(&account_id) {
            return Err(InvalidParameters::ParticipantAlreadyInSet.into());
        }
        // O(log n) check for duplicate participant ID
        if self.used_ids.contains(&id) {
            return Err(InvalidParameters::ParticipantAlreadyInSet.into());
        }
        if id < self.next_id() {
            return Err(InvalidParameters::ParticipantAlreadyUsed.into());
        }
        self.participants.insert(account_id, (id, info));
        self.used_ids.insert(id);
        self.next_id.0 = id.0 + 1;
        Ok(())
    }

    pub fn insert(&mut self, account_id: AccountId, info: ParticipantInfo) -> Result<(), Error> {
        self.insert_with_id(account_id, info, self.next_id)
    }

    /// Returns an iterator over participants as tuples for backward compatibility.
    /// The iteration order is by AccountId (lexicographic).
    pub fn participants(
        &self,
    ) -> impl Iterator<Item = (&AccountId, &ParticipantId, &ParticipantInfo)> {
        self.participants
            .iter()
            .map(|(account_id, (participant_id, info))| (account_id, participant_id, info))
    }

    /// Returns entries as owned tuples (for cases requiring Vec compatibility).
    pub fn participants_vec(&self) -> Vec<(AccountId, ParticipantId, ParticipantInfo)> {
        self.participants
            .iter()
            .map(|(account_id, (participant_id, info))| {
                (account_id.clone(), *participant_id, info.clone())
            })
            .collect()
    }

    pub fn next_id(&self) -> ParticipantId {
        self.next_id
    }

    /// Validates that the fields are coherent:
    ///  - All participant IDs are unique (enforced by used_ids set).
    ///  - All account IDs are unique (enforced by BTreeMap key).
    ///  - The next_id is greater than all participant IDs.
    pub fn validate(&self) -> Result<(), Error> {
        // Uniqueness of AccountId is guaranteed by BTreeMap
        // Uniqueness of ParticipantId is guaranteed by used_ids BTreeSet
        // Just need to verify next_id invariant
        for (pid, _) in self.participants.values() {
            if self.next_id.get() <= pid.get() {
                return Err(InvalidCandidateSet::IncoherentParticipantIds.into());
            }
        }
        // Verify used_ids is consistent with participants
        if self.used_ids.len() != self.participants.len() {
            return Err(InvalidCandidateSet::IncoherentParticipantIds.into());
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
        let mut map = BTreeMap::new();
        let mut used_ids = BTreeSet::new();
        for (account_id, participant_id, info) in participants {
            used_ids.insert(participant_id);
            map.insert(account_id, (participant_id, info));
        }
        Self {
            next_id,
            participants: map,
            used_ids,
        }
    }

    /// O(log n) lookup to get participant info by account ID.
    pub fn info(&self, account_id: &AccountId) -> Option<&ParticipantInfo> {
        self.participants.get(account_id).map(|(_, info)| info)
    }

    /// O(log n) update of participant info.
    pub fn update_info(
        &mut self,
        account_id: AccountId,
        new_info: ParticipantInfo,
    ) -> Result<(), Error> {
        if let Some((_, info)) = self.participants.get_mut(&account_id) {
            *info = new_info;
            Ok(())
        } else {
            Err(crate::errors::InvalidState::NotParticipant.into())
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Participants {
    /// O(n) lookup - test only. Returns ParticipantId by AccountId.
    pub fn id(&self, account_id: &AccountId) -> Result<ParticipantId, Error> {
        self.participants
            .get(account_id)
            .map(|(p_id, _)| *p_id)
            .ok_or_else(|| crate::errors::InvalidState::NotParticipant.into())
    }

    /// O(n) reverse lookup - test only. Returns AccountId by ParticipantId.
    pub fn account_id(&self, id: &ParticipantId) -> Result<AccountId, Error> {
        self.participants
            .iter()
            .find(|(_, (p_id, _))| p_id == id)
            .map(|(a_id, _)| a_id.clone())
            .ok_or_else(|| crate::errors::InvalidState::ParticipantIndexOutOfRange.into())
    }

    /// Returns a subset of the participants according to the given range of indices.
    /// Note: Since BTreeMap iteration is by AccountId order, this may differ from Vec order.
    pub fn subset(&self, range: std::ops::Range<usize>) -> Participants {
        let participants: Vec<_> = self
            .participants
            .iter()
            .skip(range.start)
            .take(range.end - range.start)
            .map(|(a, (p, i))| (a.clone(), *p, i.clone()))
            .collect();
        let mut used_ids = BTreeSet::new();
        let mut map = BTreeMap::new();
        for (account_id, participant_id, info) in participants {
            used_ids.insert(participant_id);
            map.insert(account_id, (participant_id, info));
        }
        Participants {
            next_id: self.next_id,
            participants: map,
            used_ids,
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
        if let Some((participant_id, _)) = self.participants.remove(account) {
            self.used_ids.remove(&participant_id);
        }
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
            assert!(participants.account_id(&ParticipantId(i as u32)).is_ok());
        }
        assert!(participants.validate().is_ok());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let n = 10;
        let expected = gen_accounts_and_info(n);
        let mut participants = Participants::new();
        for (account_id, info) in expected.iter() {
            participants
                .insert(account_id.clone(), info.clone())
                .unwrap();
        }

        // Test Borsh roundtrip
        let borsh_bytes = borsh::to_vec(&participants).unwrap();
        let deserialized: Participants = borsh::from_slice(&borsh_bytes).unwrap();
        assert_eq!(participants.len(), deserialized.len());
        for (account_id, info) in expected.iter() {
            assert!(deserialized.is_participant(account_id));
            assert_eq!(deserialized.info(account_id).unwrap(), info);
        }

        // Test JSON roundtrip
        let json_str = serde_json::to_string(&participants).unwrap();
        let deserialized: Participants = serde_json::from_str(&json_str).unwrap();
        assert_eq!(participants.len(), deserialized.len());
        for (account_id, info) in expected.iter() {
            assert!(deserialized.is_participant(account_id));
            assert_eq!(deserialized.info(account_id).unwrap(), info);
        }
    }
}
