//! This module holds some utilities for working with participants.
//!
//! Often you need to do things like, storing one item for each participant,
//! or getting the field values corresponding to each participant, etc.
//! This module tries to provide useful data structures for doing that.

use std::{collections::HashMap, mem};

use serde::Serialize;

use crate::crypto::{ciphersuite::Ciphersuite, polynomials::compute_lagrange_coefficient};
use crate::protocol::{errors::ProtocolError, Participant};
use crate::Scalar;

/// Represents a sorted list of participants.
///
/// The advantage of this data structure is that it can be hashed in the protocol transcript,
/// since everybody will agree on its order.
#[derive(Clone, Debug, Serialize)]
pub struct ParticipantList {
    participants: Vec<Participant>,
    /// This maps each participant to their index in the vector above.
    #[serde(skip_serializing)]
    indices: HashMap<Participant, usize>,
}

impl ParticipantList {
    // For optimization reasons, another method needs this.
    fn new_vec(mut participants: Vec<Participant>) -> Option<Self> {
        participants.sort();

        let indices: HashMap<_, _> = participants
            .iter()
            .enumerate()
            .map(|(p, x)| (*x, p))
            .collect();

        if indices.len() < participants.len() {
            return None;
        }

        Some(Self {
            participants,
            indices,
        })
    }

    /// Create a participant list from a slice of participants.
    ///
    /// This will return None if the participants have duplicates.
    pub fn new(participants: &[Participant]) -> Option<Self> {
        Self::new_vec(participants.to_owned())
    }

    pub fn len(&self) -> usize {
        self.participants.len()
    }

    pub fn is_empty(&self) -> bool {
        self.participants.is_empty()
    }

    /// Check if this list has a given participant.
    pub fn contains(&self, participant: Participant) -> bool {
        self.indices.contains_key(&participant)
    }

    /// Iterate over the other participants
    pub fn others(&self, me: Participant) -> impl Iterator<Item = Participant> + '_ {
        self.participants.iter().filter(move |x| **x != me).copied()
    }

    /// Return the index of a given participant.
    ///
    /// Basically, the order they appear in a sorted list
    pub fn index(&self, participant: Participant) -> Result<usize, ProtocolError> {
        self.indices
            .get(&participant)
            .copied()
            .ok_or(ProtocolError::InvalidIndex)
    }

    // Return a participant of a given index from the order they
    // appear in the sorted list
    pub fn get_participant(&self, index: usize) -> Option<Participant> {
        if index >= self.participants.len() {
            return None;
        }
        Some(self.participants[index])
    }

    /// Get the lagrange coefficient for a participant, relative to this list.
    /// The lagrange coefficient is evaluated at zero
    /// Use generic frost library types
    pub fn lagrange<C: Ciphersuite>(&self, p: Participant) -> Result<Scalar<C>, ProtocolError> {
        let p = p.scalar::<C>();
        let identifiers: Vec<Scalar<C>> = self
            .participants()
            .iter()
            .map(super::protocol::Participant::scalar::<C>)
            .collect();
        Ok(compute_lagrange_coefficient::<C>(&identifiers, &p, None)?.0)
    }

    /// Return the intersection of this list with another list.
    #[allow(clippy::missing_panics_doc)]
    pub fn intersection(&self, others: &Self) -> Self {
        let mut out = Vec::new();
        for &p in &self.participants {
            if others.contains(p) {
                out.push(p);
            }
        }
        // We know that no duplicates will be created, so unwrapping is safe
        Self::new_vec(out).unwrap()
    }

    // Returns all the participants in the list
    pub fn participants(&self) -> &[Participant] {
        self.participants.as_slice()
    }

    #[cfg(test)]
    #[allow(clippy::missing_panics_doc)]
    pub fn shuffle(&self, mut rng: impl rand_core::CryptoRngCore) -> Option<Self> {
        let mut participants = self.participants().to_vec();
        let len = self.participants.len();
        for i in (1..len).rev() {
            let j = usize::try_from(rng.next_u32()).unwrap() % (i + 1);
            participants.swap(i, j);
        }
        Self::new(&participants)
    }
}

impl From<ParticipantList> for Vec<Participant> {
    fn from(val: ParticipantList) -> Self {
        val.participants
    }
}

/// A map from participants to elements.
///
/// The idea is that you have one element for each participant.
#[derive(Debug, Clone, Serialize)]
pub struct ParticipantMap<'a, T> {
    #[serde(skip_serializing)]
    participants: &'a ParticipantList,
    data: Vec<Option<T>>,
    #[serde(skip_serializing)]
    count: usize,
}

impl<'a, T> ParticipantMap<'a, T> {
    /// Create a new map from a list of participants.
    ///
    /// This map only lives as long as that list of participants.
    pub fn new(participants: &'a ParticipantList) -> Self {
        // We could also require a T: Clone bound instead of doing this initialization manually.
        let size = participants.participants.len();
        let mut data = Vec::with_capacity(size);
        for _ in 0..size {
            data.push(None);
        }

        Self {
            participants,
            data,
            count: 0,
        }
    }

    /// Check if this map is full, i.e. if every participant has put something in.
    pub fn full(&self) -> bool {
        self.count == self.data.len()
    }

    /// Place the data for a participant in this map.
    ///
    /// This will do nothing if the participant is unknown, or already has a value
    pub fn put(&mut self, participant: Participant, data: T) {
        let i = self.participants.indices.get(&participant);
        if i.is_none() {
            return;
        }
        let i = *i.unwrap();

        if self.data[i].is_some() {
            return;
        }

        self.data[i] = Some(data);
        self.count += 1;
    }

    // Consumes the Map returning only the vector of the unwrapped data
    // If one of the data is still none, then return None
    pub fn into_vec_or_none(self) -> Option<Vec<T>> {
        self.data.into_iter().collect::<Option<Vec<_>>>()
    }

    // Does not consume the map returning only the vector of the unwrapped data
    // If one of the data is still none, then return None
    pub fn to_refs_or_none(&self) -> Option<Vec<&T>> {
        self.data
            .iter()
            .map(|opt| opt.as_ref())
            .collect::<Option<Vec<_>>>()
    }

    // Returns the set of included participants
    pub fn participants(&self) -> &[Participant] {
        self.participants.participants()
    }

    pub fn index(&self, index: Participant) -> Result<&T, ProtocolError> {
        let index = self.participants.index(index)?;
        self.data
            .get(index)
            .ok_or(ProtocolError::InvalidIndex)?
            .as_ref()
            .ok_or_else(|| ProtocolError::Other("No data found".to_string()))
    }
}

/// A way to count participants.
///
/// This is used when you want to process a message from each participant only once.
/// This datastructure will let you put a participant in, and then tell you if this
/// participant was newly inserted or not, allowing you to thus process the
/// first message received from them.
#[derive(Debug, Clone)]
pub struct ParticipantCounter<'a> {
    participants: &'a ParticipantList,
    seen: Vec<bool>,
    counter: usize,
}

impl<'a> ParticipantCounter<'a> {
    /// Create a new participant counter from the list of all participants.
    pub fn new(participants: &'a ParticipantList) -> Self {
        Self {
            participants,
            seen: vec![false; participants.len()],
            counter: participants.len(),
        }
    }

    /// Put a new participant in this counter.
    ///
    /// This will return true if the participant was added, or false otherwise.
    ///
    /// The participant may not have been added because:
    /// - The participant is not part of our participant list.
    /// - The participant has already been added.
    ///
    /// This can be checked to not process a message twice.
    pub fn put(&mut self, participant: Participant) -> bool {
        let i = match self.participants.indices.get(&participant) {
            None => return false,
            Some(&i) => i,
        };

        // Need the old value to be false.
        let inserted = !mem::replace(&mut self.seen[i], true);
        if inserted {
            self.counter -= 1;
        }
        inserted
    }

    /// Clear the contents of this counter.
    pub fn clear(&mut self) {
        for x in &mut self.seen {
            *x = false;
        }
        self.counter = self.participants.len();
    }

    /// Check if this counter contains all participants
    pub fn full(&self) -> bool {
        self.counter == 0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::generate_participants;

    #[test]
    fn test_get_index_participant_error() {
        let participants = generate_participants(5);
        let participants = ParticipantList::new(&participants).unwrap();
        assert!(participants.index(Participant::from(1234_u32)).is_err());
    }

    #[test]
    fn test_get_index_data_error() {
        let participants = generate_participants(5);
        let participants = ParticipantList::new(&participants).unwrap();
        let map: ParticipantMap<'_, u32> = ParticipantMap::new(&participants);
        // no participant test
        assert!(map.index(Participant::from(1233_u32)).is_err());
        // no data test
        assert!(map.index(Participant::from(1_u32)).is_err());
    }
}
