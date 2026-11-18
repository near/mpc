//! Derives, from what [`connectivity`](super::connectivity) publishes, which participants are
//! alive and which connections are broken for a computation, and selects participants from that.

mod participant_selection;
mod publisher;

use std::collections::BTreeSet;

use itertools::Itertools;

use crate::network::connectivity::UndirectedEdge;

/// What the participants of an asset are checked against: all of them must be alive, and no two
/// of them may share a broken connection.
#[derive(Clone, PartialEq, Eq)]
pub struct NetworkReadiness<T> {
    alive_participants: BTreeSet<T>,
    broken_connections: BTreeSet<UndirectedEdge<T>>,
}

impl<T> NetworkReadiness<T> {
    pub fn new(
        alive_participants: BTreeSet<T>,
        broken_connections: BTreeSet<UndirectedEdge<T>>,
    ) -> Self {
        Self {
            alive_participants,
            broken_connections,
        }
    }
}

impl<T: Ord + Clone> NetworkReadiness<T> {
    pub fn supports(&self, participants: &[T]) -> bool {
        let is_alive = |participant: &T| self.alive_participants.contains(participant);
        let is_broken = |[a, b]: [&T; 2]| self.is_broken(a, b);
        participants.iter().all(is_alive)
            && !participants.iter().array_combinations::<2>().any(is_broken)
    }

    /// The alive participants that share no broken connection with `participant`, including
    /// `participant` itself if it is alive.
    pub fn connected_to(&self, participant: &T) -> BTreeSet<T> {
        self.alive_participants
            .iter()
            .filter(|other| !self.is_broken(participant, other))
            .cloned()
            .collect()
    }

    fn is_broken(&self, a: &T, b: &T) -> bool {
        UndirectedEdge::new(a.clone(), b.clone())
            .is_ok_and(|connection| self.broken_connections.contains(&connection))
    }
}

impl<T> Default for NetworkReadiness<T> {
    fn default() -> Self {
        Self {
            alive_participants: BTreeSet::new(),
            broken_connections: BTreeSet::new(),
        }
    }
}
