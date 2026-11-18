use std::collections::{BTreeMap, BTreeSet};

use rand::{Rng, seq::SliceRandom};
use tokio::sync::watch;

use crate::{
    network::{
        connectivity::CheckComputationSupport,
        constants::{MAX_CLIQUE_SEARCH_ATTEMPTS, MAX_PICKS_PER_CLIQUE_SEARCH_ATTEMPT},
        readiness::{NetworkReadiness, publisher::NetworkReadinessPublisher},
    },
    primitives::ParticipantId,
    providers::participant_selection::{ComputationDuration, SelectParticipants},
};

struct RandomParticipantClique {
    any: watch::Receiver<NetworkReadiness<ParticipantId>>,
    seconds: watch::Receiver<NetworkReadiness<ParticipantId>>,
    half_minute: watch::Receiver<NetworkReadiness<ParticipantId>>,
}

impl RandomParticipantClique {
    fn new<S: CheckComputationSupport>(
        publisher: &mut NetworkReadinessPublisher<ParticipantId, S>,
    ) -> Self {
        Self {
            any: publisher.subscribe(ComputationDuration::Any),
            seconds: publisher.subscribe(ComputationDuration::Seconds),
            half_minute: publisher.subscribe(ComputationDuration::HalfMinute),
        }
    }
}

impl SelectParticipants for RandomParticipantClique {
    type Error = SelectParticipantsError;

    fn select_participants(
        &self,
        participant_count: usize,
        eligible: &[ParticipantId],
        must_include: ParticipantId,
        duration: ComputationDuration,
    ) -> Result<Vec<ParticipantId>, Self::Error> {
        if !eligible.contains(&must_include) {
            return Err(SelectParticipantsError::MustIncludeNotEligible(
                must_include,
            ));
        }
        let readiness = match duration {
            ComputationDuration::Any => &self.any,
            ComputationDuration::Seconds => &self.seconds,
            ComputationDuration::HalfMinute => &self.half_minute,
        };
        // Cloned so that the search does not hold the lock of the watch.
        let readiness = readiness.borrow().clone();
        readiness.select_clique(
            participant_count,
            eligible,
            &must_include,
            &mut rand::thread_rng(),
        )
    }
}

impl<T: Ord + Clone> NetworkReadiness<T> {
    /// A random clique of `size` alive participants from `eligible` that contains `must_include`.
    fn select_clique(
        &self,
        size: usize,
        eligible: &[T],
        must_include: &T,
        rng: &mut impl Rng,
    ) -> Result<Vec<T>, SelectParticipantsError> {
        let mut candidates: Vec<&T> = self
            .alive_participants
            .iter()
            .filter(|participant| *participant != must_include && eligible.contains(participant))
            .collect();
        let alive = if self.alive_participants.contains(must_include) {
            candidates.len().saturating_add(1)
        } else {
            0
        };
        if alive < size {
            return Err(SelectParticipantsError::NotEnoughParticipants {
                needed: size,
                available: alive,
            });
        }
        let others_needed = size.saturating_sub(1);
        if self.broken_connections.is_empty() {
            candidates.shuffle(rng);
            candidates.truncate(others_needed);
        } else {
            candidates.retain(|candidate| !self.is_broken(must_include, candidate));
            let mut usable_neighbors = self.usable_neighbors(&candidates);
            drop_poorly_connected(&mut usable_neighbors, others_needed.saturating_sub(1));
            let mut found = None;
            for _ in 0..MAX_CLIQUE_SEARCH_ATTEMPTS {
                candidates.shuffle(rng);
                let mut clique = Vec::new();
                let mut picks_left = MAX_PICKS_PER_CLIQUE_SEARCH_ATTEMPT;
                match extend_clique(
                    &mut clique,
                    &candidates,
                    others_needed,
                    &usable_neighbors,
                    &mut picks_left,
                ) {
                    Ok(true) => {
                        found = Some(clique);
                        break;
                    }
                    Ok(false) => {
                        return Err(SelectParticipantsError::NoClique {
                            needed: size,
                            alive,
                        });
                    }
                    // In another order, the candidates usually lead to a clique within the picks.
                    Err(OutOfPicksError) => {}
                }
            }
            candidates = found.ok_or(SelectParticipantsError::SearchBudgetExhausted {
                needed: size,
                alive,
            })?;
        }
        Ok(std::iter::once(must_include)
            .chain(candidates)
            .cloned()
            .collect())
    }

    /// The participants of `among` that are in a clique of `size` drawn from `among`. A
    /// participant whose search is given up counts as in none.
    // todo:
    // - building `usable_neighbors` and dropping the poorly connected from it can probably be
    //   combined into one cheaper step;
    // - the worst case is one search per participant, each of `MAX_CLIQUE_SEARCH_ATTEMPTS`
    //   attempts of `MAX_PICKS_PER_CLIQUE_SEARCH_ATTEMPT` picks, which can be large;
    // - the attempts are in random order, so when a search is given up, two nodes with the same
    //   view of the network can return different sets.
    pub fn participants_in_clique(
        &self,
        size: usize,
        among: &BTreeSet<T>,
        rng: &mut impl Rng,
    ) -> BTreeSet<T> {
        if among.len() < size {
            return BTreeSet::new();
        }
        if self.broken_connections.is_empty() {
            return among.clone();
        }
        let candidates: Vec<&T> = among.iter().collect();
        let neighbors_needed = size.saturating_sub(1);
        let mut usable_neighbors = self.usable_neighbors(&candidates);
        drop_poorly_connected(&mut usable_neighbors, neighbors_needed);
        let mut in_clique = BTreeSet::new();
        for (participant, neighbors) in &usable_neighbors {
            if in_clique.contains(participant) {
                continue;
            }
            let mut neighbors: Vec<&T> = neighbors.iter().copied().collect();
            for _ in 0..MAX_CLIQUE_SEARCH_ATTEMPTS {
                neighbors.shuffle(rng);
                let mut clique = Vec::new();
                let mut picks_left = MAX_PICKS_PER_CLIQUE_SEARCH_ATTEMPT;
                match extend_clique(
                    &mut clique,
                    &neighbors,
                    neighbors_needed,
                    &usable_neighbors,
                    &mut picks_left,
                ) {
                    Ok(true) => {
                        in_clique.insert(*participant);
                        in_clique.extend(clique);
                        break;
                    }
                    Ok(false) => break,
                    Err(OutOfPicksError) => {}
                }
            }
        }
        in_clique.into_iter().cloned().collect()
    }

    /// For each of `candidates`, the other candidates it shares no broken connection with.
    fn usable_neighbors<'a>(&self, candidates: &[&'a T]) -> BTreeMap<&'a T, BTreeSet<&'a T>> {
        candidates
            .iter()
            .map(|candidate| {
                let neighbors = candidates
                    .iter()
                    .copied()
                    .filter(|other| other != candidate && !self.is_broken(candidate, other))
                    .collect();
                (*candidate, neighbors)
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SelectParticipantsError {
    #[error("not enough alive participants: need {needed}, got {available}")]
    NotEnoughParticipants { needed: usize, available: usize },
    #[error("no {needed} of the {alive} alive participants are all connected to each other")]
    NoClique { needed: usize, alive: usize },
    #[error(
        "gave up looking for {needed} of the {alive} alive participants that are all connected to each other"
    )]
    SearchBudgetExhausted { needed: usize, alive: usize },
    #[error("participant {0} must be included, but is not eligible")]
    MustIncludeNotEligible(ParticipantId),
}

/// A member of the clique needs `neighbors_needed` neighbors. Dropping a candidate can leave
/// others with too few, so this repeats until nobody is dropped.
fn drop_poorly_connected<'a, T: Ord>(
    usable_neighbors: &mut BTreeMap<&'a T, BTreeSet<&'a T>>,
    neighbors_needed: usize,
) {
    loop {
        let poorly_connected: Vec<&T> = usable_neighbors
            .iter()
            .filter(|(_, neighbors)| neighbors.len() < neighbors_needed)
            .map(|(candidate, _)| *candidate)
            .collect();
        if poorly_connected.is_empty() {
            return;
        }
        for neighbors in usable_neighbors.values_mut() {
            neighbors.retain(|neighbor| !poorly_connected.contains(neighbor));
        }
        usable_neighbors.retain(|candidate, _| !poorly_connected.contains(candidate));
    }
}

/// Extends `clique` by `needed` of the `candidates`, trying them in order and backing out of a
/// pick that cannot be completed. Every candidate must be a neighbor of all of `clique`.
///
/// `Ok(false)` if no such extension exists. Every pick tried costs one of `picks_left`.
fn extend_clique<'a, T: Ord>(
    clique: &mut Vec<&'a T>,
    mut candidates: &[&'a T],
    needed: usize,
    usable_neighbors: &BTreeMap<&'a T, BTreeSet<&'a T>>,
    picks_left: &mut usize,
) -> Result<bool, OutOfPicksError> {
    let Some(needed_after_pick) = needed.checked_sub(1) else {
        return Ok(true);
    };
    while let Some((&pick, rest)) = candidates.split_first() {
        candidates = rest;
        let Some(neighbors) = usable_neighbors.get(pick) else {
            continue;
        };
        *picks_left = picks_left.checked_sub(1).ok_or(OutOfPicksError)?;
        let connected: Vec<&T> = rest
            .iter()
            .copied()
            .filter(|candidate| neighbors.contains(candidate))
            .collect();
        if connected.len() >= needed_after_pick {
            clique.push(pick);
            if extend_clique(
                clique,
                &connected,
                needed_after_pick,
                usable_neighbors,
                picks_left,
            )? {
                return Ok(true);
            }
            clique.pop();
        }
    }
    Ok(false)
}

struct OutOfPicksError;
