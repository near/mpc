use std::collections::BTreeSet;

use crate::network::connectivity::UndirectedEdge;
use crate::primitives::ParticipantId;

/// Picks the participant set for a computation we lead.
pub trait SelectParticipants {
    /// `participant_count` participants taken from `eligible`, one of them `must_include`,
    /// pairwise ready for a computation of `duration`.
    fn select_participants(
        &self,
        participant_count: usize,
        eligible: &[ParticipantId],
        must_include: ParticipantId,
        duration: ComputationDuration,
    ) -> Result<Vec<ParticipantId>, SelectParticipantsError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SelectParticipantsError {
    #[error("not enough alive participants: need {needed}, got {available}")]
    NotEnoughParticipants { needed: usize, available: usize },
}

pub trait CheckReadiness {
    type Node: Ord + Clone;

    /// Whether `nodes` can currently run a computation of `duration` together.
    /// Errors only if a node in `nodes` is not part of the network.
    fn check_readiness(
        &self,
        nodes: &BTreeSet<Self::Node>,
        duration: ComputationDuration,
    ) -> Result<(), NotReadyError<Self::Node>>;
}

#[derive(Clone, Copy)]
pub enum ComputationDuration {
    Any,
    Seconds,
    HalfMinute,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotReadyError<N> {
    #[error("node {0:?} is not in the network")]
    UnknownNode(N),
    #[error("connection {0} is not established")]
    NotConnected(UndirectedEdge<N>),
    #[error("connection {0} is too degraded for this computation")]
    Degraded(UndirectedEdge<N>),
}
