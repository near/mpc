use crate::primitives::ParticipantId;

/// Chooses a clique of participants: a set in which every two are connected to each other.
pub trait SelectParticipants {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Returns a clique of `participant_count` participants from `eligible` that contains
    /// `must_include` and whose connections are expected to hold for `duration`.
    ///
    /// Errors if `must_include` is not in `eligible`, if no such clique exists, or if the search
    /// for one is given up.
    fn select_participants(
        &self,
        participant_count: usize,
        eligible: &[ParticipantId],
        must_include: ParticipantId,
        duration: ComputationDuration,
    ) -> Result<Vec<ParticipantId>, Self::Error>;
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ComputationDuration {
    Any,
    Seconds,
    HalfMinute,
}
