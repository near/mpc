use crate::primitives::ParticipantId;

/// Chooses a clique of participants: a set in which every two are connected to each other.
pub trait SelectParticipants {
    /// Returns a clique of `participant_count` participants from `eligible` that contains
    /// `must_include` and whose connections are expected to hold for `duration`.
    ///
    /// Errors if `must_include` is not in `eligible`, or if no such clique exists.
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
    #[error("participant {0} must be included, but is not eligible")]
    MustIncludeNotEligible(ParticipantId),
}

#[derive(Clone, Copy)]
pub enum ComputationDuration {
    Any,
    Seconds,
    HalfMinute,
}
