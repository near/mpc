use crate::{
    ReconstructionThreshold,
    errors::InitializationError,
    participants::{Participant, ParticipantList},
};

/// Validates the FROST participant set and threshold (≥2 participants, no duplicates, `me`
/// present, threshold ≤ count) and returns the validated [`ParticipantList`].
pub fn assert_participant_inputs(
    participants: &[Participant],
    threshold: impl Into<ReconstructionThreshold>,
    me: Participant,
) -> Result<ParticipantList, InitializationError> {
    let threshold = threshold.into();
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }
    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // validate threshold
    let threshold = threshold.try_as_usize()?;
    if threshold > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold,
            max: participants.len(),
        });
    }

    Ok(participants)
}

/// Verifies that the sign inputs are valid
pub fn assert_sign_inputs(
    participants: &[Participant],
    threshold: impl Into<ReconstructionThreshold>,
    me: Participant,
    coordinator: Participant,
) -> Result<ParticipantList, InitializationError> {
    let participants = assert_participant_inputs(participants, threshold, me)?;

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }
    Ok(participants)
}
