use crate::{
    ReconstructionThreshold,
    errors::InitializationError,
    participants::{Participant, ParticipantList},
};

/// Verifies that the sign inputs are valid
pub fn assert_sign_inputs(
    participants: &[Participant],
    threshold: impl Into<ReconstructionThreshold>,
    me: Participant,
    coordinator: Participant,
) -> Result<ParticipantList, InitializationError> {
    let threshold = threshold.into();
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }
    let Some(participants) = ParticipantList::new(participants) else {
        return Err(InitializationError::DuplicateParticipants);
    };

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

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }
    Ok(participants)
}
