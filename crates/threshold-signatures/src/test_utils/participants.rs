use crate::participants::Participant;
use rand_core::CryptoRngCore;

// +++++++++++++++++ Participants Utilities +++++++++++++++++ //
/// Generates a vector of `number` participants, sorted by the participant id.
/// The participants ids range from 0 to `number`-1
pub fn generate_participants(number: usize) -> Vec<Participant> {
    (0..u32::try_from(number).unwrap())
        .map(Participant::from)
        .collect::<Vec<_>>()
}

/// Generates a vector of `number` participants, sorted by the participant id.
/// The participants ids are drawn from rng.
pub fn generate_participants_with_random_ids(
    number: usize,
    rng: &mut impl CryptoRngCore,
) -> Vec<Participant> {
    let mut participants = (0..number)
        .map(|_| Participant::from(rng.next_u32()))
        .collect::<Vec<_>>();
    participants.sort();
    participants
}
