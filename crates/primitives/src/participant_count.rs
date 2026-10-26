/// Number of participants: the size of a participant set, or how many participants cast a
/// given vote. Compared against thresholds through [`GovernanceThreshold::is_met_by`] and
/// [`ReconstructionThreshold::is_met_by`].
///
/// [`GovernanceThreshold::is_met_by`]: crate::GovernanceThreshold::is_met_by
/// [`ReconstructionThreshold::is_met_by`]: crate::ReconstructionThreshold::is_met_by
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    derive_more::Display,
    derive_more::From,
    derive_more::Into,
)]
pub struct ParticipantCount(pub u64);

const _: () = assert!(usize::BITS <= u64::BITS);

impl ParticipantCount {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }

    /// The single place a collection length becomes a count. Infallible: the assertion above
    /// rejects any target whose `usize` is wider than `u64`.
    pub fn from_len(len: usize) -> Self {
        Self(u64::try_from(len).expect("usize fits in u64"))
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::ParticipantCount;

    #[test]
    fn from_len__should_preserve_the_length() {
        // Given
        let len = 7;

        // When
        let count = ParticipantCount::from_len(len);

        // Then
        assert_eq!(count, ParticipantCount::new(7));
        assert_eq!(count.value(), 7);
    }
}
