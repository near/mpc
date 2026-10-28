use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct Serial8(pub u8);

impl Serial8 {
    pub const fn new(val: u8) -> Self {
        Self(val)
    }

    pub fn next(&mut self) -> Self {
        let current = *self;
        self.0 = self.0.wrapping_add(1);
        current
    }

    pub fn rfc1982_less_than(&self, other: Self) -> bool {
        let diff = other.0.wrapping_sub(self.0);
        diff > 0 && diff < 128
    }

    pub fn rfc1982_greater_than(&self, other: Self) -> bool {
        other.rfc1982_less_than(*self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc1982_u8_wraparound() {
        // Given
        let old_seq = Serial8::new(255);
        let new_seq = Serial8::new(0);
        // When / Then
        assert!(new_seq.rfc1982_greater_than(old_seq));
        assert!(old_seq.rfc1982_less_than(new_seq));
        assert!(Serial8::new(127).rfc1982_greater_than(Serial8::new(0)));
        assert!(!Serial8::new(128).rfc1982_greater_than(Serial8::new(0)));
        assert!(!Serial8::new(0).rfc1982_greater_than(Serial8::new(128)));
        assert!(Serial8::new(10).rfc1982_greater_than(Serial8::new(5)));
        assert!(Serial8::new(5).rfc1982_less_than(Serial8::new(10)));
    }

    #[test]
    fn test_equality_and_bounds() {
        // Given
        let seq = Serial8::new(100);
        // When / Then
        assert!(!seq.rfc1982_greater_than(seq));
        assert!(!seq.rfc1982_less_than(seq));
        let base = Serial8::new(0);
        assert!(Serial8::new(127).rfc1982_greater_than(base));
        assert!(!Serial8::new(128).rfc1982_greater_than(base));
        assert!(Serial8::new(129).rfc1982_less_than(base));
    }
}
