use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct Rfc1982SerialU8(pub u8);

impl Rfc1982SerialU8 {
    pub const fn new(val: u8) -> Self {
        Self(val)
    }

    pub fn post_increment(&mut self) -> Self {
        let current = *self;
        self.0 = self.0.wrapping_add(1);
        current
    }

    pub fn less_than(&self, other: Self) -> bool {
        let diff = other.0.wrapping_sub(self.0);
        diff > 0 && diff < 128
    }

    pub fn greater_than(&self, other: Self) -> bool {
        other.less_than(*self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc1982_u8_wraparound() {
        // Given
        let old_seq = Rfc1982SerialU8::new(255);
        let new_seq = Rfc1982SerialU8::new(0);
        // When / Then
        assert!(new_seq.greater_than(old_seq));
        assert!(old_seq.less_than(new_seq));
        assert!(Rfc1982SerialU8::new(127).greater_than(Rfc1982SerialU8::new(0)));
        assert!(!Rfc1982SerialU8::new(128).greater_than(Rfc1982SerialU8::new(0)));
        assert!(!Rfc1982SerialU8::new(0).greater_than(Rfc1982SerialU8::new(128)));
        assert!(Rfc1982SerialU8::new(10).greater_than(Rfc1982SerialU8::new(5)));
        assert!(Rfc1982SerialU8::new(5).less_than(Rfc1982SerialU8::new(10)));
    }

    #[test]
    fn test_equality_and_bounds() {
        // Given
        let seq = Rfc1982SerialU8::new(100);
        // When / Then
        assert!(!seq.greater_than(seq));
        assert!(!seq.less_than(seq));
        let base = Rfc1982SerialU8::new(0);
        assert!(Rfc1982SerialU8::new(127).greater_than(base));
        assert!(!Rfc1982SerialU8::new(128).greater_than(base));
        assert!(Rfc1982SerialU8::new(129).less_than(base));
    }
}
