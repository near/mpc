use rand::{CryptoRng, RngCore};
use rand_chacha::{rand_core::SeedableRng, ChaCha12Rng};
use rand_core::CryptoRngCore;

/// Used for deterministic Rngs and only in testing
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockCryptoRng(ChaCha12Rng);

impl SeedableRng for MockCryptoRng {
    type Seed = [u8; 32];
    fn seed_from_u64(seed: u64) -> Self {
        Self(ChaCha12Rng::seed_from_u64(seed))
    }

    fn from_seed(seed: Self::Seed) -> Self {
        Self(ChaCha12Rng::from_seed(seed))
    }
}

impl RngCore for MockCryptoRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl CryptoRng for MockCryptoRng {}

/// Creates multiple Mock rngs for multiple participants using a seed
pub fn create_rngs(size: usize, seed: &mut impl CryptoRngCore) -> Vec<MockCryptoRng> {
    (0..size)
        .map(|_| MockCryptoRng::seed_from_u64(seed.next_u64()))
        .collect()
}

#[cfg(test)]
pub mod test {
    use super::create_rngs;
    use crate::test_utils::MockCryptoRng;
    use rand::{RngCore, SeedableRng};

    #[test]
    fn test_clone_rngs() {
        let num = 5;
        let mut rng = MockCryptoRng::seed_from_u64(42u64);
        let mut rngs = create_rngs(num, &mut rng);
        // Clone rng
        let mut clone_rngs = rngs.clone();

        let consumption = rngs.iter_mut().map(RngCore::next_u64).collect::<Vec<_>>();
        let clone_consumption = clone_rngs
            .iter_mut()
            .map(RngCore::next_u64)
            .collect::<Vec<_>>();

        for (c1, c2) in consumption.iter().zip(clone_consumption.iter()) {
            assert_eq!(c1, c2);
        }
    }
}
