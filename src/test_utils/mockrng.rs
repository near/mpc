use rand::{CryptoRng, RngCore};
use rand_chacha::{rand_core::SeedableRng, ChaCha12Rng};

/// Used for deterministic Rngs and only in testing
pub struct MockCryptoRng(ChaCha12Rng);

impl MockCryptoRng {
    pub fn seed_from_u64(seed: u64) -> Self {
        Self(ChaCha12Rng::seed_from_u64(seed))
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
