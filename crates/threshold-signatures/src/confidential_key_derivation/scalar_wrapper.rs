use core::ptr;
use digest::consts::U48;
use digest::generic_array::GenericArray;
use elliptic_curve::hash2curve::FromOkm;
use elliptic_curve::Field;
use std::sync::atomic;
use zeroize::Zeroize;

#[derive(Default, Clone, Debug)]
pub struct ScalarWrapper(pub(crate) blstrs::Scalar);

impl Zeroize for ScalarWrapper {
    /// Implementation based on the zeroize crate, which guarantees the value
    /// becomes 0 when the function is called by ensuring the compiler does not
    /// optimize the function away
    /// See <https://docs.rs/zeroize/latest/zeroize/#what-guarantees-does-this-crate-provide>
    /// for more details
    /// TODO(#238): push this feature upstream
    fn zeroize(&mut self) {
        unsafe {
            ptr::write_volatile(&mut self.0, blstrs::Scalar::default());
        }
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl ScalarWrapper {
    // Based on https://github.com/arkworks-rs/algebra/blob/c6f9284c17df00c50d954a5fe1c72dd4a5698103/ff/src/fields/prime.rs#L72
    // Converts `bytes` into a `Scalar` by interpreting the input as
    // an integer in big-endian and then converting the result to Scalar
    // which implicitly does modular reduction
    fn from_be_bytes_mod_order(bytes: &[u8]) -> Self {
        let mut res = blstrs::Scalar::ZERO;

        let mut count = 0;
        let mut remainder = 0;
        for byte in bytes {
            remainder = (remainder << 8) + u64::from(*byte);
            count += 1;
            if count == 8 {
                res = res.shl(64) + blstrs::Scalar::from(remainder);
                remainder = 0;
                count = 0;
            }
        }
        if count > 0 {
            res = res * res.shl(count * 8) + blstrs::Scalar::from(remainder);
        }
        Self(res)
    }
}

// Follows https://github.com/zkcrypto/bls12_381/blob/6bb96951d5c2035caf4989b6e4a018435379590f/src/hash_to_curve/map_scalar.rs
impl FromOkm for ScalarWrapper {
    // ceil(log2(p)) = 255, m = 1, k = 128.
    type Length = U48;

    fn from_okm(okm: &GenericArray<u8, Self::Length>) -> Self {
        Self::from_be_bytes_mod_order(okm)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        confidential_key_derivation::scalar_wrapper::ScalarWrapper, test_utils::MockCryptoRng,
    };
    use rand::Rng as _;
    use rand_core::{RngCore, SeedableRng};

    #[test]
    // This test only makes sense if `overflow-checks` are enabled
    // This is guaranteed by the `test_verify_overflow_failure` below
    fn test_stress_test_scalar_from_le_bytes_mod_order() {
        // empty case
        ScalarWrapper::from_be_bytes_mod_order(&[]);
        let mut rng = MockCryptoRng::seed_from_u64(42);
        for _ in 0..1000 {
            let len = rng.gen_range(1..10000);
            let mut bytes = vec![0; len];
            rng.fill_bytes(&mut bytes);
            ScalarWrapper::from_be_bytes_mod_order(&bytes);
        }
    }

    #[test]
    #[should_panic(expected = "attempt to add with overflow")]
    // This test guarantees that `overflow-checks` are enabled
    fn test_verify_overflow_failure() {
        let mut a = u64::MAX - 123;
        let mut rng = MockCryptoRng::seed_from_u64(42);
        // Required to avoid clippy detecting the overflow
        let b = rng.gen_range(124..10000);
        a += b;
        assert!(a > 0);
    }
}
