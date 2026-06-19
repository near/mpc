use elliptic_curve::PrimeField;
use elliptic_curve::sec1::ToEncodedPoint;
use frost_secp256k1::{Field, Secp256K1ScalarField};
use hkdf::Hkdf;
use k256::AffinePoint;

use super::{Scalar, Tweak};
use crate::errors::ProtocolError;
use crate::participants::ParticipantList;

/// The arguments used to derive randomness used for presignature rerandomization.
/// Presignature rerandomization has been thoroughly described in
/// \[GS21\] <https://eprint.iacr.org/2021/1330.pdf>
///
/// *** Warning ***
/// Following \[GS21\] <https://eprint.iacr.org/2021/1330.pdf>, the entropy should
/// be public, freshly generated, and unpredictable.
// Cannot derive Debug here because an external type inside Tweak does not implement it
#[derive(Clone)]
pub struct RerandomizationArguments {
    // Preferable (but non-binding) the master public key
    pub pk: AffinePoint,
    pub tweak: Tweak,
    pub msg_hash: [u8; 32],
    pub big_r: AffinePoint,
    pub participants: ParticipantList,
    /// Fresh, Unpredictable, and Public source of entropy
    pub entropy: [u8; 32],
}

impl RerandomizationArguments {
    /// The following salt is picked by hashing with sha256
    /// "NEAR 6.4478$ 7:20pm CEST 2024-11-24"
    /// Based on [Krawczyk10] paper:
    /// ``[...] in most applications the extractor key (or salt) can be used
    /// repeatedly with many (independent) samples from the same source [...]``
    const SALT: [u8; 32] = [
        0x32, 0x8a, 0x47, 0xc2, 0xb8, 0x79, 0x44, 0x45, 0x25, 0x5c, 0x16, 0x47, 0x60, 0x8d, 0xf5,
        0xdb, 0x85, 0xc6, 0x8b, 0xb0, 0xe7, 0x17, 0x0a, 0xbe, 0xc5, 0x34, 0xdf, 0x27, 0x64, 0xa4,
        0x58, 0x31,
    ];

    pub fn new(
        pk: AffinePoint,
        tweak: Tweak,
        msg_hash: [u8; 32],
        big_r: AffinePoint,
        participants: ParticipantList,
        entropy: [u8; 32],
    ) -> Self {
        Self {
            pk,
            tweak,
            msg_hash,
            big_r,
            participants,
            entropy,
        }
    }

    /// Derives a random string from the public key, tweak, message hash, presignature R,
    /// set of participants and the entropy.
    ///
    /// Outputs a random string computed as HKDF(entropy, pk, hash, R, participants)
    pub fn derive_randomness(&self) -> Result<Scalar, ProtocolError> {
        // create a string containing (pk, msg_hash, big_r, sorted(participants))
        let pk_encoded_point = self.pk.to_encoded_point(true);
        let encoded_pk: &[u8] = pk_encoded_point.as_bytes();
        let encoded_tweak: &[u8] = &<Secp256K1ScalarField as Field>::serialize(&self.tweak.value());
        let encoded_msg_hash: &[u8] = &self.msg_hash;
        let big_r_encoded_point = self.big_r.to_encoded_point(true);
        let encoded_big_r: &[u8] = big_r_encoded_point.as_bytes();

        // concatenate all the bytes
        let mut concatenation = Vec::new();
        // First byte is a counter (for the unlikely case the derived scalar is 0); the second byte is a fixed tag.
        concatenation.extend_from_slice(&[0u8, 1]);
        concatenation.extend_from_slice(encoded_pk);
        concatenation.extend_from_slice(encoded_tweak);
        concatenation.extend_from_slice(encoded_msg_hash);
        concatenation.extend_from_slice(encoded_big_r);
        // Append each ParticipantId's
        for participant in self.participants.participants() {
            concatenation.extend_from_slice(&participant.bytes());
        }

        // initiate hkdf with the salt and with some `good' entropy
        let hk = Hkdf::<sha3::Sha3_256>::new(Some(&Self::SALT), &self.entropy);

        let mut delta = Scalar::ZERO;
        // If the randomness created is 0 then we want to generate a new randomness
        while bool::from(delta.is_zero()) {
            // Generate randomization out of HKDF(counter, entropy, pk, msg_hash, big_r, participants, )
            // where entropy is a public but unpredictable random string.
            // The counter depends on the number of times we enter into this loop
            let mut okm = [0u8; 32];

            hk.expand(&concatenation, &mut okm)
                .map_err(|_| ProtocolError::HashingError)?;

            // derive the randomness delta
            delta = Scalar::from_repr(okm.into()).unwrap_or(
                // if delta falls outside the field
                // probability is negligible: in the order of 1/2^224
                Scalar::ZERO,
            );
            // Increment the counter, the probability that this overflows is astronomically low
            let concatenation_0 = concatenation
                .first_mut()
                .ok_or(ProtocolError::InvalidIndex)?;
            *concatenation_0 += 1;
        }
        Ok(delta)
    }
}

#[cfg(test)]
mod test {
    use super::RerandomizationArguments;
    use crate::ecdsa::{Scalar, Secp256K1Sha256, Tweak};
    use crate::participants::ParticipantList;
    use crate::test_utils::{
        MockCryptoRng, ecdsa_generate_rerandpresig_args, generate_participants_with_random_ids,
    };

    use frost_core::Ciphersuite;
    use rand::SeedableRng;
    use rand_core::{CryptoRngCore, RngCore};

    type C = Secp256K1Sha256;

    // Outputs pk, R, hash, participants, entropy, randomness
    fn compute_random_outputs(
        rng: &mut impl CryptoRngCore,
        num_participants: usize,
    ) -> (RerandomizationArguments, Scalar) {
        let (_, big_r) = <C>::generate_nonce(rng);
        let (_, pk) = <C>::generate_nonce(rng);
        let pk = frost_core::VerifyingKey::new(pk);
        let big_r = big_r.to_affine();

        // Generate unique ten ParticipantId values
        let participants = generate_participants_with_random_ids(num_participants, rng);
        // Generate Rerandomization arguments
        let (args, _) = ecdsa_generate_rerandpresig_args(rng, &participants, pk, big_r);

        let delta = args.derive_randomness().unwrap();
        (args, delta)
    }

    #[test]
    fn test_different_pk() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let num_participants = 10;
        let (mut args, delta) = compute_random_outputs(&mut rng, num_participants);
        // different pk
        let (_, pk) = <C>::generate_nonce(&mut rng);
        args.pk = pk.to_affine();
        let delta_prime = args.derive_randomness().unwrap();
        assert_ne!(delta, delta_prime);
    }

    #[test]
    fn test_different_tweak() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let num_participants = 10;

        let (mut args, delta) = compute_random_outputs(&mut rng, num_participants);
        // different pk
        args.tweak = Tweak::new(frost_core::random_nonzero::<Secp256K1Sha256, _>(&mut rng));
        let delta_prime = args.derive_randomness().unwrap();
        assert_ne!(delta, delta_prime);
    }

    #[test]
    fn test_different_msg_hash() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let num_participants = 10;
        let (mut args, delta) = compute_random_outputs(&mut rng, num_participants);
        // different msg_hash
        args.msg_hash = [0; 32];
        let delta_prime = args.derive_randomness().unwrap();
        assert_ne!(delta, delta_prime);
    }

    #[test]
    fn test_different_big_r() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let num_participants = 10;
        let (mut args, delta) = compute_random_outputs(&mut rng, num_participants);
        // different big_r
        let (_, big_r) = <C>::generate_nonce(&mut rng);
        args.big_r = big_r.to_affine();
        let delta_prime = args.derive_randomness().unwrap();
        assert_ne!(delta, delta_prime);
    }

    #[test]
    fn test_different_participants() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let num_participants = 10;
        let (mut args, delta) = compute_random_outputs(&mut rng, num_participants);
        // different participants set
        let participants = generate_participants_with_random_ids(num_participants, &mut rng);
        args.participants = ParticipantList::new(&participants).unwrap();
        let delta_prime = args.derive_randomness().unwrap();
        assert_ne!(delta, delta_prime);
    }

    #[test]
    fn test_different_entropy() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let num_participants = 10;
        let (mut args, delta) = compute_random_outputs(&mut rng, num_participants);

        // different entropy
        rng.fill_bytes(&mut args.entropy);
        let delta_prime = args.derive_randomness().unwrap();
        assert_ne!(delta, delta_prime);
    }

    // Test that with different order of participants, the randomness is the same.
    #[test]
    fn test_same_randomness() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let num_participants = 10;
        let (mut args, delta) = compute_random_outputs(&mut rng, num_participants);

        // reshuffle
        args.participants = args.participants.shuffle(rng).unwrap();
        let delta_prime = args.derive_randomness().unwrap();
        assert_eq!(delta, delta_prime);
    }
}
