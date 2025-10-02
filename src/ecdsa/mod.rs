//! This module serves as a wrapper for ECDSA scheme.
pub mod ot_based_ecdsa;
pub mod robust_ecdsa;

use hkdf::Hkdf;

use elliptic_curve::{
    bigint::U256,
    ops::{Invert, Reduce},
    point::AffineCoordinates,
    sec1::ToEncodedPoint,
    PrimeField,
};

use frost_secp256k1::{Field, Group, Secp256K1Group, Secp256K1ScalarField, Secp256K1Sha256};
use k256::{AffinePoint, ProjectivePoint};

use crate::crypto::ciphersuite::{BytesOrder, Ciphersuite, ScalarSerializationFormat};
use crate::participants::ParticipantList;
use crate::protocol::errors::ProtocolError;

pub type KeygenOutput = crate::KeygenOutput<Secp256K1Sha256>;
pub type Tweak = crate::Tweak<Secp256K1Sha256>;
pub type Scalar = <Secp256K1ScalarField as Field>::Scalar;
pub type Element = <Secp256K1Group as Group>::Element;
pub type CoefficientCommitment = frost_core::keys::CoefficientCommitment<Secp256K1Sha256>;
pub type Polynomial = crate::crypto::polynomials::Polynomial<Secp256K1Sha256>;
pub type PolynomialCommitment = crate::crypto::polynomials::PolynomialCommitment<Secp256K1Sha256>;

impl ScalarSerializationFormat for Secp256K1Sha256 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::BigEndian
    }
}

impl Ciphersuite for Secp256K1Sha256 {}

/// Get the x coordinate of a point, as a scalar
pub(crate) fn x_coordinate(point: &AffinePoint) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&point.x())
}

/// Represents a signature that supports different variants of ECDSA.
///
/// An ECDSA signature is usually two scalars.
/// The first is derived from using the x-coordinate of an elliptic curve point (`big_r`),
/// and the second is computed using the typical ecdsa signing equation.
/// Deriving the x-coordination implies losing information about `big_r`, some variants
/// may thus include an extra information to recover this point.
///
/// This signature supports all variants by containing `big_r` entirely
#[derive(Clone)]
pub struct Signature {
    /// This is the entire first point.
    pub big_r: AffinePoint,
    /// This is the second scalar, normalized to be in the lower range.
    pub s: Scalar,
}

impl Signature {
    // This verification tests the signature including whether s has been normalized
    pub fn verify(&self, public_key: &AffinePoint, msg_hash: &Scalar) -> bool {
        let r: Scalar = x_coordinate(&self.big_r);
        if r.is_zero().into() || self.s.is_zero().into() {
            return false;
        }
        // tested earlier is not zero, so inversion will not raise an error and unwrap cannot panic
        let s_inv = self.s.invert_vartime().unwrap();
        let reproduced = (ProjectivePoint::GENERATOR * (*msg_hash * s_inv))
            + (ProjectivePoint::from(*public_key) * (r * s_inv));
        x_coordinate(&reproduced.into()) == r
    }
}

/// None for participants and Some for coordinator
pub type SignatureOption = Option<Signature>;

/// The arguments used to derive randomness used for presignature rerandomization.
/// Presignature rerandomization has been thoroughly described in
/// [GS21] <https://eprint.iacr.org/2021/1330.pdf>
///
/// *** Warning ***
/// Following [GS21] <https://eprint.iacr.org/2021/1330.pdf>, the entropy should
/// be public, freshly generated, and unpredictable.
pub struct RerandomizationArguments {
    pub pk: AffinePoint,
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
        msg_hash: [u8; 32],
        big_r: AffinePoint,
        participants: ParticipantList,
        entropy: [u8; 32],
    ) -> Self {
        Self {
            pk,
            msg_hash,
            big_r,
            participants,
            entropy,
        }
    }

    /// Derives a random string from the public key, message hash, presignature R,
    /// set of participants and the entropy.
    ///
    /// Outputs a random string computed as HKDF(entropy, pk, hash, R, participants)
    pub fn derive_randomness(&self) -> Result<Scalar, ProtocolError> {
        // create a string containing (pk, msg_hash, big_r, sorted(participants))
        let pk_encoded_point = self.pk.to_encoded_point(true);
        let encoded_pk: &[u8] = pk_encoded_point.as_bytes();
        let encoded_msg_hash: &[u8] = &self.msg_hash;
        let big_r_encoded_point = self.big_r.to_encoded_point(true);
        let encoded_big_r: &[u8] = big_r_encoded_point.as_bytes();

        // concatenate all the bytes
        let mut concatenation = Vec::new();
        concatenation.extend_from_slice(encoded_pk);
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
            // Generate randomization out of HKDF(entropy, pk, msg_hash, big_r, participants, nonce)
            // where entropy is a public but unpredictable random string.
            // The nonce is a succession of appended ones of growing length depending on the number of times
            // we enter into this loop
            let mut okm = [0u8; 32];

            hk.expand(&concatenation, &mut okm)
                .map_err(|_| ProtocolError::HashingError)?;

            // derive the randomness delta
            delta = Scalar::from_repr(okm.into()).unwrap_or(
                // if delta falls outside the field
                // probability is negligible: in the order of 1/2^224
                Scalar::ZERO,
            );
            // append an extra 0 at the end of the concatenation every time delta is zero
            concatenation.extend_from_slice(&[0u8, 1]);
        }
        Ok(delta)
    }
}

#[cfg(test)]
mod test {
    use crate::test::generate_participants;
    use crate::test::MockCryptoRng;

    use super::*;
    use crate::test::generate_participants_with_random_ids;
    use elliptic_curve::ops::{Invert, LinearCombination, Reduce};

    use frost_core::{
        keys::SigningShare, Ciphersuite, SigningKey as FrostSigningKey,
        VerifyingKey as FrostVerifyingKey,
    };

    use k256::{
        ecdsa::{signature::Verifier, SigningKey, VerifyingKey},
        ProjectivePoint, Scalar, Secp256k1,
    };
    use rand_core::{CryptoRngCore, OsRng, RngCore};
    use sha2::{digest::FixedOutput, Digest, Sha256};
    type C = Secp256K1Sha256;

    fn random_32_bytes(rng: &mut impl CryptoRngCore) -> [u8; 32] {
        let mut bytes: [u8; 32] = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    #[test]
    fn test_verify() {
        let msg = b"Hello from Near";
        let mut hasher = Sha256::new();
        hasher.update(msg);

        let sk = SigningKey::random(&mut OsRng);
        let pk = VerifyingKey::from(&sk);
        let (sig, _) = sk.sign_digest_recoverable(hasher.clone()).unwrap();
        assert!(pk.verify(msg, &sig).is_ok());

        let z_bytes = hasher.clone().finalize_fixed();
        let z =
            <Scalar as Reduce<<Secp256k1 as elliptic_curve::Curve>::Uint>>::reduce_bytes(&z_bytes);
        let (r, s) = sig.split_scalars();
        let s_inv = *s.invert_vartime();
        let u1 = z * s_inv;
        let u2 = *r * s_inv;
        let pk = ProjectivePoint::from(pk.as_affine());
        let big_r =
            ProjectivePoint::lincomb(&ProjectivePoint::GENERATOR, &u1, &pk, &u2).to_affine();

        let full_sig = Signature {
            big_r,
            s: *s.as_ref(),
        };

        let is_verified = full_sig.verify(&pk.to_affine(), &z);
        // Should always be ok as signature contains Uint i.e. normalized elements
        assert!(is_verified);
    }

    #[test]
    #[allow(non_snake_case)]
    fn keygen_output__should_be_serializable() {
        // Given
        let mut rng = MockCryptoRng::new([1; 8]);
        let signing_key = FrostSigningKey::<C>::new(&mut rng);

        let keygen_output = KeygenOutput {
            private_share: SigningShare::<C>::new(Scalar::ONE),
            public_key: FrostVerifyingKey::<C>::from(signing_key),
        };

        // When
        let serialized_keygen_output =
            serde_json::to_string(&keygen_output).expect("should be able to serialize output");

        // Then
        assert_eq!(
            serialized_keygen_output,
            "{\"private_share\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"public_key\":\"031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f\"}"
        );
    }

    // Outputs pk, R, hash, participants, entropy, randomness
    fn compute_random_outputs(
        rng: &mut impl CryptoRngCore,
        num_participants: usize,
    ) -> (RerandomizationArguments, Scalar) {
        let sk = SigningKey::random(&mut OsRng);
        let pk = *VerifyingKey::from(sk).as_affine();
        let (_, big_r) = <C>::generate_nonce(&mut OsRng);
        let big_r = big_r.to_affine();

        let msg_hash = random_32_bytes(rng);
        let entropy = random_32_bytes(rng);
        // Generate unique ten ParticipantId values
        let participants = generate_participants_with_random_ids(num_participants, rng);
        let participants = ParticipantList::new(&participants).unwrap();

        let args = RerandomizationArguments::new(pk, msg_hash, big_r, participants, entropy);
        let delta = args.derive_randomness().unwrap();
        (args, delta)
    }

    #[test]
    fn test_different_pk() {
        let num_participants = 10;
        let mut rng = OsRng;
        let (mut args, delta) = compute_random_outputs(&mut rng, num_participants);
        // different pk
        let (_, pk) = <C>::generate_nonce(&mut rng);
        args.pk = pk.to_affine();
        let delta_prime = args.derive_randomness().unwrap();
        assert_ne!(delta, delta_prime);
    }

    #[test]
    fn test_different_msg_hash() {
        let num_participants = 10;
        let mut rng = OsRng;
        let (mut args, delta) = compute_random_outputs(&mut rng, num_participants);
        // different msg_hash
        args.msg_hash = random_32_bytes(&mut rng);
        let delta_prime = args.derive_randomness().unwrap();
        assert_ne!(delta, delta_prime);
    }

    #[test]
    fn test_different_big_r() {
        let num_participants = 10;
        let mut rng = OsRng;
        let (mut args, delta) = compute_random_outputs(&mut rng, num_participants);
        // different big_r
        let (_, big_r) = <C>::generate_nonce(&mut OsRng);
        args.big_r = big_r.to_affine();
        let delta_prime = args.derive_randomness().unwrap();
        assert_ne!(delta, delta_prime);
    }

    #[test]
    fn test_different_participants() {
        let num_participants = 10;
        let mut rng = OsRng;
        let (mut args, delta) = compute_random_outputs(&mut rng, num_participants);
        // different participants set
        let participants = generate_participants_with_random_ids(num_participants, &mut rng);
        args.participants = ParticipantList::new(&participants).unwrap();
        let delta_prime = args.derive_randomness().unwrap();
        assert_ne!(delta, delta_prime);
    }

    #[test]
    fn test_different_entropy() {
        let num_participants = 10;
        let mut rng = OsRng;
        let (mut args, delta) = compute_random_outputs(&mut rng, num_participants);

        // different entropy
        OsRng.fill_bytes(&mut args.entropy);
        let delta_prime = args.derive_randomness().unwrap();
        assert_ne!(delta, delta_prime);
    }

    // Test that with different order of participants, the randomness is the same.
    #[test]
    fn test_same_randomness() {
        let num_participants = 10;
        let mut rng = OsRng;
        let (mut args, delta) = compute_random_outputs(&mut rng, num_participants);

        // reshuffle
        args.participants = args.participants.shuffle(rng).unwrap();
        let delta_prime = args.derive_randomness().unwrap();
        assert_eq!(delta, delta_prime);
    }

    #[test]
    fn test_keygen() {
        let participants = generate_participants(3);
        let threshold = 2;
        crate::dkg::test::test_keygen::<C>(&participants, threshold);
    }

    #[test]
    fn test_refresh() {
        let participants = generate_participants(3);
        let threshold = 2;
        crate::dkg::test::test_refresh::<C>(&participants, threshold);
    }

    #[test]
    fn test_reshare() {
        let participants = generate_participants(3);
        let threshold0 = 2;
        let threshold1 = 3;
        crate::dkg::test::test_reshare::<C>(&participants, threshold0, threshold1);
    }
}
