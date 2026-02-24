use super::strobe_transcript::Transcript;
use crate::{
    crypto::constants::{
        NEAR_DLOGEQ_CHALLENGE_LABEL, NEAR_DLOGEQ_COMMITMENT_LABEL,
        NEAR_DLOGEQ_ENCODE_LABEL_GENERATOR1, NEAR_DLOGEQ_ENCODE_LABEL_PUBLIC0,
        NEAR_DLOGEQ_ENCODE_LABEL_PUBLIC1, NEAR_DLOGEQ_ENCODE_LABEL_STATEMENT,
        NEAR_DLOGEQ_STATEMENT_LABEL,
    },
    errors::ProtocolError,
    Ciphersuite, Element, Scalar,
};
use frost_core::{serialization::SerializableScalar, Group};
use subtle::ConstantTimeEq;

/// The public statement for this proof.
/// This statement claims knowledge of a scalar that's the discrete logarithm
/// of one point under the standard generator, and of another point under an alternate generator.
#[derive(Clone, Copy)]
pub struct Statement<'a, C: Ciphersuite> {
    pub public0: &'a Element<C>,
    pub generator1: &'a Element<C>,
    pub public1: &'a Element<C>,
}

fn element_into<C: Ciphersuite>(
    point: &Element<C>,
    label: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let mut enc = Vec::new();
    match <C::Group as Group>::serialize(point) {
        Ok(ser) => {
            enc.extend_from_slice(label);
            enc.extend_from_slice(ser.as_ref());
        }
        // unreachable as either the statement is locally created
        // and thus the points are well defined, or it is received
        // from someone and thus it is serializable.
        _ => return Err(ProtocolError::PointSerialization),
    }
    Ok(enc)
}

impl<C: Ciphersuite> Statement<'_, C> {
    /// Calculate the homomorphism we want to prove things about.
    fn phi(&self, x: &Scalar<C>) -> (Element<C>, Element<C>) {
        (C::Group::generator() * *x, *self.generator1 * *x)
    }

    /// Encode into Vec<u8>: some sort of serialization
    fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut enc = Vec::new();
        enc.extend_from_slice(NEAR_DLOGEQ_ENCODE_LABEL_STATEMENT);
        // None of the following calls should panic as neither public and generator are identity
        let ser0 = element_into::<C>(self.public0, NEAR_DLOGEQ_ENCODE_LABEL_PUBLIC0)?;
        let ser1 = element_into::<C>(self.generator1, NEAR_DLOGEQ_ENCODE_LABEL_GENERATOR1)?;
        let ser2 = element_into::<C>(self.public1, NEAR_DLOGEQ_ENCODE_LABEL_PUBLIC1)?;
        enc.extend_from_slice(&ser0);
        enc.extend_from_slice(&ser1);
        enc.extend_from_slice(&ser2);
        Ok(enc)
    }
}

/// The private witness for this proof.
/// This holds the scalar the prover needs to know.
#[derive(Clone, Copy)]
pub struct Witness<C: Ciphersuite> {
    pub x: SerializableScalar<C>,
}

/// Represents a proof of the statement.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct Proof<C: Ciphersuite> {
    e: SerializableScalar<C>,
    s: SerializableScalar<C>,
}

/// Encodes two EC points into a vec including the identity point.
/// Should be used with HIGH precaution as it allows serializing the identity point
/// deviating from the standard
fn encode_two_points<C: Ciphersuite>(
    point_1: &Element<C>,
    point_2: &Element<C>,
) -> Result<Vec<u8>, ProtocolError> {
    // Create a serialization of big_k
    let mut ser1 = C::Group::serialize(point_1)
        .map_err(|_| ProtocolError::IdentityElement)?
        .as_ref()
        .to_vec();

    let ser2 = C::Group::serialize(point_2)
        .map_err(|_| ProtocolError::IdentityElement)?
        .as_ref()
        .to_vec();

    ser1.extend_from_slice(b" and ");
    ser1.extend_from_slice(&ser2);
    Ok(ser1)
}

/// Produce a proof for the given statement and witness, using a caller-provided nonce.
/// The nonce `k` must be sampled from a cryptographically secure RNG by the caller.
/// The challenge is derived via the Fiat-Shamir transform over the transcript.
pub fn prove_with_nonce<C: Ciphersuite>(
    transcript: &mut Transcript,
    statement: Statement<'_, C>,
    witness: Witness<C>,
    k: Scalar<C>,
) -> Result<Proof<C>, ProtocolError>
where
    Element<C>: ConstantTimeEq,
{
    if statement.generator1.ct_eq(&C::Group::identity()).into() {
        return Err(ProtocolError::IdentityElement);
    }

    transcript.message(NEAR_DLOGEQ_STATEMENT_LABEL, &statement.encode()?);

    let (big_k_0, big_k_1) = statement.phi(&k);

    // This will never raise error as k is not zero and generator1 is not the identity
    let enc = encode_two_points::<C>(&big_k_0, &big_k_1)?;

    transcript.message(NEAR_DLOGEQ_COMMITMENT_LABEL, &enc);
    let mut rng = transcript.challenge_then_build_rng(NEAR_DLOGEQ_CHALLENGE_LABEL);
    let e = frost_core::random_nonzero::<C, _>(&mut rng);

    let s = k + e * witness.x.0;
    Ok(Proof {
        e: SerializableScalar::<C>(e),
        s: SerializableScalar::<C>(s),
    })
}

/// Verify that a proof attesting to the validity of some statement.
///
/// We use a transcript in order to verify the Fiat-Shamir transformation.
pub fn verify<C: Ciphersuite>(
    transcript: &mut Transcript,
    statement: Statement<'_, C>,
    proof: &Proof<C>,
) -> Result<bool, ProtocolError>
where
    Element<C>: ConstantTimeEq,
{
    if statement.generator1.ct_eq(&C::Group::identity()).into() {
        return Err(ProtocolError::IdentityElement);
    }

    transcript.message(NEAR_DLOGEQ_STATEMENT_LABEL, &statement.encode()?);

    let (phi0, phi1) = statement.phi(&proof.s.0);
    let big_k0 = phi0 - *statement.public0 * proof.e.0;
    let big_k1 = phi1 - *statement.public1 * proof.e.0;

    let enc = encode_two_points::<C>(&big_k0, &big_k1)?;

    transcript.message(NEAR_DLOGEQ_COMMITMENT_LABEL, &enc);
    let mut rng = transcript.challenge_then_build_rng(NEAR_DLOGEQ_CHALLENGE_LABEL);
    let e = frost_core::random_nonzero::<C, _>(&mut rng);

    Ok(e == proof.e.0)
}

#[cfg(test)]
mod test {
    use elliptic_curve::{bigint::Uint, scalar::FromUintUnchecked};
    use rand::SeedableRng;

    use crate::test_utils::MockCryptoRng;

    use super::*;
    use frost_secp256k1::Secp256K1Sha256;
    use k256::{ProjectivePoint, Scalar};

    #[test]
    fn test_valid_proof_verifies() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let x = Scalar::generate_biased(&mut rng);

        let big_h = ProjectivePoint::GENERATOR * Scalar::generate_biased(&mut rng);
        let statement = Statement::<Secp256K1Sha256> {
            public0: &(ProjectivePoint::GENERATOR * x),
            generator1: &big_h,
            public1: &(big_h * x),
        };
        let witness = Witness {
            x: SerializableScalar::<Secp256K1Sha256>(x),
        };

        let k = frost_core::random_nonzero::<Secp256K1Sha256, _>(&mut rng);
        let transcript = Transcript::new(b"protocol");

        let proof =
            prove_with_nonce(&mut transcript.fork(b"party", &[1]), statement, witness, k).unwrap();

        let ok = verify(&mut transcript.fork(b"party", &[1]), statement, &proof).unwrap();

        assert!(ok);
    }

    #[test]
    fn test_prove_with_nonce_fixed_randomness() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let x = Scalar::generate_biased(&mut rng);
        let h = Scalar::generate_biased(&mut rng);
        let big_h = ProjectivePoint::GENERATOR * h;

        let statement = Statement::<Secp256K1Sha256> {
            public0: &(ProjectivePoint::GENERATOR * x),
            generator1: &big_h,
            public1: &(big_h * x),
        };
        let witness = Witness {
            x: SerializableScalar::<Secp256K1Sha256>(x),
        };

        let k = frost_core::random_nonzero::<Secp256K1Sha256, _>(&mut rng);
        let transcript = Transcript::new(b"protocol");

        let proof =
            prove_with_nonce(&mut transcript.fork(b"party", &[1]), statement, witness, k).unwrap();

        // Snapshot values for deterministic nonce from MockCryptoRng(42)
        insta::assert_snapshot!(format!("{:?}", proof.s.0), @"Scalar(Uint(0x0D5982BE2922D4BF893BFA4F0086C59738CA1F77BCA4316F28F263E2F1347C21))");
        insta::assert_snapshot!(format!("{:?}", proof.e.0), @"Scalar(Uint(0x2912F8772B0E33708AD3A3F8A587FCBE23A50109496F4A3F8669979F2B78AEFD))");
    }

    #[test]
    fn test_verify_fixed_randomness() {
        let x = Scalar::from_uint_unchecked(Uint::from_be_hex(
            "FC9A011DF3753BD79D841C11F6521F25AD2AB1DECEB96B7E8C28D87EA3303A06",
        ));
        let h = Scalar::from_uint_unchecked(Uint::from_be_hex(
            "FC9A011DF3753BD79D841C11F6521F25AD2AB1DECEB96B7E8C28D87EA3303A06",
        ));
        let big_h = ProjectivePoint::GENERATOR * h;
        let transcript = Transcript::new(b"protocol");
        let statement = Statement::<Secp256K1Sha256> {
            public0: &(ProjectivePoint::GENERATOR * x),
            generator1: &big_h,
            public1: &(big_h * x),
        };
        let proof: Proof<Secp256K1Sha256> = Proof {
            s: SerializableScalar(Scalar::from_uint_unchecked(Uint::from_be_hex(
                "067B14308E1E96A782791C10179F1801B6764037141CBA0462A4D495EB78B2D0",
            ))),
            e: SerializableScalar(Scalar::from_uint_unchecked(Uint::from_be_hex(
                "95B6C33214488D2F0429129E9AF2CB2943F9F064421BB270918CFA412CB680E2",
            ))),
        };
        assert!(verify(&mut transcript.fork(b"party", &[1]), statement, &proof).unwrap());
    }

    #[test]
    fn test_prove_with_nonce_identity_generator1_fails() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let x = Scalar::generate_biased(&mut rng);

        let statement = Statement::<Secp256K1Sha256> {
            public0: &(ProjectivePoint::GENERATOR * x),
            generator1: &<Secp256K1Sha256 as frost_core::Ciphersuite>::Group::identity(),
            public1: &(<Secp256K1Sha256 as frost_core::Ciphersuite>::Group::identity() * x),
        };
        let witness = Witness {
            x: SerializableScalar::<Secp256K1Sha256>(x),
        };

        let k = frost_core::random_nonzero::<Secp256K1Sha256, _>(&mut rng);
        let transcript = Transcript::new(b"protocol");

        let proof_result =
            prove_with_nonce(&mut transcript.fork(b"party", &[1]), statement, witness, k);

        assert!(matches!(proof_result, Err(ProtocolError::IdentityElement)));
    }

    #[test]
    fn test_verify_with_identity_generator1_fails() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let x = Scalar::generate_biased(&mut rng);

        let statement = Statement::<Secp256K1Sha256> {
            public0: &(ProjectivePoint::GENERATOR * x),
            generator1: &<Secp256K1Sha256 as frost_core::Ciphersuite>::Group::identity(),
            public1: &(<Secp256K1Sha256 as frost_core::Ciphersuite>::Group::identity() * x),
        };

        // A dummy proof, its content doesn't matter for this test
        let dummy_proof = Proof {
            e: SerializableScalar::<Secp256K1Sha256>(Scalar::from(1u64)),
            s: SerializableScalar::<Secp256K1Sha256>(Scalar::from(1u64)),
        };

        let transcript = Transcript::new(b"protocol");

        let verify_result = verify(
            &mut transcript.fork(b"party", &[1]),
            statement,
            &dummy_proof,
        );

        assert!(matches!(verify_result, Err(ProtocolError::IdentityElement)));
    }
}
