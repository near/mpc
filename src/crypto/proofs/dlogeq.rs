use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;

use crate::{
    crypto::ciphersuite::{Ciphersuite, Element},
    protocol::errors::ProtocolError,
};

use frost_core::{serialization::SerializableScalar, Group, Scalar};

use super::strobe_transcript::Transcript;

/// The label we use for hashing the statement.
const STATEMENT_LABEL: &[u8] = b"dlogeq proof statement";
/// The label we use for hashing the first prover message.
const COMMITMENT_LABEL: &[u8] = b"dlogeq proof commitment";
/// The label we use for generating the challenge.
const CHALLENGE_LABEL: &[u8] = b"dlogeq proof challenge";
/// A string used to extend an encoding
const ENCODE_LABEL_STATEMENT: &[u8] = b"statement:";
/// A string used to extend an encoding
const ENCODE_LABEL_PUBLIC0: &[u8] = b"public 0:";
/// A string used to extend an encoding
const ENCODE_LABEL_PUBLIC1: &[u8] = b"public 1:";
/// A string used to extend an encoding
const ENCODE_LABEL_GENERATOR1: &[u8] = b"generator 1:";

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
    };
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
        enc.extend_from_slice(ENCODE_LABEL_STATEMENT);
        // None of the following calls should panic as neither public and generator are identity
        let ser0 = element_into::<C>(self.public0, ENCODE_LABEL_PUBLIC0)?;
        let ser1 = element_into::<C>(self.generator1, ENCODE_LABEL_GENERATOR1)?;
        let ser2 = element_into::<C>(self.public1, ENCODE_LABEL_PUBLIC1)?;
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

/// Prove that a witness satisfies a given statement.
/// We need some randomness for the proof, and also a transcript, which is
/// used for the Fiat-Shamir transform.
#[allow(dead_code)]
pub fn prove<C: Ciphersuite>(
    rng: &mut impl CryptoRngCore,
    transcript: &mut Transcript,
    statement: Statement<'_, C>,
    witness: Witness<C>,
) -> Result<Proof<C>, ProtocolError>
where
    Element<C>: ConstantTimeEq,
{
    if statement.generator1.ct_eq(&C::Group::identity()).into() {
        return Err(ProtocolError::IdentityElement);
    }
    transcript.message(STATEMENT_LABEL, &statement.encode()?);

    let k = frost_core::random_nonzero::<C, _>(rng);
    let (big_k_0, big_k_1) = statement.phi(&k);

    // This will never raise error as k is not zero and generator1 is not the identity
    let enc = encode_two_points::<C>(&big_k_0, &big_k_1)?;

    transcript.message(COMMITMENT_LABEL, &enc);
    let mut rng = transcript.challenge_then_build_rng(CHALLENGE_LABEL);
    let e = frost_core::random_nonzero::<C, _>(&mut rng);

    let s = k + e * witness.x.0;
    Ok(Proof {
        e: SerializableScalar::<C>(e),
        s: SerializableScalar::<C>(s),
    })
}

// Same as `prove` but using fixed nonce
pub fn prove_with_nonce<C: Ciphersuite>(
    transcript: &mut Transcript,
    statement: Statement<'_, C>,
    witness: Witness<C>,
    k: Scalar<C>,
) -> Result<Proof<C>, ProtocolError> {
    transcript.message(STATEMENT_LABEL, &statement.encode()?);

    if *statement.generator1 == C::Group::identity() {
        return Err(ProtocolError::IdentityElement);
    }

    let (big_k_0, big_k_1) = statement.phi(&k);

    // This will never raise error as k is not zero and generator1 is not the identity
    let enc = encode_two_points::<C>(&big_k_0, &big_k_1)?;

    transcript.message(COMMITMENT_LABEL, &enc);
    let mut rng = transcript.challenge_then_build_rng(CHALLENGE_LABEL);
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
    transcript.message(STATEMENT_LABEL, &statement.encode()?);

    let (phi0, phi1) = statement.phi(&proof.s.0);
    let big_k0 = phi0 - *statement.public0 * proof.e.0;
    let big_k1 = phi1 - *statement.public1 * proof.e.0;

    let enc = encode_two_points::<C>(&big_k0, &big_k1)?;

    transcript.message(COMMITMENT_LABEL, &enc);
    let mut rng = transcript.challenge_then_build_rng(CHALLENGE_LABEL);
    let e = frost_core::random_nonzero::<C, _>(&mut rng);

    Ok(e == proof.e.0)
}

#[cfg(test)]
mod test {
    use elliptic_curve::{bigint::Uint, scalar::FromUintUnchecked};
    use rand_core::OsRng;

    use crate::test::MockCryptoRng;

    use super::*;
    use frost_secp256k1::Secp256K1Sha256;
    use k256::{ProjectivePoint, Scalar};

    #[test]
    fn test_valid_proof_verifies() {
        let x = Scalar::generate_biased(&mut OsRng);

        let big_h = ProjectivePoint::GENERATOR * Scalar::generate_biased(&mut OsRng);
        let statement = Statement::<Secp256K1Sha256> {
            public0: &(ProjectivePoint::GENERATOR * x),
            generator1: &big_h,
            public1: &(big_h * x),
        };
        let witness = Witness {
            x: SerializableScalar::<Secp256K1Sha256>(x),
        };

        let transcript = Transcript::new(b"protocol");

        let proof = prove(
            &mut OsRng,
            &mut transcript.fork(b"party", &[1]),
            statement,
            witness,
        )
        .unwrap();

        let ok = verify(&mut transcript.fork(b"party", &[1]), statement, &proof).unwrap();

        assert!(ok);
    }

    #[test]
    fn test_prove_fixed_randomness() {
        let mut rng = MockCryptoRng::new([1; 8]);
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

        let transcript = Transcript::new(b"protocol");

        let proof = prove(
            &mut rng,
            &mut transcript.fork(b"party", &[1]),
            statement,
            witness,
        )
        .unwrap();
        assert_eq!(
            Scalar::from_uint_unchecked(Uint::from_be_hex(
                "067B14308E1E96A782791C10179F1801B6764037141CBA0462A4D495EB78B2D0"
            )),
            proof.s.0
        );
        assert_eq!(
            Scalar::from_uint_unchecked(Uint::from_be_hex(
                "95B6C33214488D2F0429129E9AF2CB2943F9F064421BB270918CFA412CB680E2"
            )),
            proof.e.0
        );
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
    fn test_prove_with_identity_generator1_fails() {
        let x = Scalar::generate_biased(&mut OsRng);

        let statement = Statement::<Secp256K1Sha256> {
            public0: &(ProjectivePoint::GENERATOR * x),
            generator1: &<Secp256K1Sha256 as frost_core::Ciphersuite>::Group::identity(), // Identity element
            public1: &(<Secp256K1Sha256 as frost_core::Ciphersuite>::Group::identity() * x),
        };
        let witness = Witness {
            x: SerializableScalar::<Secp256K1Sha256>(x),
        };

        let transcript = Transcript::new(b"protocol");

        let proof_result = prove(
            &mut OsRng,
            &mut transcript.fork(b"party", &[1]),
            statement,
            witness,
        );

        assert!(proof_result.is_err());
        if let Err(e) = proof_result {
            assert_eq!(e, ProtocolError::IdentityElement);
        } else {
            panic!("Expected an error, but got Ok");
        }
    }

    #[test]
    fn test_verify_with_identity_generator1_fails() {
        let x = Scalar::generate_biased(&mut OsRng);

        let statement = Statement::<Secp256K1Sha256> {
            public0: &(ProjectivePoint::GENERATOR * x),
            generator1: &<Secp256K1Sha256 as frost_core::Ciphersuite>::Group::identity(), // Identity element
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

        assert!(verify_result.is_err());
        if let Err(e) = verify_result {
            assert_eq!(e, ProtocolError::IdentityElement);
        } else {
            panic!("Expected an error, but got Ok");
        }
    }
}
