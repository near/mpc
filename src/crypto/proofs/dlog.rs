use crate::{
    crypto::{
        ciphersuite::{Ciphersuite, Element},
        proofs::strobe_transcript::TranscriptRng,
    },
    protocol::errors::ProtocolError,
};
use frost_core::{serialization::SerializableScalar, Group, Scalar};

use super::strobe_transcript::Transcript;
use rand_core::CryptoRngCore;

/// The label we use for hashing the statement.
const STATEMENT_LABEL: &[u8] = b"dlog proof statement";
/// The label we use for hashing the first prover message.
const COMMITMENT_LABEL: &[u8] = b"dlog proof commitment";
/// The label we use for generating the challenge.
const CHALLENGE_LABEL: &[u8] = b"dlog proof challenge";
/// A string used to extend an encoding
const ENCODE_LABEL_STATEMENT: &[u8] = b"statement:";
/// A string used to extend an encoding
const ENCODE_LABEL_PUBLIC: &[u8] = b"public:";

/// The public statement for this proof.
/// This statement claims knowledge of the discrete logarithm of some point.
#[derive(Clone, Copy)]
pub struct Statement<'a, C: Ciphersuite> {
    pub public: &'a Element<C>,
}

impl<C: Ciphersuite> Statement<'_, C> {
    /// Encode into Vec<u8>: some sort of serialization
    fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut enc = Vec::new();
        enc.extend_from_slice(ENCODE_LABEL_STATEMENT);

        match <C::Group as Group>::serialize(self.public) {
            Ok(ser) => {
                enc.extend_from_slice(ENCODE_LABEL_PUBLIC);
                enc.extend_from_slice(ser.as_ref());
            }
            _ => return Err(ProtocolError::PointSerialization),
        };
        Ok(enc)
    }
}

/// The private witness for this proof.
/// This holds the scalar the prover needs to know.
#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
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

/// Prove that a witness satisfies a given statement.
/// We need some randomness for the proof, and also a transcript, which is
/// used for the Fiat-Shamir transform.
pub fn prove<C: Ciphersuite>(
    rng: &mut impl CryptoRngCore,
    transcript: &mut Transcript,
    statement: Statement<'_, C>,
    witness: Witness<C>,
) -> Result<Proof<C>, ProtocolError> {
    transcript.message(STATEMENT_LABEL, &statement.encode()?);

    let (k, big_k) = <C>::generate_nonce(rng);

    // Create a serialization of big_k
    let ser = C::Group::serialize(&big_k).map_err(|_| ProtocolError::IdentityElement)?;
    transcript.message(COMMITMENT_LABEL, ser.as_ref());
    let mut rng = transcript.challenge_then_build_rng(CHALLENGE_LABEL);
    let e = frost_core::random_nonzero::<C, _>(&mut rng);

    let s = k + e * witness.x.0;
    Ok(Proof {
        e: SerializableScalar(e),
        s: SerializableScalar(s),
    })
}

// Same as the function `prove`, but given nonce
pub fn prove_with_nonce<C: Ciphersuite>(
    transcript: &mut Transcript,
    statement: Statement<'_, C>,
    witness: Witness<C>,
    nonce: (Scalar<C>, Element<C>),
) -> Result<Proof<C>, ProtocolError> {
    transcript.message(STATEMENT_LABEL, &statement.encode()?);

    let (k, big_k) = nonce;

    // Create a serialization of big_k
    let ser = C::Group::serialize(&big_k).map_err(|_| ProtocolError::IdentityElement)?;
    transcript.message(COMMITMENT_LABEL, ser.as_ref());
    let mut rng = transcript.challenge_then_build_rng(CHALLENGE_LABEL);
    let e = frost_core::random_nonzero::<C, _>(&mut rng);

    let s = k + e * witness.x.0;
    Ok(Proof {
        e: SerializableScalar(e),
        s: SerializableScalar(s),
    })
}

/// Verify that a proof attesting to the validity of some statement.
/// We use a transcript in order to verify the Fiat-Shamir transformation.
pub fn verify<C: Ciphersuite>(
    transcript: &mut Transcript,
    statement: Statement<'_, C>,
    proof: &Proof<C>,
) -> Result<bool, ProtocolError> {
    transcript.message(STATEMENT_LABEL, &statement.encode()?);

    let big_k = C::Group::generator() * proof.s.0 - *statement.public * proof.e.0;

    // Create a serialization of big_k
    // Raises error if the big_k turned out to be the identity element
    let ser = C::Group::serialize(&big_k).map_err(|_| ProtocolError::IdentityElement)?;

    transcript.message(COMMITMENT_LABEL, ser.as_ref());
    let mut rng = transcript.challenge_then_build_rng(CHALLENGE_LABEL);
    let e = frost_core::random_nonzero::<C, TranscriptRng>(&mut rng);

    Ok(e == proof.e.0)
}

#[cfg(test)]
mod test {
    use elliptic_curve::{bigint::Uint, scalar::FromUintUnchecked};
    use rand_core::OsRng;

    use super::*;
    use crate::test::MockCryptoRng;
    use frost_secp256k1::Secp256K1Sha256;
    use k256::{ProjectivePoint, Scalar};

    #[test]
    fn test_valid_proof_verifies() {
        let x = Scalar::generate_biased(&mut OsRng);

        let statement = Statement::<Secp256K1Sha256> {
            public: &(ProjectivePoint::GENERATOR * x),
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

        let statement = Statement::<Secp256K1Sha256> {
            public: &(ProjectivePoint::GENERATOR * x),
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
                "5086B275DC32C8CD1AAD377918E0B622BAF92844BDC46808BD5568D6E304DB33"
            )),
            proof.s.0
        );
        assert_eq!(
            Scalar::from_uint_unchecked(Uint::from_be_hex(
                "BA7718DDF60BC62FC6081B658322E908CD4FF161AB754748EC170CBC66898CDB"
            )),
            proof.e.0
        );
    }

    #[test]
    fn test_verify_fixed_randomness() {
        let x = Scalar::from_uint_unchecked(Uint::from_be_hex(
            "FC9A011DF3753BD79D841C11F6521F25AD2AB1DECEB96B7E8C28D87EA3303A06",
        ));
        let transcript = Transcript::new(b"protocol");
        let statement = Statement::<Secp256K1Sha256> {
            public: &(ProjectivePoint::GENERATOR * x),
        };
        let proof: Proof<Secp256K1Sha256> = Proof {
            e: SerializableScalar(Scalar::from_uint_unchecked(Uint::from_be_hex(
                "BA7718DDF60BC62FC6081B658322E908CD4FF161AB754748EC170CBC66898CDB",
            ))),
            s: SerializableScalar(Scalar::from_uint_unchecked(Uint::from_be_hex(
                "5086B275DC32C8CD1AAD377918E0B622BAF92844BDC46808BD5568D6E304DB33",
            ))),
        };
        assert!(verify(&mut transcript.fork(b"party", &[1]), statement, &proof).unwrap());
    }
}
