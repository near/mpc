//! Sigma protocol (Fiat-Shamir) proving `W = a * R + b * G` consistent with the Pedersen
//! commitments to `a` and `b`. Callers bind the context (η, party index) into the transcript.

use super::strobe_transcript::Transcript;
use crate::{
    Ciphersuite, Element, Scalar,
    crypto::constants::{
        NEAR_W_OPENING_CHALLENGE_LABEL, NEAR_W_OPENING_COMMITMENT_LABEL,
        NEAR_W_OPENING_ENCODE_LABEL_BIG_R, NEAR_W_OPENING_ENCODE_LABEL_BIG_W,
        NEAR_W_OPENING_ENCODE_LABEL_COM_A, NEAR_W_OPENING_ENCODE_LABEL_COM_B,
        NEAR_W_OPENING_ENCODE_LABEL_H_PED, NEAR_W_OPENING_ENCODE_LABEL_STATEMENT,
        NEAR_W_OPENING_STATEMENT_LABEL,
    },
    errors::ProtocolError,
};
use frost_core::{Group, serialization::SerializableScalar};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Public statement: an opening `(a, b, ρ, σ)` of `big_w` consistent with `com_a` and `com_b`.
#[derive(Clone, Copy)]
pub struct Statement<'a, C: Ciphersuite> {
    /// `W = w * G` for the proven opening `w = a * k + b`.
    pub big_w: &'a Element<C>,
    /// The nonce commitment `R = k * G`.
    pub big_r: &'a Element<C>,
    /// Pedersen commitment `a * G + ρ * H`.
    pub com_a: &'a Element<C>,
    /// Pedersen commitment `b * G + σ * H`.
    pub com_b: &'a Element<C>,
    /// The Pedersen generator `H` with unknown discrete log.
    pub h_ped: &'a Element<C>,
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
        // unreachable: statement points are locally built or were deserialized
        _ => return Err(ProtocolError::PointSerialization),
    }
    Ok(enc)
}

impl<C: Ciphersuite> Statement<'_, C> {
    /// Encodes the statement for the transcript.
    fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut enc = Vec::new();
        enc.extend_from_slice(NEAR_W_OPENING_ENCODE_LABEL_STATEMENT);
        enc.extend_from_slice(&element_into::<C>(
            self.big_w,
            NEAR_W_OPENING_ENCODE_LABEL_BIG_W,
        )?);
        enc.extend_from_slice(&element_into::<C>(
            self.big_r,
            NEAR_W_OPENING_ENCODE_LABEL_BIG_R,
        )?);
        enc.extend_from_slice(&element_into::<C>(
            self.com_a,
            NEAR_W_OPENING_ENCODE_LABEL_COM_A,
        )?);
        enc.extend_from_slice(&element_into::<C>(
            self.com_b,
            NEAR_W_OPENING_ENCODE_LABEL_COM_B,
        )?);
        enc.extend_from_slice(&element_into::<C>(
            self.h_ped,
            NEAR_W_OPENING_ENCODE_LABEL_H_PED,
        )?);
        Ok(enc)
    }
}

/// Private witness: the opening `(a, b, ρ, σ)`.
#[derive(Clone)]
pub struct Witness<C: Ciphersuite>
where
    Scalar<C>: Zeroize,
{
    pub a: SerializableScalar<C>,
    pub b: SerializableScalar<C>,
    pub rho: SerializableScalar<C>,
    pub sigma: SerializableScalar<C>,
}

impl<C: Ciphersuite> Zeroize for Witness<C>
where
    Scalar<C>: Zeroize,
{
    fn zeroize(&mut self) {
        self.a.0.zeroize();
        self.b.0.zeroize();
        self.rho.0.zeroize();
        self.sigma.0.zeroize();
    }
}

impl<C: Ciphersuite> Drop for Witness<C>
where
    Scalar<C>: Zeroize,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Nonces `(u_a, u_b, u_ρ, u_σ)`, sampled by the caller from a secure RNG.
pub type Nonces<C> = (Scalar<C>, Scalar<C>, Scalar<C>, Scalar<C>);

/// Proof of the statement.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct Proof<C: Ciphersuite> {
    e: SerializableScalar<C>,
    z_a: SerializableScalar<C>,
    z_b: SerializableScalar<C>,
    z_rho: SerializableScalar<C>,
    z_sigma: SerializableScalar<C>,
}

/// Encodes three points, erroring on the identity.
fn encode_three_points<C: Ciphersuite>(
    point_1: &Element<C>,
    point_2: &Element<C>,
    point_3: &Element<C>,
) -> Result<Vec<u8>, ProtocolError> {
    let mut ser = C::Group::serialize(point_1)
        .map_err(|_| ProtocolError::IdentityElement)?
        .as_ref()
        .to_vec();
    for point in [point_2, point_3] {
        let ser_next = C::Group::serialize(point).map_err(|_| ProtocolError::IdentityElement)?;
        ser.extend_from_slice(b" and ");
        ser.extend_from_slice(ser_next.as_ref());
    }
    Ok(ser)
}

/// Proof commitments: `K0 = t_a * R + t_b * G`, `K1 = t_a * G + t_ρ * H`,
/// `K2 = t_b * G + t_σ * H`.
fn phi<C: Ciphersuite>(
    statement: &Statement<'_, C>,
    t_a: &Scalar<C>,
    t_b: &Scalar<C>,
    t_rho: &Scalar<C>,
    t_sigma: &Scalar<C>,
) -> (Element<C>, Element<C>, Element<C>) {
    let generator = C::Group::generator();
    (
        *statement.big_r * *t_a + generator * *t_b,
        generator * *t_a + *statement.h_ped * *t_rho,
        generator * *t_b + *statement.h_ped * *t_sigma,
    )
}

/// Proves the statement with caller-provided nonces (challenge: Fiat-Shamir over the transcript).
pub fn prove_with_nonces<C: Ciphersuite>(
    transcript: &mut Transcript,
    statement: Statement<'_, C>,
    witness: &Witness<C>,
    nonces: &Nonces<C>,
) -> Result<Proof<C>, ProtocolError>
where
    Element<C>: ConstantTimeEq,
    Scalar<C>: Zeroize,
{
    if statement.h_ped.ct_eq(&C::Group::identity()).into() {
        return Err(ProtocolError::IdentityElement);
    }

    transcript.message(NEAR_W_OPENING_STATEMENT_LABEL, &statement.encode()?);

    let (u_a, u_b, u_rho, u_sigma) = nonces;
    let (big_k0, big_k1, big_k2) = phi(&statement, u_a, u_b, u_rho, u_sigma);

    let enc = encode_three_points::<C>(&big_k0, &big_k1, &big_k2)?;
    transcript.message(NEAR_W_OPENING_COMMITMENT_LABEL, &enc);
    let mut rng = transcript.challenge_then_build_rng(NEAR_W_OPENING_CHALLENGE_LABEL);
    let e = frost_core::random_nonzero::<C, _>(&mut rng);

    Ok(Proof {
        e: SerializableScalar::<C>(e),
        z_a: SerializableScalar::<C>(*u_a + e * witness.a.0),
        z_b: SerializableScalar::<C>(*u_b + e * witness.b.0),
        z_rho: SerializableScalar::<C>(*u_rho + e * witness.rho.0),
        z_sigma: SerializableScalar::<C>(*u_sigma + e * witness.sigma.0),
    })
}

/// Verifies a proof by replaying the Fiat-Shamir transcript.
pub fn verify<C: Ciphersuite>(
    transcript: &mut Transcript,
    statement: Statement<'_, C>,
    proof: &Proof<C>,
) -> Result<bool, ProtocolError>
where
    Element<C>: ConstantTimeEq,
    Scalar<C>: ConstantTimeEq,
{
    if statement.h_ped.ct_eq(&C::Group::identity()).into() {
        return Err(ProtocolError::IdentityElement);
    }

    transcript.message(NEAR_W_OPENING_STATEMENT_LABEL, &statement.encode()?);

    let (phi0, phi1, phi2) = phi(
        &statement,
        &proof.z_a.0,
        &proof.z_b.0,
        &proof.z_rho.0,
        &proof.z_sigma.0,
    );
    let big_k0 = phi0 - *statement.big_w * proof.e.0;
    let big_k1 = phi1 - *statement.com_a * proof.e.0;
    let big_k2 = phi2 - *statement.com_b * proof.e.0;

    let enc = encode_three_points::<C>(&big_k0, &big_k1, &big_k2)?;
    transcript.message(NEAR_W_OPENING_COMMITMENT_LABEL, &enc);
    let mut rng = transcript.challenge_then_build_rng(NEAR_W_OPENING_CHALLENGE_LABEL);
    let e = frost_core::random_nonzero::<C, _>(&mut rng);

    Ok(bool::from(e.ct_eq(&proof.e.0)))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::MockCryptoRng;
    use frost_secp256k1::Secp256K1Sha256;
    use k256::{ProjectivePoint, Scalar};
    use rand::SeedableRng;

    type C = Secp256K1Sha256;

    struct TestCase {
        statement_points: [ProjectivePoint; 5],
        witness: Witness<C>,
        nonces: Nonces<C>,
        transcript: Transcript,
    }

    fn make_test_case(seed: u64) -> TestCase {
        let mut rng = MockCryptoRng::seed_from_u64(seed);
        let a = Scalar::generate_biased(&mut rng);
        let b = Scalar::generate_biased(&mut rng);
        let rho = Scalar::generate_biased(&mut rng);
        let sigma = Scalar::generate_biased(&mut rng);
        let k = Scalar::generate_biased(&mut rng);
        let h = ProjectivePoint::GENERATOR * Scalar::generate_biased(&mut rng);

        let big_r = ProjectivePoint::GENERATOR * k;
        let big_w = ProjectivePoint::GENERATOR * (a * k + b);
        let com_a = ProjectivePoint::GENERATOR * a + h * rho;
        let com_b = ProjectivePoint::GENERATOR * b + h * sigma;

        let nonces = (
            frost_core::random_nonzero::<C, _>(&mut rng),
            frost_core::random_nonzero::<C, _>(&mut rng),
            frost_core::random_nonzero::<C, _>(&mut rng),
            frost_core::random_nonzero::<C, _>(&mut rng),
        );

        let transcript = Transcript::new(b"protocol");

        TestCase {
            statement_points: [big_w, big_r, com_a, com_b, h],
            witness: Witness {
                a: SerializableScalar(a),
                b: SerializableScalar(b),
                rho: SerializableScalar(rho),
                sigma: SerializableScalar(sigma),
            },
            nonces,
            transcript,
        }
    }

    fn make_statement(points: &[ProjectivePoint; 5]) -> Statement<'_, C> {
        Statement {
            big_w: &points[0],
            big_r: &points[1],
            com_a: &points[2],
            com_b: &points[3],
            h_ped: &points[4],
        }
    }

    #[test]
    fn test_valid_proof_verifies() {
        let case = make_test_case(42);
        let statement = make_statement(&case.statement_points);

        let proof = prove_with_nonces(
            &mut case.transcript.fork(b"party", &[1]),
            statement,
            &case.witness,
            &case.nonces,
        )
        .unwrap();

        assert!(verify(&mut case.transcript.fork(b"party", &[1]), statement, &proof).unwrap());
    }

    #[test]
    fn test_wrong_witness_fails() {
        let case = make_test_case(42);
        let statement = make_statement(&case.statement_points);

        let mut witness = case.witness.clone();
        witness.a.0 += Scalar::ONE;
        let proof = prove_with_nonces(
            &mut case.transcript.fork(b"party", &[1]),
            statement,
            &witness,
            &case.nonces,
        )
        .unwrap();

        assert!(!verify(&mut case.transcript.fork(b"party", &[1]), statement, &proof).unwrap());
    }

    #[test]
    fn test_different_party_fork_fails() {
        let case = make_test_case(42);
        let statement = make_statement(&case.statement_points);

        let proof = prove_with_nonces(
            &mut case.transcript.fork(b"party", &[1]),
            statement,
            &case.witness,
            &case.nonces,
        )
        .unwrap();

        assert!(!verify(&mut case.transcript.fork(b"party", &[2]), statement, &proof).unwrap());
    }

    #[test]
    fn test_different_transcript_context_fails() {
        let case = make_test_case(42);
        let statement = make_statement(&case.statement_points);

        let mut prover_transcript = case.transcript.fork(b"party", &[1]);
        let proof = prove_with_nonces(
            &mut prover_transcript,
            statement,
            &case.witness,
            &case.nonces,
        )
        .unwrap();

        // verifier absorbed a different context (e.g. another eta)
        let other_transcript = Transcript::new(b"protocol");
        let mut verifier_transcript = other_transcript.fork(b"party", &[1]);
        verifier_transcript.message(b"eta", b"different context");
        assert!(!verify(&mut verifier_transcript, statement, &proof).unwrap());
    }

    #[test]
    fn test_swapped_statement_fails() {
        let case = make_test_case(42);
        let statement = make_statement(&case.statement_points);

        let proof = prove_with_nonces(
            &mut case.transcript.fork(b"party", &[1]),
            statement,
            &case.witness,
            &case.nonces,
        )
        .unwrap();

        // com_a and com_b swapped
        let mut swapped_points = case.statement_points;
        swapped_points.swap(2, 3);
        let swapped = make_statement(&swapped_points);
        assert!(!verify(&mut case.transcript.fork(b"party", &[1]), swapped, &proof).unwrap());
    }

    #[test]
    fn test_identity_h_ped_fails() {
        let case = make_test_case(42);
        let mut points = case.statement_points;
        points[4] = ProjectivePoint::IDENTITY;
        let statement = make_statement(&points);

        let result = prove_with_nonces(
            &mut case.transcript.fork(b"party", &[1]),
            statement,
            &case.witness,
            &case.nonces,
        );
        let Err(e) = result else {
            panic!("expected IdentityElement error");
        };
        assert_eq!(e, ProtocolError::IdentityElement);

        let dummy_proof = Proof::<C> {
            e: SerializableScalar(Scalar::ONE),
            z_a: SerializableScalar(Scalar::ONE),
            z_b: SerializableScalar(Scalar::ONE),
            z_rho: SerializableScalar(Scalar::ONE),
            z_sigma: SerializableScalar(Scalar::ONE),
        };
        let result = verify(
            &mut case.transcript.fork(b"party", &[1]),
            statement,
            &dummy_proof,
        );
        let Err(e) = result else {
            panic!("expected IdentityElement error");
        };
        assert_eq!(e, ProtocolError::IdentityElement);
    }

    #[test]
    fn test_proof_serde_roundtrip() {
        let case = make_test_case(42);
        let statement = make_statement(&case.statement_points);

        let proof = prove_with_nonces(
            &mut case.transcript.fork(b"party", &[1]),
            statement,
            &case.witness,
            &case.nonces,
        )
        .unwrap();

        let ser = serde_json::to_string(&proof).unwrap();
        let de: Proof<C> = serde_json::from_str(&ser).unwrap();
        assert!(verify(&mut case.transcript.fork(b"party", &[1]), statement, &de).unwrap());
    }

    #[test]
    fn test_prove_with_nonces_fixed_randomness() {
        let case = make_test_case(42);
        let statement = make_statement(&case.statement_points);

        let proof = prove_with_nonces(
            &mut case.transcript.fork(b"party", &[1]),
            statement,
            &case.witness,
            &case.nonces,
        )
        .unwrap();

        // deterministic nonces from MockCryptoRng(42)
        insta::assert_snapshot!(format!(
            "e: {:?}\nz_a: {:?}\nz_b: {:?}\nz_rho: {:?}\nz_sigma: {:?}",
            proof.e.0, proof.z_a.0, proof.z_b.0, proof.z_rho.0, proof.z_sigma.0
        ));
    }
}
