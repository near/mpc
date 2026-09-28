//! Pedersen commitments over secp256k1: `Com(v; r) = v * G + r * H`.
//!
//! [`PEDERSEN_H`] is a second generator derived by hashing a fixed tag to
//! the curve ([RFC 9380](https://www.rfc-editor.org/rfc/rfc9380)), so that no
//! party can know its discrete logarithm. [`commit_polynomial`] extends `Com`
//! coefficientwise to polynomials; by linearity `Com(f; r)(j) = Com(f(j); r(j))`,
//! which is what [`verify_share`] checks.

use std::sync::LazyLock;

use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use elliptic_curve::ops::LinearCombination;
use k256::{ProjectivePoint, Secp256k1};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::crypto::constants::{NEAR_PEDERSEN_GENERATOR_DST, NEAR_PEDERSEN_GENERATOR_MSG};
use crate::ecdsa::{CoefficientCommitment, Element, Polynomial, PolynomialCommitment, Scalar};
use crate::errors::ProtocolError;
use crate::participants::Participant;

/// The Pedersen generator `H`: a fixed public constant with unknown discrete
/// logarithm relative to the group generator `G`.
pub static PEDERSEN_H: LazyLock<Element> = LazyLock::new(|| {
    Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[NEAR_PEDERSEN_GENERATOR_MSG],
        &[NEAR_PEDERSEN_GENERATOR_DST],
    )
    .expect("hash-to-curve with a fixed, non-empty DST of valid length never fails")
});

/// Computes the Pedersen commitment `Com(value; blinding) = value * G + blinding * H`.
pub fn commit(value: &Scalar, blinding: &Scalar) -> Element {
    ProjectivePoint::lincomb(&ProjectivePoint::GENERATOR, value, &PEDERSEN_H, blinding)
}

/// Commits to `f` coefficientwise under the blinding `r`: coefficient `m` is `Com(f_m; r_m)`.
/// Errors if the two polynomials do not have the same degree.
pub fn commit_polynomial(
    f: &Polynomial,
    r: &Polynomial,
) -> Result<PolynomialCommitment, ProtocolError> {
    let f_coefficients = f.coefficients();
    let r_coefficients = r.coefficients();
    if f_coefficients.len() != r_coefficients.len() {
        return Err(ProtocolError::InvalidInput(
            "the blinding polynomial must have the same degree as the committed polynomial"
                .to_string(),
        ));
    }
    let commitments = f_coefficients
        .iter()
        .zip(r_coefficients)
        .map(|(f_m, r_m)| CoefficientCommitment::new(commit(f_m, r_m)))
        .collect::<Vec<_>>();
    PolynomialCommitment::new(&commitments)
}

/// Checks that `(value, blinding)` opens the committed polynomial at `participant`,
/// i.e. that `Com(value; blinding) = committed(participant)`.
pub fn verify_share(
    committed: &PolynomialCommitment,
    participant: Participant,
    value: &Scalar,
    blinding: &Scalar,
) -> Result<bool, ProtocolError> {
    let expected = committed.eval_at_participant(participant)?;
    Ok(bool::from(expected.value().ct_eq(&commit(value, blinding))))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::MockCryptoRng;
    use assert_matches::assert_matches;
    use frost_secp256k1::{Field, Group, Secp256K1Group, Secp256K1ScalarField};
    use rand::SeedableRng;

    #[test]
    #[allow(non_snake_case)]
    fn pedersen_generator__should_be_a_valid_pinned_point() {
        // Given
        let h = *PEDERSEN_H;

        // Then
        assert!(bool::from(h.ct_ne(&Secp256K1Group::identity())));
        assert!(bool::from(h.ct_ne(&Secp256K1Group::generator())));

        // Pin the generator so any change to its derivation is caught.
        let ser = Secp256K1Group::serialize(&h).expect("H is not the identity");
        insta::assert_snapshot!(hex::encode(ser));
    }

    #[test]
    #[allow(non_snake_case)]
    fn commit__should_bind_to_both_value_and_blinding() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let v = Secp256K1ScalarField::random(&mut rng);
        let r = Secp256K1ScalarField::random(&mut rng);
        let zero = Secp256K1ScalarField::zero();

        // Then
        assert_eq!(commit(&v, &zero), Secp256K1Group::generator() * v);
        assert_eq!(commit(&zero, &r), *PEDERSEN_H * r);
        assert_eq!(
            commit(&v, &r),
            Secp256K1Group::generator() * v + *PEDERSEN_H * r
        );
        assert_ne!(commit(&v, &r), commit(&v, &zero));
        assert_ne!(commit(&v, &r), commit(&zero, &r));
    }

    #[test]
    #[allow(non_snake_case)]
    fn commit_polynomial__should_match_pointwise_commitments() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let f = Polynomial::generate_polynomial(None, 3, &mut rng).unwrap();
        let r = Polynomial::generate_polynomial(Some(Secp256K1ScalarField::zero()), 3, &mut rng)
            .unwrap();

        // When
        let committed = commit_polynomial(&f, &r).unwrap();

        // Then
        assert_eq!(committed.degree(), 3);
        for id in [0u32, 1, 5, 17] {
            let participant = Participant::from(id);
            let expected = commit(
                &f.eval_at_participant(participant).unwrap().0,
                &r.eval_at_participant(participant).unwrap().0,
            );
            assert_eq!(
                committed.eval_at_participant(participant).unwrap().value(),
                expected
            );
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn commit_polynomial__should_reject_mismatched_degrees() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let f = Polynomial::generate_polynomial(None, 4, &mut rng).unwrap();
        let r = Polynomial::generate_polynomial(None, 2, &mut rng).unwrap();

        // When
        let result = commit_polynomial(&f, &r);

        // Then
        assert_matches!(result, Err(ProtocolError::InvalidInput(_)));
    }

    #[test]
    #[allow(non_snake_case)]
    fn verify_share__should_accept_valid_and_reject_invalid_openings() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let f = Polynomial::generate_polynomial(None, 3, &mut rng).unwrap();
        let r = Polynomial::generate_polynomial(None, 3, &mut rng).unwrap();
        let committed = commit_polynomial(&f, &r).unwrap();

        let participant = Participant::from(7u32);
        let value = f.eval_at_participant(participant).unwrap().0;
        let blinding = r.eval_at_participant(participant).unwrap().0;

        // Then
        assert!(verify_share(&committed, participant, &value, &blinding).unwrap());

        let one = Secp256K1ScalarField::one();
        assert!(!verify_share(&committed, participant, &(value + one), &blinding).unwrap());
        assert!(!verify_share(&committed, participant, &value, &(blinding + one)).unwrap());
        let other = Participant::from(8u32);
        assert!(!verify_share(&committed, other, &value, &blinding).unwrap());
    }
}
