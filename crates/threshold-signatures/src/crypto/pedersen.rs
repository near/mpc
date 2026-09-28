//! Pedersen commitments over secp256k1.
//!
//! A commitment to a value `v` with blinding `r` is `Com(v; r) = v * G + r * H`,
//! where [`struct@PEDERSEN_H`] is a second generator with unknown discrete logarithm,
//! derived once by hashing a protocol-specific tag to the curve
//! ([RFC 9380](https://www.rfc-editor.org/rfc/rfc9380)) so that no party can know
//! its discrete logarithm.
//!
//! [`commit_polynomial`] extends `Com` coefficientwise to polynomials: for
//! `f(X) = Σ f_m X^m` and `r(X) = Σ r_m X^m`, the committed polynomial has
//! coefficients `Com(f_m; r_m)`. Since `Com` is linear,
//! `Com(f; r)(j) = Com(f(j); r(j))`, which is what [`verify_share`] checks.

use std::sync::LazyLock;

use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use frost_secp256k1::{Field, Group, Secp256K1Group, Secp256K1ScalarField};
use k256::Secp256k1;
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
    Secp256K1Group::generator() * *value + *PEDERSEN_H * *blinding
}

/// Commits to the polynomial `f` coefficientwise under the blinding polynomial `r`:
/// coefficient `m` of the result is `Com(f_m; r_m)`.
///
/// The two polynomials need not have the same degree; the shorter one is treated
/// as zero-padded, so trailing unblinded (or valueless) coefficients are allowed.
///
/// The caller is responsible for stripping a leading identity coefficient
/// (when `f` and `r` both have a zero constant term) before serialization.
pub fn commit_polynomial(
    f: &Polynomial,
    r: &Polynomial,
) -> Result<PolynomialCommitment, ProtocolError> {
    let f_coefficients = f.get_coefficients();
    let r_coefficients = r.get_coefficients();
    let zero = Secp256K1ScalarField::zero();

    let len = f_coefficients.len().max(r_coefficients.len());
    let mut commitments = Vec::with_capacity(len);
    for m in 0..len {
        let f_m = f_coefficients.get(m).unwrap_or(&zero);
        let r_m = r_coefficients.get(m).unwrap_or(&zero);
        commitments.push(CoefficientCommitment::new(commit(f_m, r_m)));
    }
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
    use rand::SeedableRng;

    #[test]
    fn test_pedersen_generator_is_valid() {
        let h = *PEDERSEN_H;
        assert!(bool::from(h.ct_ne(&Secp256K1Group::identity())));
        assert!(bool::from(h.ct_ne(&Secp256K1Group::generator())));

        // Pin the generator so any change to its derivation is caught.
        let ser = Secp256K1Group::serialize(&h).expect("H is not the identity");
        insta::assert_snapshot!(hex::encode(ser));
    }

    #[test]
    fn test_commit_is_binding_to_both_arguments() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let v = Secp256K1ScalarField::random(&mut rng);
        let r = Secp256K1ScalarField::random(&mut rng);
        let zero = Secp256K1ScalarField::zero();

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
    fn test_commit_polynomial_matches_pointwise_commitments() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let f = Polynomial::generate_polynomial(None, 3, &mut rng).unwrap();
        let r = Polynomial::generate_polynomial(Some(Secp256K1ScalarField::zero()), 3, &mut rng)
            .unwrap();

        let committed = commit_polynomial(&f, &r).unwrap();
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
    fn test_commit_polynomial_zero_pads_the_shorter_polynomial() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let f = Polynomial::generate_polynomial(None, 4, &mut rng).unwrap();
        let r = Polynomial::generate_polynomial(None, 2, &mut rng).unwrap();

        let committed = commit_polynomial(&f, &r).unwrap();
        assert_eq!(committed.degree(), 4);

        // the unblinded tail commits to the plain coefficients of f
        let f_coefficients = f.get_coefficients();
        let coefficients = committed.get_coefficients();
        for m in 3..=4 {
            assert_eq!(
                coefficients[m].value(),
                Secp256K1Group::generator() * f_coefficients[m]
            );
        }
    }

    #[test]
    fn test_verify_share_accepts_valid_and_rejects_invalid_openings() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let f = Polynomial::generate_polynomial(None, 3, &mut rng).unwrap();
        let r = Polynomial::generate_polynomial(None, 3, &mut rng).unwrap();
        let committed = commit_polynomial(&f, &r).unwrap();

        let participant = Participant::from(7u32);
        let value = f.eval_at_participant(participant).unwrap().0;
        let blinding = r.eval_at_participant(participant).unwrap().0;

        assert!(verify_share(&committed, participant, &value, &blinding).unwrap());

        let one = Secp256K1ScalarField::one();
        assert!(!verify_share(&committed, participant, &(value + one), &blinding).unwrap());
        assert!(!verify_share(&committed, participant, &value, &(blinding + one)).unwrap());
        let other = Participant::from(8u32);
        assert!(!verify_share(&committed, other, &value, &blinding).unwrap());
    }
}
