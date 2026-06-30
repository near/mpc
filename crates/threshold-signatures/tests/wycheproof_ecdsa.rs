//! Wycheproof secp256k1/SHA-256 coverage for our in-house ECDSA verification
//! equation, [`threshold_signatures::ecdsa::Signature::verify`] (used in
//! production to check assembled signatures before they are returned).
//!
//! `verify` operates on the full `R` point, but Wycheproof signatures only carry
//! the scalar `r`. We reconstruct a point whose x-coordinate is `r` (its
//! y-coordinate is irrelevant, since `verify` only reads `x_coordinate(big_r)`), then
//! map results, mirroring the malleability policy `verify` enforces (rejects
//! high-S, `r = 0`, `s = 0`):
//!   * `Invalid`        -> rejected,
//!   * `Valid` + low-S  -> accepted,
//!   * `Valid` + high-S -> rejected, accepted once `s` is normalized.
//!
//! `Acceptable` vectors are spec-optional and left unasserted.

#![allow(non_snake_case)]

use elliptic_curve::ops::Reduce;
use elliptic_curve::scalar::IsHigh;
use elliptic_curve::sec1::FromEncodedPoint;
use k256::ecdsa::Signature as K256EcdsaSignature;
use k256::{AffinePoint, EncodedPoint, PublicKey, Secp256k1};
use sha2::{Digest, Sha256};
use threshold_signatures::ecdsa::{Scalar, Signature};
use wycheproof::{
    TestResult,
    ecdsa::{TestName, TestSet},
};

#[test]
fn signature_verify__should_reject_all_wycheproof_invalid_vectors() {
    // Given
    let test_set = load();

    // When / Then
    let mut checked = 0usize;
    for group in test_set.test_groups {
        for test in group.tests {
            if test.result != TestResult::Invalid {
                continue;
            }
            let accepted = parse(group.key.key.as_ref(), test.msg.as_ref(), test.sig.as_ref())
                .and_then(|(public_key, z, sig)| {
                    lift_r(&sig)
                        .map(|big_r| Signature { big_r, s: *sig.s() }.verify(&public_key, &z))
                })
                .unwrap_or(false);
            assert!(!accepted, "tc{}: invalid vector was accepted", test.tc_id);
            checked += 1;
        }
    }
    assert!(checked > 0, "no invalid vectors were exercised");
}

#[test]
fn signature_verify__should_accept_wycheproof_valid_low_s_vectors() {
    // Given
    let test_set = load();

    // When / Then
    let mut checked = 0usize;
    for group in test_set.test_groups {
        for test in group.tests {
            if test.result != TestResult::Valid {
                continue;
            }
            let (public_key, z, sig) =
                parse(group.key.key.as_ref(), test.msg.as_ref(), test.sig.as_ref())
                    .expect("valid vector should parse");
            if sig.normalize_s().is_some() {
                continue; // high-S: covered by the normalization test
            }
            let Some(big_r) = lift_r(&sig) else {
                // R.x >= n cannot be reconstructed from r alone; vanishingly rare
                // and absent from the standard valid set.
                continue;
            };

            let signature = Signature { big_r, s: *sig.s() };
            assert!(
                signature.verify(&public_key, &z),
                "tc{}: valid low-S rejected",
                test.tc_id
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "no valid low-S vectors were exercised");
}

/// A high-S signature is the malleated form of a valid one: `verify` must reject
/// it and accept the same signature once `s` is normalized to low-S, proving the
/// rejection is the malleability policy rather than a verification bug.
#[test]
fn signature_verify__should_reject_high_s_but_accept_after_normalization() {
    // Given
    let test_set = load();

    // When / Then
    let mut checked = 0usize;
    for group in test_set.test_groups {
        for test in group.tests {
            if test.result != TestResult::Valid {
                continue;
            }
            let (public_key, z, sig) =
                parse(group.key.key.as_ref(), test.msg.as_ref(), test.sig.as_ref())
                    .expect("valid vector should parse");
            if sig.normalize_s().is_none() {
                continue; // already low-S: covered by the acceptance test
            }
            let Some(big_r) = lift_r(&sig) else {
                continue;
            };

            let high_s = *sig.s();
            assert!(
                !Signature { big_r, s: high_s }.verify(&public_key, &z),
                "tc{}: malleable high-S vector was accepted",
                test.tc_id
            );
            // Negating a high-S scalar yields its low-S (n - s) equivalent.
            let low_s = -high_s;
            assert!(
                !bool::from(low_s.is_high()),
                "tc{}: negated s is still high",
                test.tc_id
            );
            assert!(
                Signature { big_r, s: low_s }.verify(&public_key, &z),
                "tc{}: normalized low-S vector was rejected",
                test.tc_id
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "no high-S valid vectors were exercised");
}

fn load() -> TestSet {
    TestSet::load(TestName::EcdsaSecp256k1Sha256)
        .expect("wycheproof secp256k1/sha256 vectors should load")
}

/// Parses a Wycheproof ECDSA case into `(public key, message-hash scalar, signature)`.
///
/// `key` is the uncompressed SEC1 point; the signature is DER. Returns `None`
/// when either encoding is malformed.
fn parse(
    key: &[u8],
    msg: &[u8],
    der_sig: &[u8],
) -> Option<(AffinePoint, Scalar, K256EcdsaSignature)> {
    let public_key = *PublicKey::from_sec1_bytes(key).ok()?.as_affine();
    let hash = Sha256::digest(msg);
    let z = <Scalar as Reduce<<Secp256k1 as elliptic_curve::Curve>::Uint>>::reduce_bytes(&hash);
    let sig = K256EcdsaSignature::from_der(der_sig).ok()?;
    Some((public_key, z, sig))
}

/// Reconstructs a curve point whose x-coordinate is the signature's `r`.
///
/// `verify` only reads `x_coordinate(big_r)`, so the y-parity is irrelevant. Returns
/// `None` when `r` is not a valid x-coordinate (the rare `R.x >= n` case).
fn lift_r(sig: &K256EcdsaSignature) -> Option<AffinePoint> {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(sig.r().to_bytes().as_slice());
    let encoded = EncodedPoint::from_bytes(compressed).ok()?;
    Option::from(AffinePoint::from_encoded_point(&encoded))
}
