//! Wycheproof test-vector coverage for the consumer-facing signature verifiers.
//!
//! EdDSA vectors map directly onto [`verify_eddsa_signature`]. ECDSA vectors are
//! DER-encoded `(r, s)` with no recovery id, and many `Valid` vectors carry a
//! high-S signature; our verifier recovers the key and enforces low-S, so ECDSA
//! results are mapped rather than compared one-to-one:
//!   * `Invalid`        -> must be rejected for every candidate recovery id,
//!   * `Valid` + low-S  -> must be accepted,
//!   * `Valid` + high-S -> must be rejected, but accepted once `s` is normalized.
//!
//! `Acceptable` vectors are spec-optional and left unasserted.

#![allow(non_snake_case)]

use k256::ecdsa::{RecoveryId, Signature as K256EcdsaSignature};
use near_mpc_contract_interface::types::{
    Ed25519PublicKey, Ed25519Signature, K256Signature, Secp256k1PublicKey,
};
use near_mpc_signature_verifier::{verify_ecdsa_signature, verify_eddsa_signature};
use sha2::{Digest, Sha256};
use wycheproof::TestResult;

#[test]
fn verify_eddsa_signature__should_match_all_wycheproof_ed25519_vectors() {
    // Given
    let test_set = wycheproof::eddsa::TestSet::load(wycheproof::eddsa::TestName::Ed25519)
        .expect("wycheproof ed25519 vectors should load");

    // When / Then
    let mut checked = 0usize;
    for group in test_set.test_groups {
        let pk_bytes =
            <[u8; 32]>::try_from(group.key.pk.as_ref()).expect("ed25519 public key is 32 bytes");
        let public_key = Ed25519PublicKey(pk_bytes);

        for test in group.tests {
            let Ok(sig_bytes) = <[u8; 64]>::try_from(test.sig.as_ref()) else {
                // A signature that is not 64 bytes can never be valid.
                assert_ne!(test.result, TestResult::Valid, "tc{}", test.tc_id);
                continue;
            };
            let signature = Ed25519Signature::from(sig_bytes);

            let result = verify_eddsa_signature(&signature, test.msg.as_ref(), &public_key);

            match test.result {
                TestResult::Valid => {
                    assert!(
                        result.is_ok(),
                        "tc{}: valid vector rejected: {result:?}",
                        test.tc_id
                    );
                    checked += 1;
                }
                TestResult::Invalid => {
                    assert!(result.is_err(), "tc{}: invalid vector accepted", test.tc_id);
                    checked += 1;
                }
                TestResult::Acceptable => {}
            }
        }
    }
    assert!(checked > 0, "no ed25519 vectors were exercised");
}

#[test]
fn verify_ecdsa_signature__should_reject_all_wycheproof_invalid_vectors() {
    // Given
    let test_set = load_ecdsa_secp256k1_sha256();

    // When / Then
    let mut checked = 0usize;
    for group in test_set.test_groups {
        for test in group.tests {
            if test.result != TestResult::Invalid {
                continue;
            }
            // Unparseable key/signature is itself a rejection.
            let accepted =
                parse_ecdsa(group.key.key.as_ref(), test.msg.as_ref(), test.sig.as_ref())
                    .is_some_and(|(public_key, digest, sig)| {
                        recover_model_accepts(&public_key, &digest, &sig)
                    });
            assert!(!accepted, "tc{}: invalid vector was accepted", test.tc_id);
            checked += 1;
        }
    }
    assert!(checked > 0, "no invalid vectors were exercised");
}

#[test]
fn verify_ecdsa_signature__should_accept_wycheproof_valid_low_s_vectors() {
    // Given
    let test_set = load_ecdsa_secp256k1_sha256();

    // When / Then
    let mut checked = 0usize;
    for group in test_set.test_groups {
        for test in group.tests {
            if test.result != TestResult::Valid {
                continue;
            }
            let (public_key, digest, sig) =
                parse_ecdsa(group.key.key.as_ref(), test.msg.as_ref(), test.sig.as_ref())
                    .expect("valid vector should parse");
            // High-S valid vectors are covered by the normalization test.
            if sig.normalize_s().is_some() {
                continue;
            }
            assert!(
                recover_model_accepts(&public_key, &digest, &sig),
                "tc{}: valid low-S vector rejected",
                test.tc_id
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "no valid low-S vectors were exercised");
}

/// A high-S signature is the malleated form of a valid one: our verifier must
/// reject it, and accept the same signature once `s` is normalized to low-S.
/// This proves the rejection is the malleability policy, not a verification bug.
#[test]
fn verify_ecdsa_signature__should_reject_high_s_but_accept_after_normalization() {
    // Given
    let test_set = load_ecdsa_secp256k1_sha256();

    // When / Then
    let mut checked = 0usize;
    for group in test_set.test_groups {
        for test in group.tests {
            if test.result != TestResult::Valid {
                continue;
            }
            let (public_key, digest, sig) =
                parse_ecdsa(group.key.key.as_ref(), test.msg.as_ref(), test.sig.as_ref())
                    .expect("valid vector should parse");
            let Some(normalized) = sig.normalize_s() else {
                continue;
            };

            assert!(
                !recover_model_accepts(&public_key, &digest, &sig),
                "tc{}: malleable high-S vector was accepted",
                test.tc_id
            );
            assert!(
                recover_model_accepts(&public_key, &digest, &normalized),
                "tc{}: normalized low-S vector was rejected",
                test.tc_id
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "no high-S valid vectors were exercised");
}

fn load_ecdsa_secp256k1_sha256() -> wycheproof::ecdsa::TestSet {
    wycheproof::ecdsa::TestSet::load(wycheproof::ecdsa::TestName::EcdsaSecp256k1Sha256)
        .expect("wycheproof secp256k1/sha256 vectors should load")
}

/// Parses a Wycheproof ECDSA case into our verifier's inputs.
///
/// `key` is the uncompressed SEC1 point (`0x04 || x || y`); the signature is DER.
/// Returns `None` when the key or signature encoding is malformed.
fn parse_ecdsa(
    key: &[u8],
    msg: &[u8],
    der_sig: &[u8],
) -> Option<(Secp256k1PublicKey, [u8; 32], K256EcdsaSignature)> {
    let uncompressed = <[u8; 64]>::try_from(key.get(1..)?).ok()?;
    let public_key = Secp256k1PublicKey(uncompressed);
    let digest: [u8; 32] = Sha256::digest(msg).into();
    let sig = K256EcdsaSignature::from_der(der_sig).ok()?;
    Some((public_key, digest, sig))
}

/// Returns whether `verify_ecdsa_signature` accepts the signature under any
/// candidate recovery id (the recovery id is absent from Wycheproof vectors).
fn recover_model_accepts(
    public_key: &Secp256k1PublicKey,
    digest: &[u8; 32],
    sig: &K256EcdsaSignature,
) -> bool {
    (0u8..=3).any(|byte| {
        let Some(recovery_id) = RecoveryId::from_byte(byte) else {
            return false;
        };
        let dto = K256Signature::from_ecdsa_recoverable(sig, recovery_id);
        verify_ecdsa_signature(&dto, digest, public_key).is_ok()
    })
}
