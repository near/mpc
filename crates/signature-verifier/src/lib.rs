use contract_interface::types::{
    Ed25519PublicKey, Ed25519Signature, K256Signature, Secp256k1PublicKey,
};

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum VerificationError {
    InvalidSignature,
    FailedToRecoverSignature,
    RecoveredPkDoesNotMatchExpectedKey,
}

pub fn verify_ecdsa_signature(
    signature: &K256Signature,
    message: &[u8; 32],
    public_key: &Secp256k1PublicKey,
) -> Result<(), VerificationError> {
    // Build the 64-byte (r || s) signature expected by ecrecover.
    // r is the x-coordinate from the compressed R point (bytes [1..33]).
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&signature.big_r.affine_point[1..]);
    sig_bytes[32..].copy_from_slice(&signature.s.scalar);

    // ecrecover with malleability_flag=true validates r < n and s < n/2,
    // then recovers the public key from the signature.
    let recovered = near_sdk::env::ecrecover(message, &sig_bytes, signature.recovery_id, true)
        .ok_or(VerificationError::FailedToRecoverSignature)?;

    if recovered != public_key.0 {
        return Err(VerificationError::RecoveredPkDoesNotMatchExpectedKey);
    }
    Ok(())
}

pub fn verify_eddsa_signature(
    signature: &Ed25519Signature,
    message: &[u8],
    public_key: &Ed25519PublicKey,
) -> Result<(), VerificationError> {
    let is_valid_signature = near_sdk::env::ed25519_verify(signature, message, public_key);
    if is_valid_signature {
        Ok(())
    } else {
        Err(VerificationError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use contract_interface::types::{
        Ed25519Signature, K256AffinePoint, K256Scalar, K256Signature, Secp256k1PublicKey,
    };
    use ed25519_dalek::Signer;
    use rand::{Rng, SeedableRng};

    fn make_ecdsa_test_case(
        key_seed: u64,
        message_digest: &[u8; 32],
    ) -> (K256Signature, Secp256k1PublicKey) {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(key_seed);
        let key_bytes: [u8; 32] = rng.r#gen();
        let signing_key = k256::ecdsa::SigningKey::from_bytes(&key_bytes.into())
            .expect("random 32 bytes should be a valid secp256k1 scalar");
        let (sig, recovery_id) = signing_key
            .sign_prehash_recoverable(message_digest)
            .unwrap();

        let prefix = if recovery_id.is_y_odd() {
            0x03u8
        } else {
            0x02u8
        };
        let mut big_r_bytes = [0u8; 33];
        big_r_bytes[0] = prefix;
        big_r_bytes[1..].copy_from_slice(&sig.r().to_bytes());

        let pk_uncompressed = signing_key.verifying_key().to_encoded_point(false);
        let pk_bytes: [u8; 64] = pk_uncompressed.as_bytes()[1..].try_into().unwrap();

        let signature = K256Signature {
            big_r: K256AffinePoint {
                affine_point: big_r_bytes,
            },
            s: K256Scalar {
                scalar: sig.s().to_bytes().into(),
            },
            recovery_id: recovery_id.to_byte(),
        };
        (signature, Secp256k1PublicKey(pk_bytes))
    }

    fn make_eddsa_test_case(
        key_seed: u64,
        message: &[u8; 32],
    ) -> (Ed25519Signature, Ed25519PublicKey) {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(key_seed);
        let key_bytes: [u8; 32] = rng.r#gen();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
        let sig: ed25519_dalek::Signature = signing_key.sign(message);
        let pk = signing_key.verifying_key();
        (
            Ed25519Signature::from(sig.to_bytes()),
            Ed25519PublicKey(pk.to_bytes()),
        )
    }

    fn make_message(seed: u64) -> [u8; 32] {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
        rng.r#gen()
    }

    #[test]
    fn ecdsa_valid_signature() {
        // given
        let msg = [42u8; 32];
        let (sig, pk) = make_ecdsa_test_case(1, &msg);

        // when
        let result = verify_ecdsa_signature(&sig, &msg, &pk);

        // then
        assert_matches!(result, Ok(()));
    }

    #[test]
    fn ecdsa_wrong_message() {
        // given
        let msg = [42u8; 32];
        let (sig, pk) = make_ecdsa_test_case(1, &msg);
        let wrong_msg = [43u8; 32];

        // when
        let result = verify_ecdsa_signature(&sig, &wrong_msg, &pk);

        // then
        assert_matches!(
            result,
            Err(VerificationError::RecoveredPkDoesNotMatchExpectedKey)
        );
    }

    #[test]
    fn ecdsa_wrong_public_key() {
        // given
        let msg = [42u8; 32];
        let (sig, _) = make_ecdsa_test_case(1, &msg);
        let (_, other_pk) = make_ecdsa_test_case(2, &msg);

        // when
        let result = verify_ecdsa_signature(&sig, &msg, &other_pk);

        // then
        assert_matches!(
            result,
            Err(VerificationError::RecoveredPkDoesNotMatchExpectedKey)
        );
    }

    #[test]
    fn eddsa_valid_signature() {
        // given
        let msg = [42u8; 32];
        let (sig, pk) = make_eddsa_test_case(1, &msg);

        // when
        let result = verify_eddsa_signature(&sig, &msg, &pk);

        // then
        assert_matches!(result, Ok(()));
    }

    #[test]
    fn eddsa_wrong_message() {
        // given
        let msg = [42u8; 32];
        let (sig, pk) = make_eddsa_test_case(1, &msg);
        let wrong_msg = [43u8; 32];

        // when
        let result = verify_eddsa_signature(&sig, &wrong_msg, &pk);

        // then
        assert_matches!(result, Err(VerificationError::InvalidSignature));
    }

    #[test]
    fn eddsa_wrong_public_key() {
        // given
        let msg = [42u8; 32];
        let (sig, _) = make_eddsa_test_case(1, &msg);
        let (_, other_pk) = make_eddsa_test_case(2, &msg);

        // when
        let result = verify_eddsa_signature(&sig, &msg, &other_pk);

        // then
        assert_matches!(result, Err(VerificationError::InvalidSignature));
    }

    #[test]
    fn ecdsa_wrong_recovery_id() {
        // given
        let msg = [42u8; 32];
        let (mut sig, pk) = make_ecdsa_test_case(1, &msg);
        sig.recovery_id ^= 1;

        // when
        let result = verify_ecdsa_signature(&sig, &msg, &pk);

        // then
        assert_matches!(
            result,
            Err(VerificationError::RecoveredPkDoesNotMatchExpectedKey)
        );
    }

    #[test]
    fn ecdsa_tampereddsa_s_scalar() {
        // given
        let msg = [42u8; 32];
        let (mut sig, pk) = make_ecdsa_test_case(1, &msg);
        sig.s.scalar = [u8::MAX; 32]; // 0xFF..FF >= curve order n

        // when
        let result = verify_ecdsa_signature(&sig, &msg, &pk);

        // then — ecrecover rejects the out-of-range s value
        assert_matches!(result, Err(VerificationError::FailedToRecoverSignature));
    }

    #[test]
    fn eddsa_tampereddsa_signature() {
        // given
        let msg = [42u8; 32];
        let (_, pk) = make_eddsa_test_case(1, &msg);
        let tampereddsa_sig = Ed25519Signature::from([0u8; 64]);

        // when
        let result = verify_eddsa_signature(&tampereddsa_sig, &msg, &pk);

        // then
        assert_matches!(result, Err(VerificationError::InvalidSignature));
    }

    #[test]
    fn ecdsa_stress_many_keys_and_messages() {
        // Sweep over 16 key seeds × 8 messages = 128 combinations.
        // Kept smaller than EdDSA because ecrecover is expensive in the NEAR mock VM.
        for key_seed in 0u64..16 {
            for msg_seed in 0u64..8 {
                let msg = make_message(msg_seed);
                let (sig, pk) = make_ecdsa_test_case(key_seed, &msg);

                let result = verify_ecdsa_signature(&sig, &msg, &pk);
                assert!(
                    result.is_ok(),
                    "ECDSA verification failed for key_seed={key_seed}, msg_seed={msg_seed}: {result:?}",
                );
            }
        }
    }

    #[test]
    fn eddsa_stress_many_keys_and_messages() {
        for key_seed in 0u64..64 {
            for msg_seed in 0u64..16 {
                let msg = make_message(msg_seed);
                let (sig, pk) = make_eddsa_test_case(key_seed, &msg);

                let result = verify_eddsa_signature(&sig, &msg, &pk);
                assert!(
                    result.is_ok(),
                    "EdDSA verification failed for key_seed={key_seed}, msg_seed={msg_seed}: {result:?}",
                );
            }
        }
    }
}
