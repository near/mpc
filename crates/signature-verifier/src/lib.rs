use contract_interface::types::{
    Ed25519PublicKey, Ed25519Signature, Hash256, K256Signature, Secp256k1PublicKey,
};

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum VerificationError {
    InvalidSignature,
    FailedToRecoverSignature,
    RecoveredPkDoesNotMatchExpectedKey,
}

pub fn check_ec_signature(
    signature: &K256Signature,
    message: &Hash256,
    public_key: &Secp256k1PublicKey,
) -> Result<(), VerificationError> {
    // Build the 64-byte (r || s) signature expected by ecrecover.
    // r is the x-coordinate from the compressed R point (bytes [1..33]).
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&signature.big_r.affine_point[1..]);
    sig_bytes[32..].copy_from_slice(&signature.s.scalar);

    // ecrecover with malleability_flag=true validates r < n and s < n/2,
    // then recovers the public key from the signature.
    let recovered = near_sdk::env::ecrecover(&message.0, &sig_bytes, signature.recovery_id, true)
        .ok_or(VerificationError::FailedToRecoverSignature)?;

    if recovered != public_key.0 {
        return Err(VerificationError::RecoveredPkDoesNotMatchExpectedKey);
    }
    Ok(())
}

pub fn check_ed_signature(
    signature: &Ed25519Signature,
    message: &Hash256,
    public_key: &Ed25519PublicKey,
) -> Result<(), VerificationError> {
    let is_valid_signature = near_sdk::env::ed25519_verify(signature, message.as_ref(), public_key);
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
        Ed25519Signature, Hash256, K256AffinePoint, K256Scalar, K256Signature, Secp256k1PublicKey,
    };
    use ed25519_dalek::Signer;

    fn make_ec_test_case(
        key_seed: u8,
        msg: [u8; 32],
    ) -> (K256Signature, Hash256, Secp256k1PublicKey) {
        let signing_key = k256::ecdsa::SigningKey::from_bytes(&[key_seed; 32].into()).unwrap();
        let (sig, recovery_id) = signing_key.sign_prehash_recoverable(&msg).unwrap();

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
        (signature, Hash256(msg), Secp256k1PublicKey(pk_bytes))
    }

    fn make_ed_test_case(
        key_seed: u8,
        msg: [u8; 32],
    ) -> (Ed25519Signature, Hash256, Ed25519PublicKey) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[key_seed; 32]);
        let sig: ed25519_dalek::Signature = signing_key.sign(&msg);
        let pk = signing_key.verifying_key();
        (
            Ed25519Signature::from(sig.to_bytes()),
            Hash256(msg),
            Ed25519PublicKey(pk.to_bytes()),
        )
    }

    #[test]
    fn ec_valid_signature() {
        // given
        let (sig, msg, pk) = make_ec_test_case(1, [42u8; 32]);

        // when
        let result = check_ec_signature(&sig, &msg, &pk);

        // then
        assert_matches!(result, Ok(()));
    }

    #[test]
    fn ec_wrong_message() {
        // given
        let (sig, _, pk) = make_ec_test_case(1, [42u8; 32]);
        let wrong_msg = Hash256([43u8; 32]);

        // when
        let result = check_ec_signature(&sig, &wrong_msg, &pk);

        // then
        assert_matches!(
            result,
            Err(VerificationError::RecoveredPkDoesNotMatchExpectedKey)
        );
    }

    #[test]
    fn ec_wrong_public_key() {
        // given
        let (sig, msg, _) = make_ec_test_case(1, [42u8; 32]);
        let (_, _, other_pk) = make_ec_test_case(2, [42u8; 32]);

        // when
        let result = check_ec_signature(&sig, &msg, &other_pk);

        // then
        assert_matches!(
            result,
            Err(VerificationError::RecoveredPkDoesNotMatchExpectedKey)
        );
    }

    #[test]
    fn ed_valid_signature() {
        // given
        let (sig, msg, pk) = make_ed_test_case(1, [42u8; 32]);

        // when
        let result = check_ed_signature(&sig, &msg, &pk);

        // then
        assert_matches!(result, Ok(()));
    }

    #[test]
    fn ed_wrong_message() {
        // given
        let (sig, _, pk) = make_ed_test_case(1, [42u8; 32]);
        let wrong_msg = Hash256([43u8; 32]);

        // when
        let result = check_ed_signature(&sig, &wrong_msg, &pk);

        // then
        assert_matches!(result, Err(VerificationError::InvalidSignature));
    }

    #[test]
    fn ed_wrong_public_key() {
        // given
        let (sig, msg, _) = make_ed_test_case(1, [42u8; 32]);
        let (_, _, other_pk) = make_ed_test_case(2, [42u8; 32]);

        // when
        let result = check_ed_signature(&sig, &msg, &other_pk);

        // then
        assert_matches!(result, Err(VerificationError::InvalidSignature));
    }

    #[test]
    fn ec_wrong_recovery_id() {
        // given
        let (mut sig, msg, pk) = make_ec_test_case(1, [42u8; 32]);
        sig.recovery_id ^= 1;

        // when
        let result = check_ec_signature(&sig, &msg, &pk);

        // then
        assert_matches!(
            result,
            Err(VerificationError::RecoveredPkDoesNotMatchExpectedKey)
        );
    }

    #[test]
    fn ec_tampered_s_scalar() {
        // given
        let (mut sig, msg, pk) = make_ec_test_case(1, [42u8; 32]);
        sig.s.scalar = [u8::MAX; 32]; // 0xFF..FF >= curve order n

        // when
        let result = check_ec_signature(&sig, &msg, &pk);

        // then — ecrecover rejects the out-of-range s value
        assert_matches!(result, Err(VerificationError::FailedToRecoverSignature));
    }

    #[test]
    fn ed_tampered_signature() {
        // given
        let (_, msg, pk) = make_ed_test_case(1, [42u8; 32]);
        let tampered_sig = Ed25519Signature::from([0u8; 64]);

        // when
        let result = check_ed_signature(&tampered_sig, &msg, &pk);

        // then
        assert_matches!(result, Err(VerificationError::InvalidSignature));
    }
}
