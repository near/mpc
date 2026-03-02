use super::CryptoConversionError;
use crate::types::crypto::Ed25519PublicKey;
use crate::types::primitives::Ed25519Signature;
use curve25519_dalek::edwards::CompressedEdwardsY;

impl From<CompressedEdwardsY> for Ed25519PublicKey {
    fn from(point: CompressedEdwardsY) -> Self {
        Ed25519PublicKey::from(point.to_bytes())
    }
}

impl From<&CompressedEdwardsY> for Ed25519PublicKey {
    fn from(point: &CompressedEdwardsY) -> Self {
        Ed25519PublicKey::from(point.to_bytes())
    }
}

impl From<ed25519_dalek::VerifyingKey> for Ed25519PublicKey {
    fn from(vk: ed25519_dalek::VerifyingKey) -> Self {
        Ed25519PublicKey::from(vk.to_bytes())
    }
}

impl From<&ed25519_dalek::VerifyingKey> for Ed25519PublicKey {
    fn from(vk: &ed25519_dalek::VerifyingKey) -> Self {
        Ed25519PublicKey::from(vk.to_bytes())
    }
}

impl TryFrom<Ed25519PublicKey> for ed25519_dalek::VerifyingKey {
    type Error = CryptoConversionError;
    fn try_from(dto: Ed25519PublicKey) -> Result<Self, Self::Error> {
        ed25519_dalek::VerifyingKey::from_bytes(dto.as_bytes())
            .map_err(|_| CryptoConversionError::InvalidPublicKey)
    }
}

impl TryFrom<&Ed25519PublicKey> for ed25519_dalek::VerifyingKey {
    type Error = CryptoConversionError;
    fn try_from(dto: &Ed25519PublicKey) -> Result<Self, Self::Error> {
        ed25519_dalek::VerifyingKey::from_bytes(dto.as_bytes())
            .map_err(|_| CryptoConversionError::InvalidPublicKey)
    }
}

impl From<ed25519_dalek::Signature> for Ed25519Signature {
    fn from(sig: ed25519_dalek::Signature) -> Self {
        Ed25519Signature::from(sig.to_bytes())
    }
}

impl From<Ed25519Signature> for ed25519_dalek::Signature {
    fn from(dto: Ed25519Signature) -> Self {
        ed25519_dalek::Signature::from_bytes(&dto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    fn roundtrip_verifying_key() {
        // given
        let vk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]).verifying_key();

        // when
        let dto = Ed25519PublicKey::from(vk);
        let recovered = ed25519_dalek::VerifyingKey::try_from(dto).unwrap();

        // then
        assert_eq!(vk, recovered);
    }

    #[test]
    fn roundtrip_verifying_key_via_ref() {
        // given
        let vk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]).verifying_key();

        // when
        let dto = Ed25519PublicKey::from(&vk);
        let recovered = ed25519_dalek::VerifyingKey::try_from(&dto).unwrap();

        // then
        assert_eq!(vk, recovered);
    }

    #[test]
    fn invalid_verifying_key_bytes_are_rejected() {
        // given: y=2 does not decompress to a valid curve point
        let mut bytes = [0u8; 32];
        bytes[0] = 2;
        let dto = Ed25519PublicKey::from(bytes);

        // when
        let result = ed25519_dalek::VerifyingKey::try_from(dto);

        // then
        assert!(matches!(
            result,
            Err(CryptoConversionError::InvalidPublicKey)
        ));
    }

    #[test]
    fn compressed_edwards_y_to_ed25519_public_key() {
        // given
        let vk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]).verifying_key();
        let compressed = curve25519_dalek::edwards::CompressedEdwardsY(vk.to_bytes());

        // when
        let dto = Ed25519PublicKey::from(compressed);

        // then
        assert_eq!(dto.as_bytes(), &vk.to_bytes());
    }

    #[test]
    fn compressed_edwards_y_to_ed25519_public_key_via_ref() {
        // given
        let vk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]).verifying_key();
        let compressed = curve25519_dalek::edwards::CompressedEdwardsY(vk.to_bytes());

        // when
        let dto = Ed25519PublicKey::from(&compressed);

        // then
        assert_eq!(dto.as_bytes(), &vk.to_bytes());
    }

    #[test]
    fn roundtrip_signature() {
        // given
        let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let sig = sk.sign(b"test message");

        // when
        let dto = Ed25519Signature::from(sig);
        let recovered = ed25519_dalek::Signature::from(dto);

        // then
        assert_eq!(sig, recovered);
    }
}
