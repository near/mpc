use crate::crypto::Ed25519PublicKey;
use curve25519_dalek::edwards::CompressedEdwardsY;

impl From<CompressedEdwardsY> for Ed25519PublicKey {
    fn from(point: CompressedEdwardsY) -> Self {
        Ed25519PublicKey::from(point.to_bytes())
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_POINT};

    #[test]
    fn ed25519_public_key_from_compressed_edwards_y__should_keep_the_compressed_bytes() {
        // Given
        let compressed = (ED25519_BASEPOINT_POINT * Scalar::from(42u64)).compress();

        // When
        let dto = Ed25519PublicKey::from(compressed);

        // Then
        assert_eq!(dto.as_bytes(), compressed.as_bytes());
    }
}
