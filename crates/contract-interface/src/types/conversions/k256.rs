use k256::elliptic_curve::{
    PrimeField as _,
    group::GroupEncoding as _,
    sec1::{FromEncodedPoint as _, ToEncodedPoint as _},
};

use super::CryptoConversionError;
use crate::types::crypto::Secp256k1PublicKey;
use crate::types::primitives::{K256AffinePoint, K256Scalar, K256Signature};

impl From<k256::AffinePoint> for K256AffinePoint {
    fn from(point: k256::AffinePoint) -> Self {
        let bytes: [u8; 33] = point
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed encoded point is always 33 bytes");
        K256AffinePoint {
            affine_point: bytes,
        }
    }
}

impl TryFrom<K256AffinePoint> for k256::AffinePoint {
    type Error = CryptoConversionError;
    fn try_from(dto: K256AffinePoint) -> Result<Self, Self::Error> {
        k256::AffinePoint::from_bytes(&dto.affine_point.into())
            .into_option()
            .ok_or(CryptoConversionError::InvalidPoint)
    }
}

impl From<k256::Scalar> for K256Scalar {
    fn from(scalar: k256::Scalar) -> Self {
        K256Scalar {
            scalar: scalar.to_bytes().into(),
        }
    }
}

impl TryFrom<K256Scalar> for k256::Scalar {
    type Error = CryptoConversionError;
    fn try_from(dto: K256Scalar) -> Result<Self, Self::Error> {
        k256::Scalar::from_repr(dto.scalar.into())
            .into_option()
            .ok_or(CryptoConversionError::InvalidScalar)
    }
}

impl TryFrom<k256::AffinePoint> for Secp256k1PublicKey {
    type Error = CryptoConversionError;
    fn try_from(point: k256::AffinePoint) -> Result<Self, Self::Error> {
        let pk =
            k256::PublicKey::from_affine(point).map_err(|_| CryptoConversionError::InvalidPoint)?;
        Ok(Secp256k1PublicKey::from(pk))
    }
}

impl TryFrom<&k256::AffinePoint> for Secp256k1PublicKey {
    type Error = CryptoConversionError;
    fn try_from(point: &k256::AffinePoint) -> Result<Self, Self::Error> {
        Secp256k1PublicKey::try_from(*point)
    }
}

impl From<k256::PublicKey> for Secp256k1PublicKey {
    fn from(pk: k256::PublicKey) -> Self {
        let mut bytes = [0u8; 64];
        // Uncompressed encoded point is 65 bytes (0x04 prefix + 64 bytes)
        bytes.copy_from_slice(&pk.to_encoded_point(false).to_bytes()[1..]);
        Secp256k1PublicKey::from(bytes)
    }
}

impl TryFrom<Secp256k1PublicKey> for k256::PublicKey {
    type Error = CryptoConversionError;
    fn try_from(dto: Secp256k1PublicKey) -> Result<Self, Self::Error> {
        let mut bytes = [0u8; 65];
        bytes[0] = 0x04; // uncompressed prefix
        bytes[1..].copy_from_slice(&dto.0);
        let point = k256::EncodedPoint::from_bytes(bytes)
            .map_err(|_| CryptoConversionError::InvalidPublicKey)?;
        k256::PublicKey::from_encoded_point(&point)
            .into_option()
            .ok_or(CryptoConversionError::InvalidPublicKey)
    }
}

impl From<&k256::PublicKey> for Secp256k1PublicKey {
    fn from(pk: &k256::PublicKey) -> Self {
        Secp256k1PublicKey::from(*pk)
    }
}

impl TryFrom<&Secp256k1PublicKey> for k256::PublicKey {
    type Error = CryptoConversionError;
    fn try_from(dto: &Secp256k1PublicKey) -> Result<Self, Self::Error> {
        k256::PublicKey::try_from(dto.clone())
    }
}

impl TryFrom<&K256Signature> for k256::ecdsa::Signature {
    type Error = CryptoConversionError;
    fn try_from(dto: &K256Signature) -> Result<Self, Self::Error> {
        // r is the x-coordinate from the compressed R point (bytes [1..33])
        let r = k256::FieldBytes::from_slice(&dto.big_r.affine_point[1..]);
        let s = k256::FieldBytes::from_slice(&dto.s.scalar);
        k256::ecdsa::Signature::from_scalars(*r, *s)
            .map_err(|_| CryptoConversionError::InvalidSignature)
    }
}

impl TryFrom<K256Signature> for k256::ecdsa::Signature {
    type Error = CryptoConversionError;
    fn try_from(dto: K256Signature) -> Result<Self, Self::Error> {
        k256::ecdsa::Signature::try_from(&dto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::elliptic_curve::Field;
    use k256::elliptic_curve::rand_core::OsRng;

    #[test]
    fn roundtrip_affine_point() {
        // given
        let point = *k256::SecretKey::random(&mut OsRng).public_key().as_affine();

        // when
        let dto = K256AffinePoint::from(point);
        let recovered = k256::AffinePoint::try_from(dto).unwrap();

        // then
        assert_eq!(point, recovered);
    }

    #[test]
    fn invalid_affine_point_bytes_are_rejected() {
        // given
        let dto = K256AffinePoint {
            affine_point: [0xff; 33],
        };

        // when
        let result = k256::AffinePoint::try_from(dto);

        // then
        assert!(matches!(result, Err(CryptoConversionError::InvalidPoint)));
    }

    #[test]
    fn roundtrip_scalar() {
        // given
        let scalar = k256::Scalar::random(&mut OsRng);

        // when
        let dto = K256Scalar::from(scalar);
        let recovered = k256::Scalar::try_from(dto).unwrap();

        // then
        assert_eq!(scalar, recovered);
    }

    #[test]
    fn roundtrip_public_key() {
        // given
        let pk = k256::SecretKey::random(&mut OsRng).public_key();

        // when
        let dto = Secp256k1PublicKey::from(pk);
        let recovered = k256::PublicKey::try_from(dto).unwrap();

        // then
        assert_eq!(pk, recovered);
    }

    #[test]
    fn roundtrip_public_key_via_ref() {
        // given
        let pk = k256::SecretKey::random(&mut OsRng).public_key();

        // when
        let dto = Secp256k1PublicKey::from(&pk);
        let recovered = k256::PublicKey::try_from(&dto).unwrap();

        // then
        assert_eq!(pk, recovered);
    }

    #[test]
    fn invalid_public_key_bytes_are_rejected() {
        // given
        let dto = Secp256k1PublicKey::from([0xff; 64]);

        // when
        let result = k256::PublicKey::try_from(dto);

        // then
        assert!(matches!(
            result,
            Err(CryptoConversionError::InvalidPublicKey)
        ));
    }

    #[test]
    fn k256_signature_to_ecdsa_signature() {
        // given
        let signing_key = SigningKey::random(&mut OsRng);
        let (sig, _recovery_id): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
            signing_key.sign_prehash(&[42u8; 32]).unwrap();
        let r_bytes = sig.r().to_bytes();
        let mut affine_point = [0u8; 33];
        affine_point[0] = 0x02;
        affine_point[1..].copy_from_slice(&r_bytes);
        let dto = K256Signature {
            big_r: K256AffinePoint { affine_point },
            s: K256Scalar {
                scalar: sig.s().to_bytes().into(),
            },
            recovery_id: 0,
        };

        // when
        let recovered_sig = k256::ecdsa::Signature::try_from(&dto).unwrap();

        // then
        assert_eq!(sig, recovered_sig);
    }
}
