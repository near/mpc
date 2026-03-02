use super::CryptoConversionError;
use crate::types::crypto::{Bls12381G1PublicKey, Bls12381G2PublicKey};

impl From<blstrs::G1Projective> for Bls12381G1PublicKey {
    fn from(point: blstrs::G1Projective) -> Self {
        Bls12381G1PublicKey::from(point.to_compressed())
    }
}

impl From<&blstrs::G1Projective> for Bls12381G1PublicKey {
    fn from(point: &blstrs::G1Projective) -> Self {
        Bls12381G1PublicKey::from(point.to_compressed())
    }
}

impl TryFrom<Bls12381G1PublicKey> for blstrs::G1Projective {
    type Error = CryptoConversionError;
    fn try_from(dto: Bls12381G1PublicKey) -> Result<Self, Self::Error> {
        blstrs::G1Projective::from_compressed(&dto.0)
            .into_option()
            .ok_or(CryptoConversionError::InvalidPoint)
    }
}

impl TryFrom<&Bls12381G1PublicKey> for blstrs::G1Projective {
    type Error = CryptoConversionError;
    fn try_from(dto: &Bls12381G1PublicKey) -> Result<Self, Self::Error> {
        blstrs::G1Projective::from_compressed(&dto.0)
            .into_option()
            .ok_or(CryptoConversionError::InvalidPoint)
    }
}

impl From<blstrs::G2Projective> for Bls12381G2PublicKey {
    fn from(point: blstrs::G2Projective) -> Self {
        Bls12381G2PublicKey::from(point.to_compressed())
    }
}

impl From<&blstrs::G2Projective> for Bls12381G2PublicKey {
    fn from(point: &blstrs::G2Projective) -> Self {
        Bls12381G2PublicKey::from(point.to_compressed())
    }
}

impl TryFrom<Bls12381G2PublicKey> for blstrs::G2Projective {
    type Error = CryptoConversionError;
    fn try_from(dto: Bls12381G2PublicKey) -> Result<Self, Self::Error> {
        blstrs::G2Projective::from_compressed(&dto.0)
            .into_option()
            .ok_or(CryptoConversionError::InvalidPoint)
    }
}

impl TryFrom<&Bls12381G2PublicKey> for blstrs::G2Projective {
    type Error = CryptoConversionError;
    fn try_from(dto: &Bls12381G2PublicKey) -> Result<Self, Self::Error> {
        blstrs::G2Projective::from_compressed(&dto.0)
            .into_option()
            .ok_or(CryptoConversionError::InvalidPoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::Group;

    #[test]
    fn roundtrip_g1_projective() {
        // given
        let point = blstrs::G1Projective::generator() * blstrs::Scalar::from(42u64);

        // when
        let dto = Bls12381G1PublicKey::from(point);
        let recovered = blstrs::G1Projective::try_from(dto).unwrap();

        // then
        assert_eq!(point, recovered);
    }

    #[test]
    fn roundtrip_g1_projective_via_ref() {
        // given
        let point = blstrs::G1Projective::generator() * blstrs::Scalar::from(42u64);

        // when
        let dto = Bls12381G1PublicKey::from(&point);
        let recovered = blstrs::G1Projective::try_from(&dto).unwrap();

        // then
        assert_eq!(point, recovered);
    }

    #[test]
    fn invalid_g1_bytes_are_rejected() {
        // given
        let dto = Bls12381G1PublicKey::from([0xff; 48]);

        // when
        let result = blstrs::G1Projective::try_from(dto);

        // then
        assert!(matches!(result, Err(CryptoConversionError::InvalidPoint)));
    }

    #[test]
    fn roundtrip_g2_projective() {
        // given
        let point = blstrs::G2Projective::generator() * blstrs::Scalar::from(42u64);

        // when
        let dto = Bls12381G2PublicKey::from(point);
        let recovered = blstrs::G2Projective::try_from(dto).unwrap();

        // then
        assert_eq!(point, recovered);
    }

    #[test]
    fn roundtrip_g2_projective_via_ref() {
        // given
        let point = blstrs::G2Projective::generator() * blstrs::Scalar::from(42u64);

        // when
        let dto = Bls12381G2PublicKey::from(&point);
        let recovered = blstrs::G2Projective::try_from(&dto).unwrap();

        // then
        assert_eq!(point, recovered);
    }

    #[test]
    fn invalid_g2_bytes_are_rejected() {
        // given
        let dto = Bls12381G2PublicKey::from([0xff; 96]);

        // when
        let result = blstrs::G2Projective::try_from(dto);

        // then
        assert!(matches!(result, Err(CryptoConversionError::InvalidPoint)));
    }
}
