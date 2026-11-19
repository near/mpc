//! Serde encoding of a group element as one byte string, to use through
//! `#[serde(with = "point_bytes")]`.
//!
//! [`CoefficientCommitment`] encodes itself as a tuple of integers in binary
//! formats, and `MessagePack` spends two bytes on every integer above 127.

use std::{fmt, marker::PhantomData};

use frost_core::keys::CoefficientCommitment;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Visitor, ser::Error as _};

use crate::Ciphersuite;

pub(super) fn serialize<C: Ciphersuite, S: Serializer>(
    point: &CoefficientCommitment<C>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        return Serialize::serialize(point, serializer);
    }
    let bytes = point.serialize().map_err(S::Error::custom)?;
    serializer.serialize_bytes(&bytes)
}

pub(super) fn deserialize<'de, C: Ciphersuite, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<CoefficientCommitment<C>, D::Error> {
    if deserializer.is_human_readable() {
        return Deserialize::deserialize(deserializer);
    }
    deserializer.deserialize_bytes(PointVisitor(PhantomData))
}

struct PointVisitor<C>(PhantomData<C>);

impl<C: Ciphersuite> Visitor<'_> for PointVisitor<C> {
    type Value = CoefficientCommitment<C>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a serialized group element other than the identity")
    }

    fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
        CoefficientCommitment::deserialize(bytes).map_err(E::custom)
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod test {
    use frost_core::Group;
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::ecdsa::{Secp256K1Group, Secp256K1Sha256};

    type C = Secp256K1Sha256;

    const COMPRESSED_POINT_LEN: usize = 33;
    /// Marker of a `MessagePack` byte string shorter than 256 bytes; its
    /// length follows on one byte.
    const BIN8: u8 = 0xc4;
    const BIN8_HEADER_LEN: usize = 2;

    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    struct Point(#[serde(with = "super")] CoefficientCommitment<C>);

    fn generator() -> Point {
        Point(CoefficientCommitment::new(Secp256K1Group::generator()))
    }

    #[test]
    fn serialize__should_add_only_a_header_to_the_compressed_point() {
        // Given
        let point = generator();

        // When
        let bytes = rmp_serde::to_vec(&point).unwrap();

        // Then
        assert_eq!(bytes, byte_string(&point.0.serialize().unwrap()));
        assert_eq!(bytes.len(), BIN8_HEADER_LEN + COMPRESSED_POINT_LEN);
    }

    #[test]
    fn deserialize__should_recover_the_point() {
        // Given
        let point = generator();
        let bytes = rmp_serde::to_vec(&point).unwrap();

        // When
        let decoded: Point = rmp_serde::from_slice(&bytes).unwrap();

        // Then
        assert_eq!(decoded.0, point.0);
    }

    #[test]
    fn deserialize__should_reject_the_identity() {
        // Given
        let bytes = byte_string(&[0u8; COMPRESSED_POINT_LEN]);

        // When
        let result = rmp_serde::from_slice::<Point>(&bytes);

        // Then
        assert!(result.is_err());
    }

    #[test]
    fn deserialize__should_reject_a_truncated_point() {
        // Given
        let point = generator().0.serialize().unwrap();
        let bytes = byte_string(&point[..COMPRESSED_POINT_LEN - 1]);

        // When
        let result = rmp_serde::from_slice::<Point>(&bytes);

        // Then
        assert!(result.is_err());
    }

    fn byte_string(bytes: &[u8]) -> Vec<u8> {
        let len = u8::try_from(bytes.len()).unwrap();
        [&[BIN8, len], bytes].concat()
    }
}
