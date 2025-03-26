use borsh::{BorshDeserialize, BorshSerialize};
use k256::{
    elliptic_curve::{bigint::ArrayEncoding, CurveArithmetic, PrimeField},
    AffinePoint, Secp256k1, U256,
};
use serde::{Deserialize, Serialize};

// TODO: This key will be much bigger. It's VerifyingKey plus "Frost header"
pub type Ed25519PublicKey = frost_ed25519::keys::PublicKeyPackage;

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SignatureResponse {
    Secp256k1(k256_types::SignatureResponse),
    Edd25519(edd25519_types::SignatureResponse),
}

pub trait ScalarExt: Sized {
    fn from_bytes(bytes: [u8; 32]) -> Option<Self>;
    fn from_non_biased(bytes: [u8; 32]) -> Self;
    fn to_bytes(&self) -> [u8; 32];
    fn name() -> &'static str;
}

pub mod k256_types {
    use super::*;
    use k256::Scalar;

    pub type PublicKey = <Secp256k1 as CurveArithmetic>::AffinePoint;

    impl ScalarExt for Scalar {
        /// Returns nothing if the bytes are greater than the field size of Secp256k1.
        /// This will be very rare with random bytes as the field size is 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
        fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
            let bytes = U256::from_be_slice(bytes.as_slice());
            Self::from_repr(bytes.to_be_byte_array()).into_option()
        }

        /// When the user can't directly select the value, this will always work
        /// Use cases are things that we know have been hashed
        fn from_non_biased(hash: [u8; 32]) -> Self {
            // This should never happen.
            // The space of inputs is 2^256, the space of the field is ~2^256 - 2^129.
            // This mean that you'd have to run 2^127 hashes to find a value that causes this to fail.
            Self::from_bytes(hash).expect("Derived scalar value falls outside of the field")
        }

        fn to_bytes(&self) -> [u8; 32] {
            self.to_bytes().into()
        }

        fn name() -> &'static str {
            "k256"
        }
    }

    // Is there a better way to force a borsh serialization?
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy, Ord, PartialOrd)]
    pub struct SerializableScalar {
        pub scalar: Scalar,
    }

    impl SerializableScalar {
        pub fn new(scalar: Scalar) -> Self {
            Self { scalar }
        }
    }

    impl From<Scalar> for SerializableScalar {
        fn from(scalar: Scalar) -> Self {
            Self { scalar }
        }
    }

    impl BorshSerialize for SerializableScalar {
        fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
            let to_ser: [u8; 32] = self.scalar.to_bytes().into();
            BorshSerialize::serialize(&to_ser, writer)
        }
    }

    impl BorshDeserialize for SerializableScalar {
        fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
            let from_ser: [u8; 32] = BorshDeserialize::deserialize_reader(reader)?;
            let scalar = Scalar::from_bytes(from_ser).ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("The given scalar is not in the field of {}", Scalar::name(),),
            ))?;
            Ok(SerializableScalar { scalar })
        }
    }

    // TODO: Is there a better way to force a borsh serialization?
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
    pub struct SerializableAffinePoint {
        pub affine_point: AffinePoint,
    }

    impl BorshSerialize for SerializableAffinePoint {
        fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
            let to_ser: Vec<u8> = serde_json::to_vec(&self.affine_point)?;
            BorshSerialize::serialize(&to_ser, writer)
        }
    }

    impl BorshDeserialize for SerializableAffinePoint {
        fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
            let from_ser: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
            let affine_point = serde_json::from_slice(&from_ser)?;
            Ok(SerializableAffinePoint { affine_point })
        }
    }
    #[derive(
        BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq,
    )]
    pub struct SignatureResponse {
        pub big_r: SerializableAffinePoint,
        pub s: SerializableScalar,
        pub recovery_id: u8,
    }

    impl SignatureResponse {
        pub fn new(big_r: AffinePoint, s: k256::Scalar, recovery_id: u8) -> Self {
            SignatureResponse {
                big_r: SerializableAffinePoint {
                    affine_point: big_r,
                },
                s: s.into(),
                recovery_id,
            }
        }
    }
}

pub mod edd25519_types {
    use super::*;
    use curve25519_dalek::{edwards::CompressedEdwardsY, Scalar};

    impl ScalarExt for Scalar {
        fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
            Self::from_repr(bytes).into_option()
        }

        /// When the user can't directly select the value, this will always work
        /// Use cases are things that we know have been hashed
        fn from_non_biased(hash: [u8; 32]) -> Self {
            // This should never happen.
            // The space of inputs is 2^256, the space of the field is ~2^256 - 2^129.
            // This mean that you'd have to run 2^127 hashes to find a value that causes this to fail.
            Self::from_bytes(hash).expect("Derived scalar value falls outside of the field")
        }

        fn to_bytes(&self) -> [u8; 32] {
            self.to_bytes()
        }

        fn name() -> &'static str {
            "edd25519"
        }
    }

    // Is there a better way to force a borsh serialization?
    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
    pub struct SerializableScalar {
        scalar: Scalar,
    }

    impl SerializableScalar {
        pub fn new(scalar: Scalar) -> Self {
            Self { scalar }
        }
    }

    impl From<Scalar> for SerializableScalar {
        fn from(scalar: Scalar) -> Self {
            Self { scalar }
        }
    }

    impl BorshSerialize for SerializableScalar {
        fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
            let to_ser: [u8; 32] = self.scalar.to_bytes();
            BorshSerialize::serialize(&to_ser, writer)
        }
    }

    impl BorshDeserialize for SerializableScalar {
        fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
            let from_ser: [u8; 32] = BorshDeserialize::deserialize_reader(reader)?;
            let scalar = Scalar::from_bytes(from_ser).ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("The given scalar is not in the field of {}", Scalar::name(),),
            ))?;
            Ok(SerializableScalar { scalar })
        }
    }

    impl Ord for SerializableScalar {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.scalar.as_bytes().cmp(other.scalar.as_bytes())
        }
    }

    impl PartialOrd for SerializableScalar {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            self.scalar.as_bytes().partial_cmp(&other.scalar.as_bytes())
        }
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize, Eq, Clone, Copy)]
    pub struct SerializableEdwardsPoint(CompressedEdwardsY);

    impl BorshSerialize for SerializableEdwardsPoint {
        fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
            let to_ser: Vec<u8> = serde_json::to_vec(&self.0)?;
            BorshSerialize::serialize(&to_ser, writer)
        }
    }

    impl BorshDeserialize for SerializableEdwardsPoint {
        fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
            let from_ser: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
            let edwards_point = serde_json::from_slice(&from_ser)?;
            Ok(SerializableEdwardsPoint(edwards_point))
        }
    }

    #[derive(
        BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq,
    )]
    pub struct SignatureResponse {
        r: SerializableEdwardsPoint,
        s: SerializableScalar,
    }

    impl SignatureResponse {
        pub fn to_bytes(&self) -> [u8; 64] {
            let r_bytes: [u8; 32] = self.r.0.to_bytes();
            let s_bytes: [u8; 32] = self.s.scalar.to_bytes();
            let mut bytes_repr = [0u8; 64];

            bytes_repr[0..32].copy_from_slice(&r_bytes);
            bytes_repr[32..64].copy_from_slice(&s_bytes);

            bytes_repr
        }
    }

    /// Make sure that [`SignatureResponse::to_bytes`] serializes to bytes
    /// by concatenating (r, s) to a 64 byte array in correct order.
    #[test]
    fn test_edd25519_signature() {
        let r_bytes = [10; 32];
        let s_bytes = [20; 32];

        let r = SerializableEdwardsPoint(CompressedEdwardsY::from_slice(&r_bytes).unwrap());
        let s = SerializableScalar::new(Scalar::from_bytes_mod_order(s_bytes));

        let signature_response = SignatureResponse { r, s: s.clone() };
        let signature_bytes: [u8; 64] = signature_response.to_bytes();

        assert_eq!(signature_bytes[0..32], r_bytes);
        assert_eq!(signature_bytes[32..64], s.scalar.to_bytes());
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn serializeable_scalar_roundtrip() {
        use k256::elliptic_curve::PrimeField;
        let test_vec = vec![
            k256::Scalar::ZERO,
            k256::Scalar::ONE,
            k256::Scalar::from_u128(u128::MAX),
            k256::Scalar::from_bytes([3; 32]).unwrap(),
        ];

        for scalar in test_vec.into_iter() {
            let input = k256_types::SerializableScalar { scalar };
            // Test borsh
            {
                let serialized = borsh::to_vec(&input).unwrap();
                let output: k256_types::SerializableScalar =
                    borsh::from_slice(&serialized).unwrap();
                assert_eq!(input, output, "Failed on {:?}", scalar);
            }
        }
    }
}
