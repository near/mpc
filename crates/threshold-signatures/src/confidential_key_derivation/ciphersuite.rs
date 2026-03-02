use crate::confidential_key_derivation::{hash_app_id_with_pk, ElementG1, Signature, VerifyingKey};
use crate::crypto::ciphersuite::{BytesOrder, ScalarSerializationFormat};
use crate::crypto::constants::NEAR_CKD_DOMAIN;
use blstrs::{G1Affine, G2Affine};
use elliptic_curve::group::prime::PrimeCurveAffine;
use elliptic_curve::hash2curve::{hash_to_field, ExpandMsgXmd};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BLS12381SHA256;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BLS12381G2Group;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BLS12381G1Group;

#[derive(Clone, Copy)]
pub struct BLS12381ScalarField;

pub use blstrs;
pub use blstrs::G1Projective;
pub use blstrs::G2Projective;
pub use elliptic_curve::{Field, Group};

use crate::confidential_key_derivation::Scalar;

impl ScalarSerializationFormat for BLS12381SHA256 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::LittleEndian
    }
}

impl crate::Ciphersuite for BLS12381SHA256 {}

const CONTEXT_STRING: &str = "NEAR-BLS12381-G2-SHA256-v1";

// We are currently not using all the functionality. Therefore,
// I implemented only those that we use.
impl frost_core::Ciphersuite for BLS12381SHA256 {
    const ID: &'static str = CONTEXT_STRING;

    type Group = BLS12381G2Group;

    type HashOutput = [u8; 64];

    type SignatureSerialization = [u8; 64];

    #[allow(unused)]
    fn H1(m: &[u8]) -> <<Self::Group as frost_core::Group>::Field as frost_core::Field>::Scalar {
        unimplemented!()
    }

    #[allow(unused)]
    fn H2(m: &[u8]) -> <<Self::Group as frost_core::Group>::Field as frost_core::Field>::Scalar {
        unimplemented!()
    }

    #[allow(unused)]
    fn H3(m: &[u8]) -> <<Self::Group as frost_core::Group>::Field as frost_core::Field>::Scalar {
        unimplemented!()
    }

    #[allow(unused)]
    fn H4(m: &[u8]) -> Self::HashOutput {
        unimplemented!()
    }

    #[allow(unused)]
    fn H5(_m: &[u8]) -> Self::HashOutput {
        unimplemented!()
    }

    fn HDKG(
        m: &[u8],
    ) -> Option<<<Self::Group as frost_core::Group>::Field as frost_core::Field>::Scalar> {
        Some(hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"dkg"], m))
    }

    #[allow(unused)]
    fn HID(
        m: &[u8],
    ) -> Option<<<Self::Group as frost_core::Group>::Field as frost_core::Field>::Scalar> {
        unimplemented!()
    }
}

impl frost_core::Field for BLS12381ScalarField {
    type Scalar = Scalar;

    type Serialization = [u8; 32];

    fn zero() -> Self::Scalar {
        Scalar::ZERO
    }

    fn one() -> Self::Scalar {
        Scalar::ONE
    }

    fn invert(scalar: &Self::Scalar) -> Result<Self::Scalar, frost_core::FieldError> {
        scalar
            .invert()
            .into_option()
            .ok_or(frost_core::FieldError::InvalidZeroScalar)
    }

    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        Scalar::random(rng)
    }

    fn serialize(scalar: &Self::Scalar) -> Self::Serialization {
        scalar.to_bytes_le()
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Scalar, frost_core::FieldError> {
        Scalar::from_bytes_le(buf)
            .into_option()
            .ok_or(frost_core::FieldError::MalformedScalar)
    }

    fn little_endian_serialize(scalar: &Self::Scalar) -> Self::Serialization {
        Self::serialize(scalar)
    }
}

// Taken from blstrs, unfortunately not public
const COMPRESSED_SIZE_G2: usize = 96;

impl frost_core::Group for BLS12381G2Group {
    type Field = BLS12381ScalarField;

    type Element = blstrs::G2Projective;

    type Serialization = [u8; COMPRESSED_SIZE_G2];

    fn cofactor() -> <Self::Field as frost_core::Field>::Scalar {
        <Self::Field as frost_core::Field>::Scalar::ONE
    }

    fn identity() -> Self::Element {
        Self::Element::identity()
    }

    fn generator() -> Self::Element {
        Self::Element::generator()
    }

    fn serialize(element: &Self::Element) -> Result<Self::Serialization, frost_core::GroupError> {
        if element.is_identity().into() {
            Err(frost_core::GroupError::InvalidIdentityElement)
        } else {
            Ok(element.to_compressed())
        }
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Element, frost_core::GroupError> {
        Self::Element::from_compressed(buf).into_option().map_or(
            Err(frost_core::GroupError::MalformedElement),
            |point| {
                if point.is_identity().into() {
                    Err(frost_core::GroupError::InvalidIdentityElement)
                } else {
                    Ok(point)
                }
            },
        )
    }
}

// Taken from blstrs, unfortunately not public
const COMPRESSED_SIZE_G1: usize = 48;

impl frost_core::Group for BLS12381G1Group {
    type Field = BLS12381ScalarField;

    type Element = blstrs::G1Projective;

    type Serialization = [u8; COMPRESSED_SIZE_G1];

    fn cofactor() -> <Self::Field as frost_core::Field>::Scalar {
        <Self::Field as frost_core::Field>::Scalar::ONE
    }

    fn identity() -> Self::Element {
        Self::Element::identity()
    }

    fn generator() -> Self::Element {
        Self::Element::generator()
    }

    fn serialize(element: &Self::Element) -> Result<Self::Serialization, frost_core::GroupError> {
        if element.is_identity().into() {
            Err(frost_core::GroupError::InvalidIdentityElement)
        } else {
            Ok(element.to_compressed())
        }
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Element, frost_core::GroupError> {
        Self::Element::from_compressed(buf).into_option().map_or(
            Err(frost_core::GroupError::MalformedElement),
            |point| {
                if point.is_identity().into() {
                    Err(frost_core::GroupError::InvalidIdentityElement)
                } else {
                    Ok(point)
                }
            },
        )
    }
}

/// BLS signature verification
/// following the standard in <https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-coreverify>
pub fn verify_signature(
    verifying_key: &VerifyingKey,
    msg: &[u8],
    signature: &Signature,
) -> Result<(), frost_core::Error<BLS12381SHA256>> {
    let element1: G1Affine = signature.into();
    if (!element1.is_on_curve() | !element1.is_torsion_free() | element1.is_identity()).into() {
        return Err(frost_core::Error::InvalidSignature);
    }
    let element2: G2Affine = verifying_key.to_element().into();
    if (!element2.is_on_curve() | !element2.is_torsion_free() | element2.is_identity()).into() {
        return Err(frost_core::Error::MalformedVerifyingKey);
    }

    // Concatenate the master public key (96 bytes) in the hash computation
    // H(pk || app_id) when H is a random oracle
    let base1 = hash_app_id_with_pk(verifying_key, msg).into();
    let base2 =
        <<BLS12381SHA256 as frost_core::Ciphersuite>::Group as frost_core::Group>::generator()
            .into();

    if blstrs::pairing(&base1, &element2).eq(&blstrs::pairing(&element1, &base2)) {
        Ok(())
    } else {
        Err(frost_core::Error::InvalidSignature)
    }
}

pub fn hash_to_curve(bytes: &[u8]) -> ElementG1 {
    G1Projective::hash_to_curve(bytes, NEAR_CKD_DOMAIN, &[])
}

// From https://github.com/ZcashFoundation/frost/blob/3ffc19d8f473d5bc4e07ed41bc884bdb42d6c29f/frost-secp256k1/src/lib.rs#L161
fn hash_to_scalar(domain: &[&[u8]], msg: &[u8]) -> Scalar {
    let mut u = [super::scalar_wrapper::ScalarWrapper(
        <BLS12381ScalarField as frost_core::Field>::zero(),
    )];
    hash_to_field::<ExpandMsgXmd<Sha256>, super::scalar_wrapper::ScalarWrapper>(
        &[msg],
        domain,
        &mut u,
    )
    .expect("should never return error according to error cases described in ExpandMsgXmd");
    u[0].0
}

#[cfg(test)]
mod tests {
    use digest::generic_array::GenericArray;
    use elliptic_curve::{hash2curve::FromOkm, Field, Group};
    use rand_core::SeedableRng;

    use crate::confidential_key_derivation::scalar_wrapper::ScalarWrapper;
    use crate::confidential_key_derivation::Scalar;
    use crate::test_utils::MockCryptoRng;
    use crate::{
        confidential_key_derivation::{
            ciphersuite::{verify_signature, BLS12381SHA256},
            hash_app_id_with_pk, ElementG2, VerifyingKey,
        },
        test_utils::check_common_traits_for_type,
    };

    #[test]
    fn check_bls12381_g2_sha256_common_traits() {
        check_common_traits_for_type(&BLS12381SHA256);
    }

    // Taken from bls12_381 implementation https://github.com/zkcrypto/bls12_381/blob/6bb96951d5c2035caf4989b6e4a018435379590f/src/hash_to_curve/map_scalar.rs#L26
    #[test]
    fn test_hash_to_scalar() {
        let tests: &[(&[u8], &str)] = &[
            (
                &[0u8; 48],
                "ScalarWrapper(Scalar(0x0000000000000000000000000000000000000000000000000000000000000000))",
            ),
            (
                b"aaaaaabbbbbbccccccddddddeeeeeeffffffgggggghhhhhh",
                "ScalarWrapper(Scalar(0x2228450bf55d8fe62395161bd3677ff6fc28e45b89bc87e02a818eda11a8c5da))",
            ),
            (
                b"111111222222333333444444555555666666777777888888",
                "ScalarWrapper(Scalar(0x4aa543cbd2f0c8f37f8a375ce2e383eb343e7e3405f61e438b0a15fb8899d1ae))",
            ),
        ];
        for (input, expected) in tests {
            let output = format!(
                "{:?}",
                <ScalarWrapper as FromOkm>::from_okm(GenericArray::from_slice(input))
            );
            assert_eq!(&output, expected);
        }
    }

    #[test]
    fn test_verify_signature() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let x = Scalar::random(&mut rng);
        let g2 = ElementG2::generator();
        let g2x = g2 * x;
        let hm = hash_app_id_with_pk(&VerifyingKey::new(g2x), b"hello world");
        let sigma = hm * x;

        assert!(verify_signature(&VerifyingKey::new(g2x), b"hello world", &sigma).is_ok());
    }

    #[test]
    fn test_verify_signature_invalid() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let x = Scalar::random(&mut rng);
        let g2 = ElementG2::generator();
        let g2x = g2 * Scalar::ZERO;
        let hm = hash_app_id_with_pk(&VerifyingKey::new(g2x), b"hello world");
        let sigma = hm * x;

        assert_eq!(
            verify_signature(&VerifyingKey::new(g2x), b"hello world", &sigma).unwrap_err(),
            frost_core::Error::MalformedVerifyingKey
        );

        let g2x = g2 * x;
        let sigma = hm * Scalar::ZERO;
        assert_eq!(
            verify_signature(&VerifyingKey::new(g2x), b"hello world", &sigma).unwrap_err(),
            frost_core::Error::InvalidSignature
        );
    }
}
