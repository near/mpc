use crate::confidential_key_derivation::{ElementG1, Signature, VerifyingKey};
use crate::crypto::ciphersuite::{BytesOrder, ScalarSerializationFormat};
use crate::crypto::constants::NEAR_CKD_DOMAIN;
use blstrs::{G1Affine, G2Affine};
use digest::{consts::U48, generic_array::GenericArray};
use elliptic_curve::group::prime::PrimeCurveAffine;
use elliptic_curve::hash2curve::{hash_to_field, ExpandMsgXmd, FromOkm};
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

pub type BLS12381Scalar = blstrs::Scalar;

pub use blstrs;
pub use blstrs::G1Projective;
pub use blstrs::G2Projective;
pub use elliptic_curve::{Field, Group};

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
    type Scalar = blstrs::Scalar;

    type Serialization = [u8; 32];

    fn zero() -> Self::Scalar {
        blstrs::Scalar::ZERO
    }

    fn one() -> Self::Scalar {
        blstrs::Scalar::ONE
    }

    fn invert(scalar: &Self::Scalar) -> Result<Self::Scalar, frost_core::FieldError> {
        scalar
            .invert()
            .into_option()
            .ok_or(frost_core::FieldError::InvalidZeroScalar)
    }

    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        blstrs::Scalar::random(rng)
    }

    fn serialize(scalar: &Self::Scalar) -> Self::Serialization {
        scalar.to_bytes_le()
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Scalar, frost_core::FieldError> {
        blstrs::Scalar::from_bytes_le(buf)
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

    let base1 = hash_to_curve(msg).into();
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
fn hash_to_scalar(domain: &[&[u8]], msg: &[u8]) -> blstrs::Scalar {
    let mut u = [ScalarWrapper(
        <BLS12381ScalarField as frost_core::Field>::zero(),
    )];
    hash_to_field::<ExpandMsgXmd<Sha256>, ScalarWrapper>(&[msg], domain, &mut u)
        .expect("should never return error according to error cases described in ExpandMsgXmd");
    u[0].0
}

#[derive(Clone, Copy, Debug, Default)]
struct ScalarWrapper(blstrs::Scalar);

impl ScalarWrapper {
    // Based on https://github.com/arkworks-rs/algebra/blob/c6f9284c17df00c50d954a5fe1c72dd4a5698103/ff/src/fields/prime.rs#L72
    // Converts `bytes` into a `Scalar` by interpreting the input as
    // an integer in big-endian and then converting the result to Scalar
    // which implicitly does modular reduction
    fn from_be_bytes_mod_order(bytes: &[u8]) -> Self {
        let mut res = blstrs::Scalar::ZERO;

        let mut count = 0;
        let mut remainder = 0;
        for byte in bytes {
            remainder = (remainder << 8) + u64::from(*byte);
            count += 1;
            if count == 8 {
                res = res.shl(64) + blstrs::Scalar::from(remainder);
                remainder = 0;
                count = 0;
            }
        }
        if count > 0 {
            res = res * res.shl(count * 8) + blstrs::Scalar::from(remainder);
        }
        Self(res)
    }
}

// Follows https://github.com/zkcrypto/bls12_381/blob/6bb96951d5c2035caf4989b6e4a018435379590f/src/hash_to_curve/map_scalar.rs
impl FromOkm for ScalarWrapper {
    // ceil(log2(p)) = 255, m = 1, k = 128.
    type Length = U48;

    fn from_okm(okm: &GenericArray<u8, Self::Length>) -> Self {
        Self::from_be_bytes_mod_order(okm)
    }
}

#[cfg(test)]
mod tests {
    use blstrs::Scalar;
    use digest::generic_array::GenericArray;
    use elliptic_curve::hash2curve::FromOkm;
    use elliptic_curve::Field;
    use elliptic_curve::Group;
    use rand::Rng;
    use rand::RngCore;
    use rand_core::OsRng;

    use crate::confidential_key_derivation::ciphersuite::verify_signature;
    use crate::confidential_key_derivation::ciphersuite::ScalarWrapper;
    use crate::confidential_key_derivation::VerifyingKey;
    use crate::{
        confidential_key_derivation::{
            ciphersuite::{hash_to_curve, BLS12381SHA256},
            ElementG2,
        },
        test::check_common_traits_for_type,
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
        let x = Scalar::random(OsRng);
        let g2 = ElementG2::generator();
        let g2x = g2 * x;
        let hm = hash_to_curve(b"hello world");
        let sigma = hm * x;

        assert!(verify_signature(&VerifyingKey::new(g2x), b"hello world", &sigma).is_ok());
    }

    #[test]
    fn test_verify_signature_invalid() {
        let x = Scalar::random(OsRng);
        let g2 = ElementG2::generator();
        let g2x = g2 * Scalar::ZERO;
        let hm = hash_to_curve(b"hello world");
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

    #[test]
    // This test only makes sense if `overflow-checks` are enabled
    // This is guaranteed by the `test_verify_overflow_failure` below
    fn test_stress_test_scalarwrapper_from_le_bytes_mod_order() {
        // empty case
        ScalarWrapper::from_be_bytes_mod_order(&[]);
        let mut rng = rand::rngs::OsRng;
        for _ in 0..1000 {
            let len = rng.gen_range(1..10000);
            let mut bytes = vec![0; len];
            rng.fill_bytes(&mut bytes);
            ScalarWrapper::from_be_bytes_mod_order(&bytes);
        }
    }

    #[test]
    #[should_panic(expected = "attempt to add with overflow")]
    // This test guarantees that `overflow-checks` are enabled
    fn test_verify_overflow_failure() {
        let mut a = u64::MAX - 123;
        let mut rng = rand::rngs::OsRng;
        // Required to avoid clippy detecting the overflow
        let b = rng.gen_range(124..10000);
        a += b;
        assert!(a > 0);
    }
}
