use alloc::{string::String, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use core::marker::PhantomData;
use derive_more::{AsRef, Deref, Into};
use hex::FromHexError;
use serde_with::{Bytes, serde_as};
use thiserror::Error;

#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(::schemars::JsonSchema),
    derive(::borsh::BorshSchema),
    schemars(transparent)
)]
#[serde_as]
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Deref,
    AsRef,
    Into,
)]
#[serde(transparent)]
pub struct Hash<T, const N: usize> {
    #[deref]
    #[as_ref]
    #[into]
    #[serde_as(as = "Bytes")]
    #[cfg_attr(
        all(feature = "abi", not(target_arch = "wasm32")),
        schemars(with = "byte_schema_generator::ByteArray<N>")
    )]
    bytes: [u8; N],
    #[into(skip)]
    _marker: PhantomData<T>,
}

impl<T, const N: usize> From<[u8; N]> for Hash<T, N> {
    fn from(bytes: [u8; N]) -> Self {
        Self {
            bytes,
            _marker: PhantomData,
        }
    }
}

#[derive(Debug, Error)]
pub enum HexToHashError<const N: usize> {
    #[error("The provided string is not a valid hex.")]
    InvalidHex(#[from] FromHexError),
    #[error(
        "Expected the provided hex to decode to `{N}` bytes. Got `{provided_length}` bytes instead."
    )]
    InvalidLength { provided_length: usize },
}

impl<T, const N: usize> Hash<T, N> {
    /// Converts the hash to a hexadecimal string representation.
    pub fn as_hex(&self) -> String {
        hex::encode(self.as_ref())
    }

    /// Attempts to create a [`Hash32`] from a hexadecimal string.
    ///
    /// # Errors
    /// Returns [`HexToHashError::InvalidHex`] if the string contains non-hex characters.
    /// Returns [`HexToHashError::InvalidLength`] if the decoded bytes are not exactly 32 bytes.
    pub fn try_from_hex(hex_hash: impl AsRef<[u8]>) -> Result<Self, HexToHashError<N>> {
        let decoded_hex = hex::decode(hex_hash)?;
        let bytes: [u8; N] =
            decoded_hex
                .try_into()
                .map_err(|err: Vec<u8>| HexToHashError::InvalidLength {
                    provided_length: err.len(),
                })?;

        Ok(Self::from(bytes))
    }
}

/// Helper module to generate json schema [`super::Hash<T, N>`]
#[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
pub(super) mod byte_schema_generator {
    use schemars::{SchemaGenerator, schema::Schema};
    pub struct ByteArray<const N: usize>;

    #[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
    impl<const N: usize> schemars::JsonSchema for ByteArray<N> {
        fn schema_name() -> String {
            format!("ByteArray_{}", N)
        }

        fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
            use schemars::schema::*;
            SchemaObject {
                instance_type: Some(InstanceType::Array.into()),
                format: Some("byte".to_string()),
                metadata: Some(Box::new(Metadata {
                    description: Some(format!("A {}-byte array", N)),
                    ..Default::default()
                })),
                ..Default::default()
            }
            .into()
        }
    }
}

// Marker types
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(::schemars::JsonSchema),
    derive(::borsh::BorshSchema)
)]
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct Image;
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(::schemars::JsonSchema),
    derive(::borsh::BorshSchema)
)]
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct Compose;

/// Hash of an MPC Docker image running in the TEE environment. Used as a proposal for a new TEE
/// code hash to add to the whitelist, together with the TEE quote (which includes the RTMR3
/// measurement and more).
pub type MpcDockerImageHash = Hash<Image, 48>;

/// Hash of the launcher's Docker Compose file used to run the MPC node in the TEE environment. It
/// is computed from the launcher's Docker Compose template populated with the MPC node's Docker
/// image hash.
pub type LauncherDockerComposeHash = Hash<Compose, 32>;

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{RngCore, SeedableRng, rngs::StdRng};

    struct TestMarker;
    type TestHash = Hash<TestMarker, 32>;

    #[test]
    fn test_from_bytes_array() {
        let bytes = [1u8; 32];
        let hash: TestHash = bytes.into();
        assert_eq!(*hash, bytes);
    }

    #[test]
    fn test_from_trait() {
        let bytes = [42u8; 32];
        let hash = TestHash::from(bytes);
        assert_eq!(*hash, bytes);
    }

    #[test]
    fn test_into_bytes_array() {
        let bytes = [123u8; 32];
        let hash = TestHash::from(bytes);
        let converted_bytes: [u8; 32] = hash.into();
        assert_eq!(converted_bytes, bytes);
    }

    #[test]
    fn test_deref() {
        let bytes = [255u8; 32];
        let hash = TestHash::from(bytes);

        assert_eq!(hash.len(), 32);
        assert_eq!(hash[0], 255);
        assert_eq!(&hash[..4], &[255, 255, 255, 255]);
    }

    #[test]
    fn test_as_ref() {
        let bytes = [42u8; 32];
        let hash = TestHash::from(bytes);

        // Test AsRef<[u8; 32]> works
        let bytes_ref: &[u8; 32] = hash.as_ref();
        assert_eq!(bytes_ref, &bytes);

        // Test can be used where &[u8; 32] is expected
        fn takes_bytes_ref(b: &[u8; 32]) -> u8 {
            b[0]
        }
        assert_eq!(takes_bytes_ref(hash.as_ref()), 42);
    }

    #[test]
    fn test_as_hex() {
        let bytes = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let hash = TestHash::from(bytes);

        let expected_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        assert_eq!(hash.as_hex(), expected_hex);
    }

    #[test]
    fn test_zero_hash() {
        let zero_bytes = [0u8; 32];
        let hash = TestHash::from(zero_bytes);

        assert_eq!(hash.as_hex(), "0".repeat(64));
        assert_eq!(hash.len(), 32);
        assert!(hash.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_max_hash() {
        let max_bytes = [255u8; 32];
        let hash = TestHash::from(max_bytes);

        assert_eq!(hash.as_hex(), "f".repeat(64));
        assert_eq!(hash.len(), 32);
        assert!(hash.iter().all(|&b| b == 255));
    }

    #[test]
    fn test_type_aliases() {
        let bytes = [1u8; 32];

        let image_hash = TestHash::from(bytes);
        let compose_hash = LauncherDockerComposeHash::from(bytes);

        assert_eq!(*image_hash, bytes);
        assert_eq!(*compose_hash, bytes);
        assert_eq!(image_hash.as_hex(), compose_hash.as_hex());
    }

    #[test]
    fn test_different_marker_types() {
        let bytes = [42u8; 32];

        // Ensure different marker types create different types
        let image_hash = TestHash::from(bytes);
        let compose_hash = LauncherDockerComposeHash::from(bytes);

        // They should have the same data but be different types
        assert_eq!(*image_hash, *compose_hash);

        // This wouldn't compile (different types):
        // let _: MpcDockerImageHash = compose_hash;
    }

    #[test]
    fn test_slice_operations() {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let hash = TestHash::from(bytes);

        assert_eq!(&hash[0..4], &[0, 1, 2, 3]);
        assert_eq!(&hash[28..32], &[28, 29, 30, 31]);
        assert_eq!(hash.first(), Some(&0));
        assert_eq!(hash.last(), Some(&31));
    }

    #[test]
    fn test_conversion_roundtrip() {
        let original_bytes = [137u8; 32];

        // Test full roundtrip: bytes -> Hash32 -> bytes
        let hash = TestHash::from(original_bytes);
        let converted_back: [u8; 32] = hash.into();

        assert_eq!(original_bytes, converted_back);
    }

    #[test]
    fn should_serialize_equivalent_to_byte_array_with_serde() {
        // Given
        let bytes = random_byte_slice(42);
        let hash = TestHash::from(bytes);

        // When
        let bytes_as_json = serde_json::to_string(&bytes).unwrap();
        let hash_as_json = serde_json::to_string(&hash).unwrap();

        // Then
        assert_eq!(bytes_as_json, hash_as_json);
    }

    #[test]
    fn should_serialize_equivalent_to_byte_array_with_borsh() {
        // Given
        let bytes = random_byte_slice(42);
        let hash = TestHash::from(bytes);

        // When
        let bytes_as_borsh_vec = borsh::to_vec(&bytes).unwrap();
        let hash_as_borsh_vec = borsh::to_vec(&hash).unwrap();

        // Then
        assert_eq!(bytes_as_borsh_vec, hash_as_borsh_vec);
    }

    fn random_byte_slice(seed: u64) -> [u8; 32] {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        bytes
    }
}
