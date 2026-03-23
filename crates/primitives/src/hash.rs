use alloc::{string::String, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use core::{marker::PhantomData, str::FromStr};
use derive_more::{AsRef, Deref, Into};
use hex::FromHexError;
use serde_with::serde_as;
use thiserror::Error;

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
    #[serde_as(as = "serde_with::hex::Hex")]
    bytes: [u8; N],
    #[into(skip)]
    _marker: PhantomData<T>,
}

// Manual BorshSchema impl because borsh derive generates "Hash" for all
// Hash<T, N> regardless of N, causing a name collision when both N=32 and
// N=48 are used in the same schema. We include N in the declaration name.
#[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
impl<T: borsh::BorshSchema, const N: usize> borsh::BorshSchema for Hash<T, N> {
    fn declaration() -> borsh::schema::Declaration {
        alloc::format!("Hash{}", N)
    }

    fn add_definitions_recursively(
        definitions: &mut alloc::collections::BTreeMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        let byte_array_decl = alloc::format!("[u8; {}]", N);
        definitions.insert(
            Self::declaration(),
            borsh::schema::Definition::Struct {
                fields: borsh::schema::Fields::NamedFields(alloc::vec![
                    ("bytes".into(), byte_array_decl),
                    ("_marker".into(), "()".into()),
                ]),
            },
        );
    }
}

// Manual JsonSchema impl because:
// 1. schemars doesn't support [u8; N] for N > 32
// 2. The JSON representation is always a hex string regardless of N,
//    so the correct JSON schema type is String for all sizes
#[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
impl<T, const N: usize> schemars::JsonSchema for Hash<T, N> {
    fn schema_name() -> String {
        alloc::format!("Hash{}", N)
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <String as schemars::JsonSchema>::json_schema(generator)
    }
}

impl<T, const N: usize> From<[u8; N]> for Hash<T, N> {
    fn from(bytes: [u8; N]) -> Self {
        Self::new(bytes)
    }
}

impl<T, const N: usize> Hash<T, N> {
    /// Converts the hash to a hexadecimal string representation.
    pub fn as_hex(&self) -> String {
        hex::encode(self.as_ref())
    }

    pub fn as_bytes(&self) -> [u8; N] {
        self.bytes
    }

    pub const fn new(bytes: [u8; N]) -> Self {
        Self {
            bytes,
            _marker: PhantomData,
        }
    }
}

/// Backward-compatible alias for 32-byte hashes.
pub type Hash32<T> = Hash<T, 32>;

#[derive(Error, Debug)]
pub enum HashParseError {
    #[error("not a valid hex string")]
    HexError(#[from] FromHexError),
    #[error("hex string not {0} bytes")]
    InvalidLength(usize),
}

/// Backward-compatible alias.
pub type Hash32ParseError = HashParseError;

impl<T, const N: usize> FromStr for Hash<T, N> {
    type Err = HashParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded_hex_bytes = hex::decode(s)?;
        let hash_bytes: [u8; N] = decoded_hex_bytes
            .try_into()
            .map_err(|v: Vec<u8>| HashParseError::InvalidLength(v.len()))?;

        Ok(hash_bytes.into())
    }
}

// 32-byte marker types

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
pub struct Launcher;

// 48-byte marker types for TDX measurements

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
pub struct Mrtd;
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
pub struct Rtmr0;
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
pub struct Rtmr1;
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
pub struct Rtmr2;
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
pub struct KeyProviderEventDigest;

/// Hash of a Docker image running in the TEE environment. Used as a proposal for a new TEE
/// code hash to add to the whitelist, together with the TEE quote (which includes the RTMR3
/// measurement and more).
pub type DockerImageHash = Hash32<Image>;

/// Hash of the MPC node's Docker image.
pub type NodeImageHash = DockerImageHash;

/// Hash of the launcher's Docker Compose file used to run the MPC node in the TEE environment. It
/// is computed from the launcher's Docker Compose template populated with the launcher image hash
/// and the MPC node's Docker image hash.
pub type LauncherDockerComposeHash = Hash32<Compose>;

/// Hash of the launcher Docker image itself. Voted on by participants to allow
/// launcher upgrades without contract redeployment.
pub type LauncherImageHash = Hash32<Launcher>;

/// SHA-384 digest of the MRTD (Module Run-Time Data) TDX measurement.
pub type MrtdHash = Hash<Mrtd, 48>;

/// SHA-384 digest of the RTMR0 TDX measurement.
pub type Rtmr0Hash = Hash<Rtmr0, 48>;

/// SHA-384 digest of the RTMR1 TDX measurement.
pub type Rtmr1Hash = Hash<Rtmr1, 48>;

/// SHA-384 digest of the RTMR2 TDX measurement.
pub type Rtmr2Hash = Hash<Rtmr2, 48>;

/// SHA-384 digest of the key provider event.
pub type KeyProviderEventDigestHash = Hash<KeyProviderEventDigest, 48>;

#[cfg(test)]
mod tests {
    use super::*;

    use alloc::format;
    use rand::{RngCore, SeedableRng, rngs::StdRng};

    #[derive(Debug)]
    struct TestMarker;
    type TestHash = Hash32<TestMarker>;

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

        let image_hash = NodeImageHash::from(bytes);
        let compose_hash = LauncherDockerComposeHash::from(bytes);

        assert_eq!(*image_hash, bytes);
        assert_eq!(*compose_hash, bytes);
        assert_eq!(image_hash.as_hex(), compose_hash.as_hex());
    }

    #[test]
    fn test_different_marker_types() {
        let bytes = [42u8; 32];

        // Ensure different marker types create different types
        let image_hash = NodeImageHash::from(bytes);
        let compose_hash = LauncherDockerComposeHash::from(bytes);

        // They should have the same data but be different types
        assert_eq!(*image_hash, *compose_hash);

        // This wouldn't compile (different types):
        // let _: NodeImageHash = compose_hash;
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

    #[test]
    fn test_node_image_hash_hex_serialization() {
        // Given
        let expected_hex = "\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\"";

        // When
        let hash: NodeImageHash = serde_json::from_str(expected_hex).unwrap();
        let serialized_hex = serde_json::to_string(&hash).unwrap();

        // Then
        assert_eq!(format!("\"{}\"", hash.as_hex()), expected_hex);
        assert_eq!(serialized_hex, expected_hex);
    }

    #[test]
    fn test_parse_from_hex_string() {
        let expected_bytes = [0x11u8; 32];
        let hex_string = "11".repeat(32);

        let parsed: TestHash = hex_string.parse().unwrap();

        assert_eq!(*parsed, expected_bytes);
        assert_eq!(parsed.as_hex(), hex_string);
    }

    #[test]
    fn test_parse_accepts_uppercase_hex() {
        let expected_bytes = [0xABu8; 32];
        let hex_string = "AB".repeat(32);

        let parsed: TestHash = hex_string.parse().unwrap();

        assert_eq!(*parsed, expected_bytes);
        assert_eq!(parsed.as_hex(), "ab".repeat(32));
    }

    #[test]
    fn test_parse_rejects_invalid_hex() {
        let err = "0x00".parse::<TestHash>().unwrap_err();

        assert!(matches!(err, HashParseError::HexError(_)));
    }

    #[test]
    fn test_parse_rejects_invalid_length() {
        let err = "00".parse::<TestHash>().unwrap_err();

        match err {
            HashParseError::InvalidLength(len) => assert_eq!(len, 1),
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn test_48_byte_hash_roundtrip() {
        let bytes = [0xABu8; 48];
        let hash = MrtdHash::from(bytes);
        assert_eq!(hash.as_bytes(), bytes);
        assert_eq!(hash.as_hex(), "ab".repeat(48));

        let converted_back: [u8; 48] = hash.into();
        assert_eq!(converted_back, bytes);
    }

    #[test]
    fn test_48_byte_hash_serde_roundtrip() {
        let bytes = [0x42u8; 48];
        let hash = MrtdHash::from(bytes);

        let json = serde_json::to_string(&hash).unwrap();
        let deserialized: MrtdHash = serde_json::from_str(&json).unwrap();
        assert_eq!(hash, deserialized);
    }

    #[test]
    fn test_48_byte_hash_borsh_roundtrip() {
        let bytes = [0x42u8; 48];
        let hash = MrtdHash::from(bytes);

        let borsh_bytes = borsh::to_vec(&hash).unwrap();
        let deserialized = MrtdHash::try_from_slice(&borsh_bytes).unwrap();
        assert_eq!(hash, deserialized);
    }

    #[test]
    fn test_48_byte_borsh_equivalent_to_raw_array() {
        let bytes = [0x42u8; 48];
        let hash = MrtdHash::from(bytes);

        let bytes_as_borsh = borsh::to_vec(&bytes).unwrap();
        let hash_as_borsh = borsh::to_vec(&hash).unwrap();
        assert_eq!(bytes_as_borsh, hash_as_borsh);
    }

    #[test]
    fn test_48_byte_different_markers_are_distinct_types() {
        let bytes = [1u8; 48];
        let mrtd = MrtdHash::from(bytes);
        let rtmr0 = Rtmr0Hash::from(bytes);

        // Same data but different types
        assert_eq!(*mrtd, *rtmr0);

        // This wouldn't compile (different types):
        // let _: MrtdHash = rtmr0;
    }

    #[test]
    fn test_48_byte_parse_from_hex_string() {
        let expected_bytes = [0x11u8; 48];
        let hex_string = "11".repeat(48);

        let parsed: MrtdHash = hex_string.parse().unwrap();

        assert_eq!(*parsed, expected_bytes);
        assert_eq!(parsed.as_hex(), hex_string);
    }
}
