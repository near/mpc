use alloc::{string::String, vec::Vec};
use hex::FromHexError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HashParseError {
    #[error("not a valid hex string")]
    HexError(#[from] FromHexError),
    #[error("expected {expected} bytes, got {got}")]
    InvalidLength { expected: usize, got: usize },
}

// Helper functions called by the macro-generated impls to keep the macro body small.

#[doc(hidden)]
pub fn debug_hash(name: &str, bytes: &[u8], f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    write!(f, "{}({})", name, hex::encode(bytes))
}

#[doc(hidden)]
pub fn serialize_hash<S: serde::Serializer>(
    bytes: &[u8],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex::encode(bytes))
}

#[doc(hidden)]
pub fn deserialize_hash<'de, const N: usize, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    let hex_str = <String as serde::Deserialize>::deserialize(deserializer)?;
    let decoded = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
    decoded.try_into().map_err(|v: Vec<u8>| {
        serde::de::Error::custom(alloc::format!("expected {} bytes, got {}", N, v.len()))
    })
}

#[doc(hidden)]
pub fn parse_hash<const N: usize>(s: &str) -> Result<[u8; N], HashParseError> {
    let decoded = hex::decode(s)?;
    decoded
        .try_into()
        .map_err(|v: Vec<u8>| HashParseError::InvalidLength {
            expected: N,
            got: v.len(),
        })
}

/// Generates a newtype hash struct wrapping `[u8; N]` with hex serde, borsh,
/// `Debug`, `FromStr`, `Deref`, `AsRef`, `Into`, and (behind the `abi` feature)
/// `BorshSchema` / `JsonSchema`.
#[macro_export]
macro_rules! define_hash {
    ($(#[$meta:meta])* $name:ident, $n:literal) => {
        $(#[$meta])*
        #[derive(
            Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
            derive_more::Deref, derive_more::AsRef, derive_more::Into,
        )]
        pub struct $name(
            #[deref] #[as_ref] #[into]
            [u8; $n],
        );

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                $crate::hash::debug_hash(stringify!($name), &self.0, f)
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}", $crate::_macro_deps::hex::encode(self.0))
            }
        }

        impl $crate::_macro_deps::serde::Serialize for $name {
            fn serialize<S: $crate::_macro_deps::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                $crate::hash::serialize_hash(&self.0, serializer)
            }
        }

        impl<'de> $crate::_macro_deps::serde::Deserialize<'de> for $name {
            fn deserialize<D: $crate::_macro_deps::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                $crate::hash::deserialize_hash::<$n, D>(deserializer).map(Self::new)
            }
        }

        impl $crate::_macro_deps::borsh::BorshSerialize for $name {
            fn serialize<W: $crate::_macro_deps::borsh::io::Write>(&self, writer: &mut W) -> $crate::_macro_deps::borsh::io::Result<()> {
                $crate::_macro_deps::borsh::BorshSerialize::serialize(&self.0, writer)
            }
        }

        impl $crate::_macro_deps::borsh::BorshDeserialize for $name {
            fn deserialize_reader<R: $crate::_macro_deps::borsh::io::Read>(reader: &mut R) -> $crate::_macro_deps::borsh::io::Result<Self> {
                <[u8; $n] as $crate::_macro_deps::borsh::BorshDeserialize>::deserialize_reader(reader).map(Self::new)
            }
        }

        #[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
        impl $crate::_macro_deps::borsh::BorshSchema for $name {
            fn declaration() -> $crate::_macro_deps::borsh::schema::Declaration {
                stringify!($name).to_string()
            }

            fn add_definitions_recursively(
                definitions: &mut std::collections::BTreeMap<
                    $crate::_macro_deps::borsh::schema::Declaration,
                    $crate::_macro_deps::borsh::schema::Definition,
                >,
            ) {
                let byte_array_decl = std::format!("[u8; {}]", $n);
                definitions.insert(
                    Self::declaration(),
                    $crate::_macro_deps::borsh::schema::Definition::Struct {
                        fields: $crate::_macro_deps::borsh::schema::Fields::UnnamedFields(std::vec![
                            byte_array_decl,
                        ]),
                    },
                );
            }
        }

        #[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
        impl $crate::_macro_deps::schemars::JsonSchema for $name {
            fn schema_name() -> String {
                stringify!($name).to_string()
            }

            fn json_schema(
                _generator: &mut $crate::_macro_deps::schemars::r#gen::SchemaGenerator,
            ) -> $crate::_macro_deps::schemars::schema::Schema {
                let hex_len = ($n * 2) as u32;
                $crate::_macro_deps::schemars::schema::Schema::Object($crate::_macro_deps::schemars::schema::SchemaObject {
                    instance_type: Some($crate::_macro_deps::schemars::schema::SingleOrVec::Single(Box::new(
                        $crate::_macro_deps::schemars::schema::InstanceType::String,
                    ))),
                    string: Some(Box::new($crate::_macro_deps::schemars::schema::StringValidation {
                        min_length: Some(hex_len),
                        max_length: Some(hex_len),
                        pattern: Some("^[0-9a-fA-F]+$".to_string()),
                    })),
                    ..Default::default()
                })
            }
        }

        impl From<[u8; $n]> for $name {
            fn from(bytes: [u8; $n]) -> Self {
                Self::new(bytes)
            }
        }

        impl core::str::FromStr for $name {
            type Err = $crate::hash::HashParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $crate::hash::parse_hash::<$n>(s).map(Self::new)
            }
        }

        impl $name {
            pub fn as_hex(&self) -> String {
                $crate::_macro_deps::hex::encode(self.0)
            }

            pub const fn new(bytes: [u8; $n]) -> Self {
                Self(bytes)
            }
        }
    };
}

define_hash!(
    /// Hash of a Docker image running in the TEE environment. Used as a proposal for a new TEE
    /// code hash to add to the whitelist, together with the TEE quote (which includes the RTMR3
    /// measurement and more).
    DockerImageHash,
    32
);

/// Hash of the MPC node's Docker image.
pub type NodeImageHash = DockerImageHash;

define_hash!(
    /// Hash of the launcher's Docker Compose file used to run the MPC node in the TEE environment.
    /// It is computed from the launcher's Docker Compose template populated with the launcher image
    /// hash and the MPC node's Docker image hash.
    LauncherDockerComposeHash,
    32
);

define_hash!(
    /// Hash of the launcher Docker image itself. Voted on by participants to allow
    /// launcher upgrades without contract redeployment.
    LauncherImageHash,
    32
);

define_hash!(
    /// A SHA-384 digest used for TDX measurements (MRTD, RTMRs, event digests).
    Sha384Digest,
    48
);

#[cfg(test)]
mod tests {
    use super::*;

    use alloc::format;
    use assert_matches::assert_matches;
    use borsh::BorshDeserialize;
    use rand::{RngCore, SeedableRng, rngs::StdRng};

    define_hash!(TestHash, 32);
    define_hash!(TestHash48, 48);

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

        let bytes_ref: &[u8; 32] = hash.as_ref();
        assert_eq!(bytes_ref, &bytes);

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
        // Given
        let expected_bytes = [0x11u8; 32];
        let hex_string = "11".repeat(32);

        // When
        let parsed: TestHash = hex_string.parse().unwrap();

        // Then
        assert_eq!(*parsed, expected_bytes);
        assert_eq!(parsed.as_hex(), hex_string);
    }

    #[test]
    fn test_parse_accepts_uppercase_hex() {
        // Given
        let expected_bytes = [0xABu8; 32];
        let hex_string = "AB".repeat(32);

        // When
        let parsed: TestHash = hex_string.parse().unwrap();

        // Then
        assert_eq!(*parsed, expected_bytes);
        assert_eq!(parsed.as_hex(), "ab".repeat(32));
    }

    #[test]
    fn test_parse_rejects_invalid_hex() {
        // When
        let err = "0x00".parse::<TestHash>().unwrap_err();

        // Then
        assert_matches!(err, HashParseError::HexError(_));
    }

    #[test]
    fn test_parse_rejects_invalid_length() {
        // When
        let err = "00".parse::<TestHash>().unwrap_err();

        // Then
        match err {
            HashParseError::InvalidLength { expected, got } => {
                assert_eq!(expected, 32);
                assert_eq!(got, 1);
            }
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn test_48_byte_hash_roundtrip() {
        // Given
        let bytes = [0xABu8; 48];
        let hash = TestHash48::from(bytes);

        // Then
        assert_eq!(*hash, bytes);
        assert_eq!(hash.as_hex(), "ab".repeat(48));

        let converted_back: [u8; 48] = hash.into();
        assert_eq!(converted_back, bytes);
    }

    #[test]
    fn test_48_byte_hash_serde_roundtrip() {
        // Given
        let bytes = [0x42u8; 48];
        let hash = TestHash48::from(bytes);

        // When
        let json = serde_json::to_string(&hash).unwrap();
        let deserialized: TestHash48 = serde_json::from_str(&json).unwrap();

        // Then
        assert_eq!(hash, deserialized);
    }

    #[test]
    fn test_48_byte_hash_borsh_roundtrip() {
        // Given
        let bytes = [0x42u8; 48];
        let hash = TestHash48::from(bytes);

        // When
        let borsh_bytes = borsh::to_vec(&hash).unwrap();
        let deserialized = TestHash48::try_from_slice(&borsh_bytes).unwrap();

        // Then
        assert_eq!(hash, deserialized);
    }

    #[test]
    fn test_48_byte_borsh_equivalent_to_raw_array() {
        // Given
        let bytes = [0x42u8; 48];
        let hash = TestHash48::from(bytes);

        // When
        let bytes_as_borsh = borsh::to_vec(&bytes).unwrap();
        let hash_as_borsh = borsh::to_vec(&hash).unwrap();

        // Then
        assert_eq!(bytes_as_borsh, hash_as_borsh);
    }

    #[test]
    fn test_48_byte_parse_from_hex_string() {
        // Given
        let expected_bytes = [0x11u8; 48];
        let hex_string = "11".repeat(48);

        // When
        let parsed: TestHash48 = hex_string.parse().unwrap();

        // Then
        assert_eq!(*parsed, expected_bytes);
        assert_eq!(parsed.as_hex(), hex_string);
    }
}
