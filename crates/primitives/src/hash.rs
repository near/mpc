use alloc::{string::String, vec::Vec};
use core::str::FromStr;
use hex::FromHexError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HashParseError {
    #[error("not a valid hex string")]
    HexError(#[from] FromHexError),
    #[error("expected {expected} bytes, got {got}")]
    InvalidLength { expected: usize, got: usize },
}

/// Generates a hash newtype wrapping `[u8; $n]` with hex serde, borsh, `FromStr`,
/// `Deref`, `AsRef`, `Into`, and (when the `abi` feature is active) BorshSchema / JsonSchema.
macro_rules! hash_newtype {
    ($(#[$meta:meta])* $name:ident, $n:literal) => {
        #[serde_with::serde_as]
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
            borsh::BorshSerialize,
            borsh::BorshDeserialize,
            derive_more::Deref,
            derive_more::AsRef,
            derive_more::Into,
        )]
        $(#[$meta])*
        #[serde(transparent)]
        pub struct $name {
            #[deref]
            #[as_ref]
            #[into]
            #[serde_as(as = "serde_with::hex::Hex")]
            bytes: [u8; $n],
        }

        impl From<[u8; $n]> for $name {
            fn from(bytes: [u8; $n]) -> Self {
                Self::new(bytes)
            }
        }

        impl $name {
            /// Converts the hash to a hexadecimal string representation.
            pub fn as_hex(&self) -> String {
                hex::encode(self.as_ref())
            }

            pub fn as_bytes(&self) -> [u8; $n] {
                self.bytes
            }

            pub const fn new(bytes: [u8; $n]) -> Self {
                Self { bytes }
            }
        }

        impl FromStr for $name {
            type Err = HashParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let decoded_hex_bytes = hex::decode(s)?;
                let hash_bytes: [u8; $n] =
                    decoded_hex_bytes
                        .try_into()
                        .map_err(|v: Vec<u8>| HashParseError::InvalidLength {
                            expected: $n,
                            got: v.len(),
                        })?;
                Ok(hash_bytes.into())
            }
        }

        #[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
        impl borsh::BorshSchema for $name {
            fn declaration() -> borsh::schema::Declaration {
                alloc::format!(stringify!($name))
            }

            fn add_definitions_recursively(
                definitions: &mut alloc::collections::BTreeMap<
                    borsh::schema::Declaration,
                    borsh::schema::Definition,
                >,
            ) {
                let byte_array_decl = alloc::format!("[u8; {}]", $n);
                definitions.insert(
                    Self::declaration(),
                    borsh::schema::Definition::Struct {
                        fields: borsh::schema::Fields::NamedFields(alloc::vec![
                            ("bytes".into(), byte_array_decl),
                        ]),
                    },
                );
            }
        }

        #[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
        impl schemars::JsonSchema for $name {
            fn schema_name() -> String {
                alloc::format!(stringify!($name))
            }

            fn json_schema(
                _generator: &mut schemars::r#gen::SchemaGenerator,
            ) -> schemars::schema::Schema {
                let hex_len = ($n * 2) as u32;
                schemars::schema::Schema::Object(schemars::schema::SchemaObject {
                    instance_type: Some(schemars::schema::SingleOrVec::Single(Box::new(
                        schemars::schema::InstanceType::String,
                    ))),
                    string: Some(Box::new(schemars::schema::StringValidation {
                        min_length: Some(hex_len),
                        max_length: Some(hex_len),
                        pattern: Some("^[0-9a-fA-F]+$".to_string()),
                    })),
                    ..Default::default()
                })
            }
        }
    };
}

hash_newtype!(
    /// Hash of a Docker image running in the TEE environment. Used as a proposal for a new TEE
    /// code hash to add to the whitelist, together with the TEE quote (which includes the RTMR3
    /// measurement and more).
    DockerImageHash,
    32
);

/// Hash of the MPC node's Docker image.
pub type NodeImageHash = DockerImageHash;

hash_newtype!(
    /// Hash of the launcher's Docker Compose file used to run the MPC node in the TEE environment.
    /// It is computed from the launcher's Docker Compose template populated with the launcher image
    /// hash and the MPC node's Docker image hash.
    LauncherDockerComposeHash,
    32
);

hash_newtype!(
    /// Hash of the launcher Docker image itself. Voted on by participants to allow
    /// launcher upgrades without contract redeployment.
    LauncherImageHash,
    32
);

#[cfg(test)]
mod tests {
    use super::*;

    use alloc::format;
    use assert_matches::assert_matches;
    use borsh::BorshDeserialize;
    use rand::{RngCore, SeedableRng, rngs::StdRng};

    hash_newtype!(TestHash, 32);
    hash_newtype!(TestHash48, 48);

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
        let bytes = random_byte_slice(42);
        let hash = TestHash::from(bytes);

        let bytes_as_borsh_vec = borsh::to_vec(&bytes).unwrap();
        let hash_as_borsh_vec = borsh::to_vec(&hash).unwrap();

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
        let expected_hex = "\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\"";

        let hash: NodeImageHash = serde_json::from_str(expected_hex).unwrap();
        let serialized_hex = serde_json::to_string(&hash).unwrap();

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

        assert_matches!(err, HashParseError::HexError(_));
    }

    #[test]
    fn test_parse_rejects_invalid_length() {
        let err = "00".parse::<TestHash>().unwrap_err();

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
        let bytes = [0xABu8; 48];
        let hash = TestHash48::from(bytes);
        assert_eq!(hash.as_bytes(), bytes);
        assert_eq!(hash.as_hex(), "ab".repeat(48));

        let converted_back: [u8; 48] = hash.into();
        assert_eq!(converted_back, bytes);
    }

    #[test]
    fn test_48_byte_hash_serde_roundtrip() {
        let bytes = [0x42u8; 48];
        let hash = TestHash48::from(bytes);

        let json = serde_json::to_string(&hash).unwrap();
        let deserialized: TestHash48 = serde_json::from_str(&json).unwrap();
        assert_eq!(hash, deserialized);
    }

    #[test]
    fn test_48_byte_hash_borsh_roundtrip() {
        let bytes = [0x42u8; 48];
        let hash = TestHash48::from(bytes);

        let borsh_bytes = borsh::to_vec(&hash).unwrap();
        let deserialized = TestHash48::try_from_slice(&borsh_bytes).unwrap();
        assert_eq!(hash, deserialized);
    }

    #[test]
    fn test_48_byte_borsh_equivalent_to_raw_array() {
        let bytes = [0x42u8; 48];
        let hash = TestHash48::from(bytes);

        let bytes_as_borsh = borsh::to_vec(&bytes).unwrap();
        let hash_as_borsh = borsh::to_vec(&hash).unwrap();
        assert_eq!(bytes_as_borsh, hash_as_borsh);
    }

    #[test]
    fn test_48_byte_parse_from_hex_string() {
        let expected_bytes = [0x11u8; 48];
        let hex_string = "11".repeat(48);

        let parsed: TestHash48 = hex_string.parse().unwrap();

        assert_eq!(*parsed, expected_bytes);
        assert_eq!(parsed.as_hex(), hex_string);
    }
}
