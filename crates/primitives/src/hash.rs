use alloc::{format, string::String, vec::Vec};
use core::{marker::PhantomData, str::FromStr};
use hex::FromHexError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HashParseError {
    #[error("not a valid hex string")]
    HexError(#[from] FromHexError),
    #[error("expected {expected} bytes, got {got}")]
    InvalidLength { expected: usize, got: usize },
}

/// Marker trait binding a hash type name to a specific byte length.
///
/// Each concrete hash type defines a zero-sized spec struct and implements this trait
/// for exactly one `N`. This prevents constructing a `HashDigest<S, WRONG_N>` — the
/// compiler rejects it because the trait bound `S: HashSpec<WRONG_N>` is not satisfied.
pub trait HashSpec<const N: usize> {
    const NAME: &'static str;
}

/// A fixed-size hash digest with hex serialization.
///
/// `S` is a zero-sized marker implementing [`HashSpec<N>`] that binds the type name
/// to the byte length `N`. All trait implementations are generic — adding a new hash
/// type requires only a spec struct, a trait impl, and a type alias.
#[derive(derive_more::Deref, derive_more::AsRef, derive_more::Into)]
pub struct HashDigest<S: HashSpec<N>, const N: usize> {
    #[deref]
    #[as_ref]
    #[into]
    bytes: [u8; N],
    #[into(skip)]
    _marker: PhantomData<S>,
}

// Manual impls to avoid spurious `S: Trait` bounds from derive macros.

impl<S: HashSpec<N>, const N: usize> Clone for HashDigest<S, N> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S: HashSpec<N>, const N: usize> Copy for HashDigest<S, N> {}

impl<S: HashSpec<N>, const N: usize> PartialEq for HashDigest<S, N> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<S: HashSpec<N>, const N: usize> Eq for HashDigest<S, N> {}

impl<S: HashSpec<N>, const N: usize> PartialOrd for HashDigest<S, N> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<S: HashSpec<N>, const N: usize> Ord for HashDigest<S, N> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl<S: HashSpec<N>, const N: usize> core::hash::Hash for HashDigest<S, N> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

// -- Debug -------------------------------------------------------------------

impl<S: HashSpec<N>, const N: usize> core::fmt::Debug for HashDigest<S, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Encode hex directly into a stack buffer to avoid allocating a String.
        let mut buf = [0u8; 2 * 128]; // max 128-byte hashes (256 hex chars)
        let hex_buf = &mut buf[..2 * N];
        hex::encode_to_slice(self.bytes, hex_buf).map_err(|_| core::fmt::Error)?;
        let hex_str = core::str::from_utf8(hex_buf).map_err(|_| core::fmt::Error)?;
        write!(f, "{}({})", S::NAME, hex_str)
    }
}

// -- Serde (hex string) ------------------------------------------------------

impl<S: HashSpec<N>, const N: usize> serde::Serialize for HashDigest<S, N> {
    fn serialize<Ser: serde::Serializer>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error> {
        serializer.serialize_str(&hex::encode(self.bytes))
    }
}

impl<'de, S: HashSpec<N>, const N: usize> serde::Deserialize<'de> for HashDigest<S, N> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex_str = <String as serde::Deserialize>::deserialize(deserializer)?;
        let decoded = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
        let bytes: [u8; N] = decoded.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected {} bytes, got {}", N, v.len()))
        })?;
        Ok(Self::new(bytes))
    }
}

// -- Borsh -------------------------------------------------------------------

impl<S: HashSpec<N>, const N: usize> borsh::BorshSerialize for HashDigest<S, N> {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        self.bytes.serialize(writer)
    }
}

impl<S: HashSpec<N>, const N: usize> borsh::BorshDeserialize for HashDigest<S, N> {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let bytes = <[u8; N]>::deserialize_reader(reader)?;
        Ok(Self::new(bytes))
    }
}

// -- BorshSchema (behind `abi` feature) --------------------------------------

#[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
impl<S: HashSpec<N>, const N: usize> borsh::BorshSchema for HashDigest<S, N> {
    fn declaration() -> borsh::schema::Declaration {
        S::NAME.to_string()
    }

    fn add_definitions_recursively(
        definitions: &mut alloc::collections::BTreeMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        let byte_array_decl = format!("[u8; {}]", N);
        definitions.insert(
            Self::declaration(),
            borsh::schema::Definition::Struct {
                fields: borsh::schema::Fields::NamedFields(alloc::vec![(
                    "bytes".into(),
                    byte_array_decl,
                )]),
            },
        );
    }
}

// -- JsonSchema (behind `abi` feature) ---------------------------------------

#[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
impl<S: HashSpec<N>, const N: usize> schemars::JsonSchema for HashDigest<S, N> {
    fn schema_name() -> String {
        S::NAME.to_string()
    }

    fn json_schema(_generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        let hex_len = (N * 2) as u32;
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

// -- From / Into / constructors ----------------------------------------------

impl<S: HashSpec<N>, const N: usize> From<[u8; N]> for HashDigest<S, N> {
    fn from(bytes: [u8; N]) -> Self {
        Self::new(bytes)
    }
}

impl<S: HashSpec<N>, const N: usize> HashDigest<S, N> {
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

// -- FromStr -----------------------------------------------------------------

impl<S: HashSpec<N>, const N: usize> FromStr for HashDigest<S, N> {
    type Err = HashParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded_hex_bytes = hex::decode(s)?;
        let hash_bytes: [u8; N] =
            decoded_hex_bytes
                .try_into()
                .map_err(|v: Vec<u8>| HashParseError::InvalidLength {
                    expected: N,
                    got: v.len(),
                })?;
        Ok(hash_bytes.into())
    }
}

// ============================================================================
// define_hash! convenience macro
// ============================================================================

/// Defines a new hash type backed by [`HashDigest`].
///
/// Generates a zero-sized spec struct (`<Name>Spec`), implements [`HashSpec`] for it,
/// and creates a type alias `<Name>` = `HashDigest<<Name>Spec, N>`.
///
/// # Example
///
/// ```ignore
/// mpc_primitives::define_hash!(
///     /// SHA-256 hash of a Bitcoin block.
///     BitcoinBlockHash, 32
/// );
/// ```
#[macro_export]
macro_rules! define_hash {
    ($(#[$meta:meta])* $name:ident, $n:literal) => {
        $crate::_macro_deps::paste::paste! {
            #[doc(hidden)]
            pub struct [<$name Spec>];

            impl $crate::_macro_deps::borsh::BorshSerialize for [<$name Spec>] {
                fn serialize<W: $crate::_macro_deps::borsh::io::Write>(
                    &self, _writer: &mut W,
                ) -> $crate::_macro_deps::borsh::io::Result<()> {
                    Ok(())
                }
            }

            impl $crate::_macro_deps::borsh::BorshDeserialize for [<$name Spec>] {
                fn deserialize_reader<R: $crate::_macro_deps::borsh::io::Read>(
                    _reader: &mut R,
                ) -> $crate::_macro_deps::borsh::io::Result<Self> {
                    Ok(Self)
                }
            }

            impl $crate::hash::HashSpec<$n> for [<$name Spec>] {
                const NAME: &'static str = stringify!($name);
            }

            $(#[$meta])*
            pub type $name = $crate::hash::HashDigest<[<$name Spec>], $n>;
        }
    };
}

// ============================================================================
// Concrete hash types
// ============================================================================

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
        assert_eq!(hash.as_bytes(), bytes);
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
