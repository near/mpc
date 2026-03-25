/// Parses an N-byte hash from a hex string.
pub(crate) fn parse_hex_hash<const N: usize, T: From<[u8; N]>>(
    s: &str,
) -> Result<T, mpc_primitives::hash::HashParseError> {
    let decoded = hex::decode(s)?;
    let bytes: [u8; N] = decoded.try_into().map_err(|v: Vec<u8>| {
        mpc_primitives::hash::HashParseError::InvalidLength {
            expected: N,
            got: v.len(),
        }
    })?;
    Ok(T::from(bytes))
}

/// Generates a 32-byte hash newtype with hex JSON serialization and `FromStr`.
/// Unlike the primitives crate's `hash_newtype!`, this does not include borsh or schema support.
macro_rules! hash_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            derive_more::Deref,
            derive_more::AsRef,
            derive_more::Into,
        )]
        $(#[$meta])*
        pub struct $name {
            #[deref]
            #[as_ref]
            #[into]
            bytes: [u8; 32],
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&hex::encode(&self.bytes))
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = <String as serde::Deserialize>::deserialize(deserializer)?;
                crate::hash::parse_hex_hash::<32, Self>(&s).map_err(serde::de::Error::custom)
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(bytes: [u8; 32]) -> Self {
                Self { bytes }
            }
        }

        impl core::str::FromStr for $name {
            type Err = mpc_primitives::hash::HashParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                crate::hash::parse_hex_hash::<32, Self>(s)
            }
        }

        impl $name {
            pub fn as_hex(&self) -> String {
                hex::encode(self.as_ref())
            }
        }
    };
}

pub(crate) use hash_newtype;
