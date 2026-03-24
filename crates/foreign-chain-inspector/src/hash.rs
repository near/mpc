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
                let hex_str = <String as serde::Deserialize>::deserialize(deserializer)?;
                let decoded =
                    hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
                let bytes: [u8; 32] = decoded.try_into().map_err(|v: Vec<u8>| {
                    serde::de::Error::custom(format!(
                        "expected 32 bytes, got {}",
                        v.len()
                    ))
                })?;
                Ok(Self { bytes })
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
                let decoded = hex::decode(s)?;
                let bytes: [u8; 32] =
                    decoded
                        .try_into()
                        .map_err(|v: Vec<u8>| mpc_primitives::hash::HashParseError::InvalidLength {
                            expected: 32,
                            got: v.len(),
                        })?;
                Ok(Self { bytes })
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
