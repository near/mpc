use crate::bounded_vec::BoundedVecOutOfBounds;

/// A [`String`] whose UTF-8 length is at most `U` bytes, checked on construction and on
/// deserialization.
///
/// Serialization delegates to the inner [`String`], so the JSON and borsh representations are
/// identical to an unbounded string: adopting this type on a field changes neither the wire
/// format nor stored bytes.
///
/// Deserialization is the enforcement point — a value over the bound is rejected rather than
/// truncated. Adopting it on a field that is *already persisted* therefore needs care: data
/// written before the bound existed becomes unreadable. See the crate README before doing so.
#[derive(PartialEq, Eq, Debug, Clone, Hash, PartialOrd, Ord)]
pub struct BoundedString<const U: usize>(String);

impl<const U: usize> BoundedString<U> {
    pub fn new(inner: String) -> Result<Self, BoundedVecOutOfBounds> {
        let got = inner.len();
        if got > U {
            return Err(BoundedVecOutOfBounds::UpperBoundError {
                upper_bound: U,
                got,
            });
        }
        Ok(Self(inner))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }

    pub const fn upper_bound() -> usize {
        U
    }
}

impl<const U: usize> std::ops::Deref for BoundedString<U> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const U: usize> std::fmt::Display for BoundedString<U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<const U: usize> TryFrom<String> for BoundedString<U> {
    type Error = BoundedVecOutOfBounds;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<const U: usize> From<BoundedString<U>> for String {
    fn from(value: BoundedString<U>) -> Self {
        value.0
    }
}

mod borsh_impl {
    use super::*;
    use borsh::{BorshDeserialize, BorshSerialize};

    impl<const U: usize> BorshSerialize for BoundedString<U> {
        fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
            self.0.serialize(writer)
        }
    }

    impl<const U: usize> BorshDeserialize for BoundedString<U> {
        fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
            let inner = String::deserialize_reader(reader)?;
            Self::new(inner)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
        }
    }

    #[cfg(feature = "abi")]
    mod schema {
        use super::*;
        use borsh::BorshSchema;
        use borsh::schema::{Declaration, Definition, add_definition};
        use std::collections::BTreeMap;

        impl<const U: usize> BorshSchema for BoundedString<U> {
            fn declaration() -> Declaration {
                format!("BoundedString<{U}>")
            }

            fn add_definitions_recursively(definitions: &mut BTreeMap<Declaration, Definition>) {
                let definition = Definition::Sequence {
                    length_width: Definition::DEFAULT_LENGTH_WIDTH,
                    length_range: 0..=(U as u64),
                    elements: u8::declaration(),
                };
                add_definition(Self::declaration(), definition, definitions);
                u8::add_definitions_recursively(definitions);
            }
        }
    }
}

mod serde_impl {
    use super::*;
    use serde::{Deserialize, Serialize};

    impl<const U: usize> Serialize for BoundedString<U> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.0.serialize(serializer)
        }
    }

    impl<'de, const U: usize> Deserialize<'de> for BoundedString<U> {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let inner = String::deserialize(deserializer)?;
            Self::new(inner).map_err(serde::de::Error::custom)
        }
    }

    #[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
    mod schema {
        use super::*;
        use schemars::JsonSchema;
        use schemars::r#gen::SchemaGenerator;
        use schemars::schema::Schema;

        impl<const U: usize> JsonSchema for BoundedString<U> {
            fn schema_name() -> String {
                format!("BoundedString_{U}")
            }

            fn json_schema(generator: &mut SchemaGenerator) -> Schema {
                let mut schema = String::json_schema(generator).into_object();
                schema.string().max_length = u32::try_from(U).ok();
                Schema::Object(schema)
            }
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    const MAX: usize = 4;
    type Bounded = BoundedString<MAX>;

    #[test]
    fn new__should_accept_up_to_the_bound_and_reject_beyond_it() {
        // Given / When / Then
        assert_eq!(Bounded::new("abcd".to_string()).unwrap().as_str(), "abcd");
        assert_eq!(
            Bounded::new("abcde".to_string()),
            Err(BoundedVecOutOfBounds::UpperBoundError {
                upper_bound: MAX,
                got: 5
            })
        );
    }

    #[test]
    fn new__should_count_bytes_not_characters() {
        // Given a 2-char string of 4 bytes, and a 3-char one of 6
        // When / Then
        assert!(Bounded::new("éé".to_string()).is_ok());
        assert!(Bounded::new("ééé".to_string()).is_err());
    }

    #[test]
    fn serde__should_round_trip_as_a_plain_string_and_reject_over_the_bound() {
        // Given
        let value = Bounded::new("abcd".to_string()).unwrap();

        // When
        let json = serde_json::to_string(&value).unwrap();

        // Then the wire format is a plain string
        assert_eq!(json, "\"abcd\"");
        assert_eq!(serde_json::from_str::<Bounded>(&json).unwrap(), value);
        assert!(serde_json::from_str::<Bounded>("\"abcde\"").is_err());
    }

    #[test]
    fn borsh__should_round_trip_as_a_plain_string_and_reject_over_the_bound() {
        // Given
        let value = Bounded::new("abcd".to_string()).unwrap();

        // When
        let bytes = borsh::to_vec(&value).unwrap();

        // Then the bytes are identical to the unbounded string
        assert_eq!(bytes, borsh::to_vec(&"abcd".to_string()).unwrap());
        assert_eq!(borsh::from_slice::<Bounded>(&bytes).unwrap(), value);

        let oversized = borsh::to_vec(&"abcde".to_string()).unwrap();
        assert!(borsh::from_slice::<Bounded>(&oversized).is_err());
    }
}
