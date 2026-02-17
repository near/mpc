use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// A `BTreeSet` that is guaranteed to contain at least one element.
#[derive(
    Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, derive_more::Deref, derive_more::Into,
)]
pub struct NonEmptyBTreeSet<T: Ord>(BTreeSet<T>);

impl<T: Ord> NonEmptyBTreeSet<T> {
    pub fn new(set: BTreeSet<T>) -> Result<Self, EmptySetError> {
        if set.is_empty() {
            Err(EmptySetError)
        } else {
            Ok(Self(set))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmptySetError;

impl std::fmt::Display for EmptySetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "set must contain at least one element")
    }
}

impl<T: Ord + Serialize> Serialize for NonEmptyBTreeSet<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Ord + Deserialize<'de>> Deserialize<'de> for NonEmptyBTreeSet<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let set = BTreeSet::<T>::deserialize(deserializer)?;
        NonEmptyBTreeSet::new(set).map_err(serde::de::Error::custom)
    }
}

impl<T: Ord + BorshSerialize> BorshSerialize for NonEmptyBTreeSet<T> {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.0.serialize(writer)
    }
}

impl<T: Ord + BorshDeserialize> BorshDeserialize for NonEmptyBTreeSet<T> {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let set = BTreeSet::<T>::deserialize_reader(reader)?;
        NonEmptyBTreeSet::new(set)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }
}

#[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
impl<T: Ord + schemars::JsonSchema> schemars::JsonSchema for NonEmptyBTreeSet<T> {
    fn schema_name() -> String {
        format!("NonEmptyBTreeSet_{}", T::schema_name())
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        // Reuse BTreeSet's schema with minItems: 1
        let mut schema = <BTreeSet<T>>::json_schema(generator);
        if let schemars::schema::Schema::Object(ref mut obj) = schema {
            if let Some(ref mut array) = obj.array {
                array.min_items = Some(1);
            }
        }
        schema
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::single_element(BTreeSet::from([1]))]
    #[case::multiple_elements(BTreeSet::from([1, 2, 3]))]
    fn new_succeeds_for_non_empty_set(#[case] set: BTreeSet<i32>) {
        // Given: a non-empty BTreeSet
        // When: constructing a NonEmptyBTreeSet
        let result = NonEmptyBTreeSet::new(set.clone());
        // Then: it succeeds and wraps the original set
        let ne = result.unwrap();
        assert_eq!(*ne, set);
    }

    #[test]
    fn new_fails_for_empty_set() {
        // Given: an empty BTreeSet
        let set: BTreeSet<i32> = BTreeSet::new();
        // When: constructing a NonEmptyBTreeSet
        let result = NonEmptyBTreeSet::new(set);
        // Then: it returns an EmptySetError
        assert_eq!(result.unwrap_err(), EmptySetError);
    }

    #[test]
    fn empty_set_error_displays_message() {
        // Given: an EmptySetError
        // When: formatting it as a string
        // Then: it produces a human-readable message
        assert_eq!(
            EmptySetError.to_string(),
            "set must contain at least one element"
        );
    }

    #[test]
    fn deref_exposes_btreeset_methods() {
        // Given: a NonEmptyBTreeSet with elements [1, 2, 3]
        let ne = NonEmptyBTreeSet::new(BTreeSet::from([1, 2, 3])).unwrap();
        // When: using BTreeSet methods via Deref
        // Then: they behave as expected
        assert!(ne.contains(&1));
        assert!(!ne.contains(&4));
        assert_eq!(ne.len(), 3);
    }

    #[test]
    fn into_converts_back_to_btreeset() {
        // Given: a NonEmptyBTreeSet
        let original = BTreeSet::from([1, 2, 3]);
        let ne = NonEmptyBTreeSet::new(original.clone()).unwrap();
        // When: converting into a BTreeSet
        let converted: BTreeSet<i32> = ne.into();
        // Then: the result equals the original set
        assert_eq!(converted, original);
    }

    #[rstest]
    #[case::single(BTreeSet::from([42]))]
    #[case::multiple(BTreeSet::from([1, 2, 3]))]
    fn serde_json_roundtrip_preserves_data(#[case] set: BTreeSet<i32>) {
        // Given: a NonEmptyBTreeSet
        let ne = NonEmptyBTreeSet::new(set).unwrap();
        // When: serializing to JSON and deserializing back
        let json = serde_json::to_string(&ne).unwrap();
        let deserialized: NonEmptyBTreeSet<i32> = serde_json::from_str(&json).unwrap();
        // Then: the result equals the original
        assert_eq!(deserialized, ne);
    }

    #[test]
    fn serde_json_deserialize_rejects_empty_array() {
        // Given: a JSON empty array
        let json = "[]";
        // When: deserializing as NonEmptyBTreeSet
        let result: Result<NonEmptyBTreeSet<i32>, _> = serde_json::from_str(json);
        // Then: deserialization fails
        assert!(result.is_err());
    }

    #[rstest]
    #[case::single(BTreeSet::from([42u32]))]
    #[case::multiple(BTreeSet::from([1u32, 2, 3]))]
    fn borsh_roundtrip_preserves_data(#[case] set: BTreeSet<u32>) {
        // Given: a NonEmptyBTreeSet
        let ne = NonEmptyBTreeSet::new(set).unwrap();
        // When: serializing to borsh and deserializing back
        let bytes = borsh::to_vec(&ne).unwrap();
        let deserialized: NonEmptyBTreeSet<u32> = BorshDeserialize::try_from_slice(&bytes).unwrap();
        // Then: the result equals the original
        assert_eq!(deserialized, ne);
    }

    #[test]
    fn borsh_deserialize_rejects_empty_set() {
        // Given: borsh bytes encoding an empty BTreeSet
        let empty: BTreeSet<u32> = BTreeSet::new();
        let bytes = borsh::to_vec(&empty).unwrap();
        // When: deserializing as NonEmptyBTreeSet
        let result: Result<NonEmptyBTreeSet<u32>, _> = BorshDeserialize::try_from_slice(&bytes);
        // Then: deserialization fails with InvalidData
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn eq_returns_true_for_identical_sets() {
        // Given: two NonEmptyBTreeSets with the same elements
        let a = NonEmptyBTreeSet::new(BTreeSet::from([1, 2])).unwrap();
        let b = NonEmptyBTreeSet::new(BTreeSet::from([1, 2])).unwrap();
        // When: comparing for equality
        // Then: they are equal
        assert_eq!(a, b);
    }

    #[test]
    fn eq_returns_false_for_different_sets() {
        // Given: two NonEmptyBTreeSets with different elements
        let a = NonEmptyBTreeSet::new(BTreeSet::from([1, 2])).unwrap();
        let b = NonEmptyBTreeSet::new(BTreeSet::from([3, 4])).unwrap();
        // When: comparing for equality
        // Then: they are not equal
        assert_ne!(a, b);
    }

    #[test]
    fn ord_compares_by_btreeset_ordering() {
        // Given: two NonEmptyBTreeSets where one is lexicographically smaller
        let smaller = NonEmptyBTreeSet::new(BTreeSet::from([1, 2])).unwrap();
        let larger = NonEmptyBTreeSet::new(BTreeSet::from([3, 4])).unwrap();
        // When: comparing their order
        // Then: the set with smaller elements comes first
        assert!(smaller < larger);
    }

    #[test]
    fn clone_produces_equal_independent_copy() {
        // Given: a NonEmptyBTreeSet
        let ne = NonEmptyBTreeSet::new(BTreeSet::from([1, 2])).unwrap();
        // When: cloning it
        let cloned = ne.clone();
        // Then: the clone is equal to the original
        assert_eq!(ne, cloned);
    }
}
