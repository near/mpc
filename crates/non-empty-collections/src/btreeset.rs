use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// A `BTreeSet` that is guaranteed to contain at least one element.
#[derive(
    Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, derive_more::Deref, derive_more::Into,
)]
pub struct NonEmptyBTreeSet<T: Ord>(BTreeSet<T>);

impl<T: Ord> NonEmptyBTreeSet<T> {
    pub fn new(item: T) -> Self {
        Self(BTreeSet::from([item]))
    }

    /// Adds a value to the set.
    ///
    /// Returns whether the value was newly inserted. That is:
    ///
    /// - If the set did not previously contain an equal value, `true` is
    ///   returned.
    /// - If the set already contained an equal value, `false` is returned, and
    ///   the entry is not updated.
    pub fn insert(&mut self, item: T) -> bool {
        self.0.insert(item)
    }

    /// Constructs without checking emptiness. Caller must guarantee non-emptiness.
    pub(crate) fn new_unchecked(set: BTreeSet<T>) -> Self {
        debug_assert!(!set.is_empty());
        Self(set)
    }
}

impl<T: Ord> TryFrom<BTreeSet<T>> for NonEmptyBTreeSet<T> {
    type Error = EmptySetError;

    fn try_from(set: BTreeSet<T>) -> Result<Self, Self::Error> {
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
        NonEmptyBTreeSet::try_from(set).map_err(serde::de::Error::custom)
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
        NonEmptyBTreeSet::try_from(set)
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
    use assert_matches::assert_matches;
    use rstest::rstest;

    #[test]
    fn new_creates_single_element_set() {
        // Given / When
        let set = NonEmptyBTreeSet::new(42);
        // Then
        assert_eq!(set.len(), 1);
        assert!(set.contains(&42));
    }

    #[test]
    fn try_from_succeeds_for_non_empty_set() {
        // Given
        let btree = BTreeSet::from([1, 2, 3]);
        // When
        let result = NonEmptyBTreeSet::try_from(btree.clone());
        // Then
        let set = result.unwrap();
        assert_eq!(*set, btree);
    }

    #[test]
    fn try_from_fails_for_empty_set() {
        // Given
        let empty: BTreeSet<i32> = BTreeSet::new();
        // When
        let result = NonEmptyBTreeSet::try_from(empty);
        // Then
        assert_eq!(result.unwrap_err(), EmptySetError);
    }

    #[test]
    fn empty_set_error_displays_message() {
        // Given
        // When
        // Then
        assert_eq!(
            EmptySetError.to_string(),
            "set must contain at least one element"
        );
    }

    #[test]
    fn deref_exposes_btreeset_methods() {
        // Given
        let mut set = NonEmptyBTreeSet::new(1);
        set.insert(2);
        set.insert(3);
        // When / Then
        assert!(set.contains(&1));
        assert!(!set.contains(&4));
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn into_converts_back_to_btreeset() {
        // Given
        let mut set = NonEmptyBTreeSet::new(1);
        set.insert(2);
        set.insert(3);
        // When
        let converted: BTreeSet<i32> = set.into();
        // Then
        assert_eq!(converted, BTreeSet::from([1, 2, 3]));
    }

    #[rstest]
    #[case::single(42)]
    #[case::multiple(1)]
    fn serde_json_roundtrip_preserves_data(#[case] first: i32) {
        // Given
        let mut original = NonEmptyBTreeSet::new(first);
        if first == 1 {
            original.insert(2);
            original.insert(3);
        }
        // When
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: NonEmptyBTreeSet<i32> = serde_json::from_str(&json).unwrap();
        // Then
        assert_eq!(deserialized, original);
    }

    #[test]
    fn serde_json_deserialize_rejects_empty_array() {
        // Given
        let empty_json_array = "[]";
        // When
        let result: Result<NonEmptyBTreeSet<i32>, _> = serde_json::from_str(empty_json_array);
        // Then
        assert_matches!(result, Err(_));
    }

    #[rstest]
    #[case::single(42u32)]
    #[case::multiple(1u32)]
    fn borsh_roundtrip_preserves_data(#[case] first: u32) {
        // Given
        let mut original = NonEmptyBTreeSet::new(first);
        if first == 1 {
            original.insert(2);
            original.insert(3);
        }
        // When
        let bytes = borsh::to_vec(&original).unwrap();
        let deserialized: NonEmptyBTreeSet<u32> = BorshDeserialize::try_from_slice(&bytes).unwrap();
        // Then
        assert_eq!(deserialized, original);
    }

    #[test]
    fn borsh_deserialize_rejects_empty_set() {
        // Given
        let empty_set_bytes = borsh::to_vec(&BTreeSet::<u32>::new()).unwrap();
        // When
        let result: Result<NonEmptyBTreeSet<u32>, _> =
            BorshDeserialize::try_from_slice(&empty_set_bytes);
        // Then
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn eq_returns_true_for_identical_sets() {
        // Given
        let mut set_a = NonEmptyBTreeSet::new(1);
        set_a.insert(2);
        let mut set_b = NonEmptyBTreeSet::new(1);
        set_b.insert(2);
        // When / Then
        assert_eq!(set_a, set_b);
    }

    #[test]
    fn eq_returns_false_for_different_sets() {
        // Given
        let mut set_a = NonEmptyBTreeSet::new(1);
        set_a.insert(2);
        let mut set_b = NonEmptyBTreeSet::new(3);
        set_b.insert(4);
        // When / Then
        assert_ne!(set_a, set_b);
    }

    #[test]
    fn ord_compares_by_btreeset_ordering() {
        // Given
        let mut smaller_set = NonEmptyBTreeSet::new(1);
        smaller_set.insert(2);
        let mut larger_set = NonEmptyBTreeSet::new(3);
        larger_set.insert(4);
        // When / Then
        assert!(smaller_set < larger_set);
    }

    #[test]
    fn clone_produces_equal_independent_copy() {
        // Given
        let mut original = NonEmptyBTreeSet::new(1);
        original.insert(2);
        // When
        let cloned = original.clone();
        // Then
        assert_eq!(original, cloned);
    }
}
