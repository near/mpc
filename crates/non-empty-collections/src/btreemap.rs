use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::NonEmptyBTreeSet;

/// A `BTreeMap` that is guaranteed to contain at least one entry.
#[derive(
    Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, derive_more::Deref, derive_more::Into,
)]
pub struct NonEmptyBTreeMap<K: Ord, V>(BTreeMap<K, V>);

impl<K: Ord, V> NonEmptyBTreeMap<K, V> {
    pub fn new(key: K, value: V) -> Self {
        Self(BTreeMap::from([(key, value)]))
    }

    /// Transforms both keys and values of this map, producing a new `NonEmptyBTreeMap`.
    ///
    /// Note: if `f` maps multiple keys to the same new key, later entries (by
    /// the original key ordering) will overwrite earlier ones.
    pub fn map<K2, V2, F>(self, mut f: F) -> NonEmptyBTreeMap<K2, V2>
    where
        K2: Ord,
        F: FnMut(K, V) -> (K2, V2),
    {
        let map = self.0.into_iter().map(|(k, v)| f(k, v)).collect();
        // SAFETY: self was non-empty, so the resulting map has at least one entry.
        NonEmptyBTreeMap(map)
    }

    /// Maps each entry to a value and collects into a `NonEmptyBTreeSet`.
    pub fn map_to_set<T, F>(&self, mut f: F) -> NonEmptyBTreeSet<T>
    where
        T: Ord,
        F: FnMut(&K, &V) -> T,
    {
        let set = self.0.iter().map(|(k, v)| f(k, v)).collect();
        // self is non-empty, so the resulting set has at least one element.
        NonEmptyBTreeSet::new_unchecked(set)
    }
}

impl<K: Ord, V> TryFrom<BTreeMap<K, V>> for NonEmptyBTreeMap<K, V> {
    type Error = EmptyMapError;

    fn try_from(map: BTreeMap<K, V>) -> Result<Self, Self::Error> {
        if map.is_empty() {
            Err(EmptyMapError)
        } else {
            Ok(Self(map))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmptyMapError;

impl std::fmt::Display for EmptyMapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "map must contain at least one entry")
    }
}

impl<K: Ord + Serialize, V: Serialize> Serialize for NonEmptyBTreeMap<K, V> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, K: Ord + Deserialize<'de>, V: Deserialize<'de>> Deserialize<'de>
    for NonEmptyBTreeMap<K, V>
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let map = BTreeMap::<K, V>::deserialize(deserializer)?;
        NonEmptyBTreeMap::try_from(map).map_err(serde::de::Error::custom)
    }
}

impl<K: Ord + BorshSerialize, V: BorshSerialize> BorshSerialize for NonEmptyBTreeMap<K, V> {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.0.serialize(writer)
    }
}

impl<K: Ord + BorshDeserialize, V: BorshDeserialize> BorshDeserialize for NonEmptyBTreeMap<K, V> {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let map = BTreeMap::<K, V>::deserialize_reader(reader)?;
        NonEmptyBTreeMap::try_from(map)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }
}

#[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
impl<K: Ord + schemars::JsonSchema, V: schemars::JsonSchema> schemars::JsonSchema
    for NonEmptyBTreeMap<K, V>
{
    fn schema_name() -> String {
        format!("NonEmptyBTreeMap_{}_{}", K::schema_name(), V::schema_name())
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        // Reuse BTreeMap's schema with minProperties: 1
        let mut schema = <BTreeMap<K, V>>::json_schema(generator);
        if let schemars::schema::Schema::Object(ref mut obj) = schema {
            if let Some(ref mut object) = obj.object {
                object.min_properties = Some(1);
            }
        }
        schema
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use assert_matches::assert_matches;
    use rstest::rstest;

    #[test]
    fn new_creates_single_entry_map() {
        // Given / When
        let map = NonEmptyBTreeMap::new(1, "a");
        // Then
        assert_eq!(map.len(), 1);
        assert_eq!(map.get(&1), Some(&"a"));
    }

    #[test]
    fn try_from_succeeds_for_non_empty_map() {
        // Given
        let btree = BTreeMap::from([(1, "a"), (2, "b")]);
        // When
        let result = NonEmptyBTreeMap::try_from(btree.clone());
        // Then
        let map = result.unwrap();
        assert_eq!(*map, btree);
    }

    #[test]
    fn try_from_fails_for_empty_map() {
        // Given
        let empty: BTreeMap<i32, &str> = BTreeMap::new();
        // When
        let result = NonEmptyBTreeMap::try_from(empty);
        // Then
        assert_eq!(result.unwrap_err(), EmptyMapError);
    }

    #[test]
    fn empty_map_error_displays_message() {
        // Given
        // When
        // Then
        assert_eq!(
            EmptyMapError.to_string(),
            "map must contain at least one entry"
        );
    }

    #[test]
    fn deref_exposes_btreemap_methods() {
        // Given
        let non_empty_btree_map =
            NonEmptyBTreeMap::try_from(BTreeMap::from([(1, "a"), (2, "b"), (3, "c")])).unwrap();
        // When / Then
        assert!(non_empty_btree_map.contains_key(&1));
        assert!(!non_empty_btree_map.contains_key(&4));
        assert_eq!(non_empty_btree_map.len(), 3);
        assert_eq!(non_empty_btree_map.get(&2), Some(&"b"));
    }

    #[test]
    fn into_converts_back_to_btreemap() {
        // Given
        let mut map = NonEmptyBTreeMap::new(1, "a");
        map.0.insert(2, "b");
        map.0.insert(3, "c");
        let expected = BTreeMap::from([(1, "a"), (2, "b"), (3, "c")]);
        // When
        let converted: BTreeMap<i32, &str> = map.into();
        // Then
        assert_eq!(converted, expected);
    }

    #[rstest]
    #[case::single(42, "x")]
    #[case::multiple(1, "a")]
    fn serde_json_roundtrip_preserves_data(#[case] first_key: i32, #[case] first_val: &str) {
        // Given
        let mut original = NonEmptyBTreeMap::new(first_key, first_val.to_string());
        if first_key == 1 {
            original.0.insert(2, "b".to_string());
            original.0.insert(3, "c".to_string());
        }
        // When
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: NonEmptyBTreeMap<i32, String> = serde_json::from_str(&json).unwrap();
        // Then
        assert_eq!(deserialized, original);
    }

    #[test]
    fn serde_json_deserialize_rejects_empty_object() {
        // Given
        let empty_json_object = "{}";
        // When
        let result: Result<NonEmptyBTreeMap<String, i32>, _> =
            serde_json::from_str(empty_json_object);
        // Then
        assert_matches!(result, Err(_));
    }

    #[rstest]
    #[case::single(42u32, 1u32)]
    #[case::multiple(1u32, 10u32)]
    fn borsh_roundtrip_preserves_data(#[case] first_key: u32, #[case] first_val: u32) {
        // Given
        let mut original = NonEmptyBTreeMap::new(first_key, first_val);
        if first_key == 1 {
            original.0.insert(2, 20);
            original.0.insert(3, 30);
        }
        // When
        let bytes = borsh::to_vec(&original).unwrap();
        let deserialized: NonEmptyBTreeMap<u32, u32> =
            BorshDeserialize::try_from_slice(&bytes).unwrap();
        // Then
        assert_eq!(deserialized, original);
    }

    #[test]
    fn borsh_deserialize_rejects_empty_map() {
        // Given
        let empty_map_bytes = borsh::to_vec(&BTreeMap::<u32, u32>::new()).unwrap();
        // When
        let result: Result<NonEmptyBTreeMap<u32, u32>, _> =
            BorshDeserialize::try_from_slice(&empty_map_bytes);
        // Then
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn map_transforms_keys_and_values() {
        // Given
        let original =
            NonEmptyBTreeMap::try_from(BTreeMap::from([(1, 10), (2, 20), (3, 30)])).unwrap();
        // When
        let mapped = original.map(|k, v| (k * 10, v * 2));
        // Then
        assert_eq!(*mapped, BTreeMap::from([(10, 20), (20, 40), (30, 60)]));
    }

    #[test]
    fn map_changes_key_and_value_types() {
        // Given
        let original = NonEmptyBTreeMap::try_from(BTreeMap::from([(1, 10), (2, 20)])).unwrap();
        // When
        let mapped: NonEmptyBTreeMap<String, String> =
            original.map(|k, v| (k.to_string(), v.to_string()));
        // Then
        assert_eq!(
            *mapped,
            BTreeMap::from([
                ("1".to_string(), "10".to_string()),
                ("2".to_string(), "20".to_string())
            ])
        );
    }

    #[test]
    fn map_preserves_values_only() {
        // Given
        let original =
            NonEmptyBTreeMap::try_from(BTreeMap::from([(1, 10), (2, 20), (3, 30)])).unwrap();
        // When
        let mapped = original.map(|k, v| (k, v * 2));
        // Then
        assert_eq!(*mapped, BTreeMap::from([(1, 20), (2, 40), (3, 60)]));
    }

    #[test]
    fn map_to_set_collects_into_non_empty_set() {
        // Given
        let original =
            NonEmptyBTreeMap::try_from(BTreeMap::from([(1, "a"), (2, "b"), (3, "c")])).unwrap();
        // When
        let set = original.map_to_set(|k, v| format!("{k}:{v}"));
        // Then
        assert_eq!(
            *set,
            BTreeSet::from(["1:a".to_string(), "2:b".to_string(), "3:c".to_string()])
        );
    }

    #[test]
    fn eq_returns_true_for_identical_maps() {
        // Given
        let mut map_a = NonEmptyBTreeMap::new(1, "a");
        map_a.0.insert(2, "b");
        let mut map_b = NonEmptyBTreeMap::new(1, "a");
        map_b.0.insert(2, "b");
        // When / Then
        assert_eq!(map_a, map_b);
    }

    #[test]
    fn eq_returns_false_for_different_maps() {
        // Given
        let mut map_a = NonEmptyBTreeMap::new(1, "a");
        map_a.0.insert(2, "b");
        let mut map_b = NonEmptyBTreeMap::new(3, "c");
        map_b.0.insert(4, "d");
        // When / Then
        assert_ne!(map_a, map_b);
    }

    #[test]
    fn ord_compares_by_btreemap_ordering() {
        // Given
        let mut smaller_map = NonEmptyBTreeMap::new(1, "a");
        smaller_map.0.insert(2, "b");
        let mut larger_map = NonEmptyBTreeMap::new(3, "c");
        larger_map.0.insert(4, "d");
        // When / Then
        assert!(smaller_map < larger_map);
    }

    #[test]
    fn clone_produces_equal_independent_copy() {
        // Given
        let mut original = NonEmptyBTreeMap::new(1, "a");
        original.0.insert(2, "b");
        // When
        let cloned = original.clone();
        // Then
        assert_eq!(original, cloned);
    }
}
