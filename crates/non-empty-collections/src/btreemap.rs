use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// A `BTreeMap` that is guaranteed to contain at least one entry.
#[derive(
    Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, derive_more::Deref, derive_more::Into,
)]
pub struct NonEmptyBTreeMap<K: Ord, V>(BTreeMap<K, V>);

impl<K: Ord, V> NonEmptyBTreeMap<K, V> {
    pub fn new(map: BTreeMap<K, V>) -> Result<Self, EmptyMapError> {
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
        NonEmptyBTreeMap::new(map).map_err(serde::de::Error::custom)
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
        NonEmptyBTreeMap::new(map)
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
    use super::*;
    use assert_matches::assert_matches;
    use rstest::rstest;

    #[rstest]
    #[case::single_entry(BTreeMap::from([(1, "a")]))]
    #[case::multiple_entries(BTreeMap::from([(1, "a"), (2, "b"), (3, "c")]))]
    fn new_succeeds_for_non_empty_map(#[case] non_empty_map: BTreeMap<i32, &str>) {
        // Given
        // When
        let result = NonEmptyBTreeMap::new(non_empty_map.clone());
        // Then
        let non_empty_btree_map = result.unwrap();
        assert_eq!(*non_empty_btree_map, non_empty_map);
    }

    #[test]
    fn new_fails_for_empty_map() {
        // Given
        let empty_map: BTreeMap<i32, &str> = BTreeMap::new();
        // When
        let result = NonEmptyBTreeMap::new(empty_map);
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
            NonEmptyBTreeMap::new(BTreeMap::from([(1, "a"), (2, "b"), (3, "c")])).unwrap();
        // When / Then
        assert!(non_empty_btree_map.contains_key(&1));
        assert!(!non_empty_btree_map.contains_key(&4));
        assert_eq!(non_empty_btree_map.len(), 3);
        assert_eq!(non_empty_btree_map.get(&2), Some(&"b"));
    }

    #[test]
    fn into_converts_back_to_btreemap() {
        // Given
        let original_map = BTreeMap::from([(1, "a"), (2, "b"), (3, "c")]);
        let non_empty_btree_map = NonEmptyBTreeMap::new(original_map.clone()).unwrap();
        // When
        let converted: BTreeMap<i32, &str> = non_empty_btree_map.into();
        // Then
        assert_eq!(converted, original_map);
    }

    #[rstest]
    #[case::single(BTreeMap::from([(42, "x")]))]
    #[case::multiple(BTreeMap::from([(1, "a"), (2, "b"), (3, "c")]))]
    fn serde_json_roundtrip_preserves_data(#[case] map: BTreeMap<i32, &str>) {
        // Given
        let original = NonEmptyBTreeMap::new(map).unwrap();
        // When
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: NonEmptyBTreeMap<i32, String> = serde_json::from_str(&json).unwrap();
        // Then
        assert_eq!(deserialized.len(), original.len());
        for (k, v) in original.iter() {
            assert_eq!(deserialized.get(k).map(|s| s.as_str()), Some(*v));
        }
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
    #[case::single(BTreeMap::from([(42u32, 1u32)]))]
    #[case::multiple(BTreeMap::from([(1u32, 10u32), (2, 20), (3, 30)]))]
    fn borsh_roundtrip_preserves_data(#[case] map: BTreeMap<u32, u32>) {
        // Given
        let original = NonEmptyBTreeMap::new(map).unwrap();
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
    fn eq_returns_true_for_identical_maps() {
        // Given
        let map_a = NonEmptyBTreeMap::new(BTreeMap::from([(1, "a"), (2, "b")])).unwrap();
        let map_b = NonEmptyBTreeMap::new(BTreeMap::from([(1, "a"), (2, "b")])).unwrap();
        // When / Then
        assert_eq!(map_a, map_b);
    }

    #[test]
    fn eq_returns_false_for_different_maps() {
        // Given
        let map_a = NonEmptyBTreeMap::new(BTreeMap::from([(1, "a"), (2, "b")])).unwrap();
        let map_b = NonEmptyBTreeMap::new(BTreeMap::from([(3, "c"), (4, "d")])).unwrap();
        // When / Then
        assert_ne!(map_a, map_b);
    }

    #[test]
    fn ord_compares_by_btreemap_ordering() {
        // Given
        let smaller_map = NonEmptyBTreeMap::new(BTreeMap::from([(1, "a"), (2, "b")])).unwrap();
        let larger_map = NonEmptyBTreeMap::new(BTreeMap::from([(3, "c"), (4, "d")])).unwrap();
        // When / Then
        assert!(smaller_map < larger_map);
    }

    #[test]
    fn clone_produces_equal_independent_copy() {
        // Given
        let original = NonEmptyBTreeMap::new(BTreeMap::from([(1, "a"), (2, "b")])).unwrap();
        // When
        let cloned = original.clone();
        // Then
        assert_eq!(original, cloned);
    }
}
