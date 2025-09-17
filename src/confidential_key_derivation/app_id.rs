use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Represents a unique identifier for an application in the confidential key derivation protocol
#[derive(Clone, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub struct AppId(Arc<[u8]>);

impl Serialize for AppId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_bytes::Serialize::serialize(&self.0[..], serializer)
    }
}

impl<'de> Deserialize<'de> for AppId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v: Vec<u8> = serde_bytes::Deserialize::deserialize(deserializer)?;
        Ok(AppId(Arc::from(v)))
    }
}

impl From<Vec<u8>> for AppId {
    fn from(id: Vec<u8>) -> Self {
        Self(Arc::from(id))
    }
}

impl<'a> From<&'a [u8]> for AppId {
    fn from(id: &'a [u8]) -> Self {
        Self(Arc::from(id))
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for AppId {
    fn from(id: &'a [u8; N]) -> Self {
        Self(Arc::from(&id[..]))
    }
}

impl AppId {
    pub fn new(id: impl AsRef<[u8]>) -> Self {
        Self(Arc::from(id.as_ref()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Arc<[u8]> {
        self.0
    }
}

impl AsRef<[u8]> for AppId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::Deref for AppId {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::borrow::Borrow<[u8]> for AppId {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for AppId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.as_bytes()))
    }
}

impl BorshSerialize for AppId {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // serialize as Vec<u8>
        let bytes: &[u8] = &self.0;
        borsh::BorshSerialize::serialize(&(bytes.len() as u32), writer)?;
        writer.write_all(bytes)
    }
}

impl BorshDeserialize for AppId {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let len = u32::deserialize_reader(reader)? as usize;
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        Ok(AppId::from(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode::config;
    use bincode::serde::{decode_from_slice, encode_to_vec};
    use rand_core::{OsRng, RngCore};

    #[test]
    fn test_app_id_display() {
        let bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let app_id = AppId::new(bytes.clone());
        assert_eq!(app_id.to_string(), "deadbeef");
        assert_eq!(app_id.as_bytes(), &bytes[..]);
    }

    #[test]
    fn test_serde_json_roundtrip() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04];
        let original = AppId::new(bytes.clone());

        let json = serde_json::to_string(&original).unwrap();
        let decoded: AppId = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, original);
        assert_eq!(decoded.as_bytes(), &bytes[..]);
    }

    #[test]
    fn test_borsh_roundtrip() {
        let test_cases = vec![
            vec![],                        // empty
            vec![0x01],                    // single byte
            vec![0xDE, 0xAD, 0xBE, 0xEF],  // normal
            (0..255).collect::<Vec<u8>>(), // moderate size
        ];

        for bytes in test_cases {
            let original = AppId::new(bytes.clone());
            let mut buf = vec![];
            borsh::BorshSerialize::serialize(&original, &mut buf).unwrap();

            let decoded = AppId::deserialize_reader(&mut buf.as_slice()).unwrap();
            assert_eq!(decoded, original);
            assert_eq!(decoded.as_bytes(), &bytes[..]);
        }

        // Very large random array
        let rng = &mut OsRng;
        let mut large_bytes = vec![0u8; 10_000];
        rng.fill_bytes(&mut large_bytes);
        let original = AppId::new(large_bytes.clone());
        let mut buf = vec![];
        borsh::BorshSerialize::serialize(&original, &mut buf).unwrap();
        let decoded = AppId::deserialize_reader(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.as_bytes(), &large_bytes[..]);
    }

    #[test]
    fn test_bincode_roundtrip() {
        let test_bytes = vec![0xAB, 0xCD, 0xEF];
        let original = AppId::new(test_bytes.clone());

        // Encode using bincode's binary format
        let encoded = encode_to_vec(&original, config::standard()).expect("bincode encode");

        // Decode back into AppId
        let (decoded, _len): (AppId, usize) =
            decode_from_slice(&encoded, config::standard()).expect("bincode decode");

        assert_eq!(decoded, original);
        assert_eq!(decoded.as_bytes(), &test_bytes[..]);
    }

    #[test]
    fn test_failure_cases() {
        // Corrupted Borsh data
        let corrupted = vec![0, 1]; // length prefix too short
        assert!(AppId::deserialize_reader(&mut corrupted.as_slice()).is_err());

        let corrupted_long = vec![0xFF; 5]; // invalid length prefix
        assert!(AppId::deserialize_reader(&mut corrupted_long.as_slice()).is_err());

        // Corrupted JSON
        let invalid_json = "{ invalid json }";
        let result: Result<AppId, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deref_and_borrow() {
        let bytes = vec![0x01, 0x02, 0x03];
        let app_id = AppId::new(bytes.clone());

        // Test Deref
        assert_eq!(&*app_id, bytes.as_slice());
        assert_eq!(app_id.len(), 3); // accessing slice method through Deref

        // Test Borrow
        use std::borrow::Borrow;
        let borrowed: &[u8] = app_id.borrow();
        assert_eq!(borrowed, bytes.as_slice());

        // Test in a hash map context
        use std::collections::HashMap;
        let mut map = HashMap::new();
        map.insert(app_id.clone(), "value");

        // Can look up with &[u8] because of Borrow implementation
        assert_eq!(map.get(bytes.as_slice()), Some(&"value"));
    }
}
