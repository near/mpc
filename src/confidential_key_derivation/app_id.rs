use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::errors::ProtocolError;

/// Represents a unique identifier for an application in the confidential key derivation protocol
#[derive(Clone, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub struct AppId(Arc<[u8]>);

// Maximum allowed length for AppId to prevent DoS attacks during deserialization.
const MAX_APP_ID_LEN: usize = 10_000;

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
        Self::try_new(v).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<Vec<u8>> for AppId {
    type Error = ProtocolError;

    fn try_from(id: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_new(id)
    }
}

impl<'a> TryFrom<&'a [u8]> for AppId {
    type Error = ProtocolError;

    fn try_from(id: &'a [u8]) -> Result<Self, Self::Error> {
        Self::try_new(id)
    }
}

impl<'a, const N: usize> TryFrom<&'a [u8; N]> for AppId {
    type Error = ProtocolError;

    fn try_from(id: &'a [u8; N]) -> Result<Self, Self::Error> {
        Self::try_new(id)
    }
}

impl AppId {
    pub fn try_new(id: impl AsRef<[u8]>) -> Result<Self, ProtocolError> {
        let id = id.as_ref();
        if id.len() > MAX_APP_ID_LEN {
            let err_msg = format!(
                "AppId length ({}) exceeds maximum allowed length ({})",
                id.len(),
                MAX_APP_ID_LEN
            );
            return Err(ProtocolError::InvalidInput(err_msg));
        }
        Ok(Self(Arc::from(id)))
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
        let bytes_len = u32::try_from(bytes.len()).map_err(|_| std::io::ErrorKind::InvalidInput)?;
        borsh::BorshSerialize::serialize(&bytes_len, writer)?;
        writer.write_all(bytes)
    }
}

impl BorshDeserialize for AppId {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let len = u32::deserialize_reader(reader)? as usize;

        if len > MAX_APP_ID_LEN {
            let err_msg =
                format!("AppId length ({len}) exceeds maximum allowed length ({MAX_APP_ID_LEN})");

            let protocol_error = ProtocolError::DeserializationError(err_msg);

            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                protocol_error,
            ));
        }
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        Self::try_from(buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode::config;
    use bincode::serde::{decode_from_slice, encode_to_vec};
    use rand_core::{OsRng, RngCore};
    use std::borrow::Borrow;
    use std::collections::HashMap;

    #[test]
    fn test_app_id_display() {
        let bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let app_id = AppId::try_new(bytes.clone()).unwrap();
        assert_eq!(app_id.to_string(), "deadbeef");
        assert_eq!(app_id.as_bytes(), &bytes[..]);
    }

    #[test]
    fn test_serde_json_roundtrip() {
        let bytes = vec![0x01, 0x02, 0x03, 0x04];
        let original = AppId::try_new(bytes.clone()).unwrap();

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
            let original = AppId::try_new(bytes.clone()).unwrap();
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
        let original = AppId::try_new(large_bytes.clone()).unwrap();
        let mut buf = vec![];
        borsh::BorshSerialize::serialize(&original, &mut buf).unwrap();
        let decoded = AppId::deserialize_reader(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.as_bytes(), &large_bytes[..]);
    }

    #[test]
    fn test_bincode_roundtrip() {
        let test_bytes = vec![0xAB, 0xCD, 0xEF];
        let original = AppId::try_new(test_bytes.clone()).unwrap();

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
    fn test_borsh_dos_attack() {
        // This is a malicious payload that specifies a length of u32::MAX,
        // which would cause a huge allocation.
        let mut malicious_payload = Vec::new();
        borsh::BorshSerialize::serialize(&u32::MAX, &mut malicious_payload).unwrap();

        // Try to deserialize it. This should fail.
        let result = AppId::deserialize_reader(&mut malicious_payload.as_slice());
        assert!(result.is_err());
    }

    #[test]
    fn test_deref_and_borrow() {
        let bytes = vec![0x01, 0x02, 0x03];
        let app_id = AppId::try_new(bytes.clone()).unwrap();

        // Test Deref
        assert_eq!(&*app_id, bytes.as_slice());
        assert_eq!(app_id.len(), 3); // accessing slice method through Deref

        // Test Borrow
        let borrowed: &[u8] = app_id.borrow();
        assert_eq!(borrowed, bytes.as_slice());

        // Test in a hash map context
        let mut map = HashMap::new();
        map.insert(app_id.clone(), "value");

        // Can look up with &[u8] because of Borrow implementation
        assert_eq!(map.get(bytes.as_slice()), Some(&"value"));
    }
}
