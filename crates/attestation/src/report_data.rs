use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::Constructor;
use near_sdk::PublicKey;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_384};

#[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
use alloc::string::ToString;

/// Number of bytes for the report data.
const REPORT_DATA_SIZE: usize = 64;

/// Common constants for all [`ReportData`] versions.
const BINARY_VERSION_OFFSET: usize = 0;
const BINARY_VERSION_SIZE: usize = 2;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
#[borsh(use_discriminant = true)]
#[repr(u16)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub enum ReportDataVersion {
    V1 = 1,
}

impl ReportDataVersion {
    pub fn to_be_bytes(self) -> [u8; BINARY_VERSION_SIZE] {
        (self as u16).to_be_bytes()
    }

    pub fn from_be_bytes(bytes: [u8; BINARY_VERSION_SIZE]) -> Option<Self> {
        match u16::from_be_bytes(bytes) {
            1 => Some(Self::V1),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Constructor)]
pub struct ReportDataV1 {
    tls_public_key: PublicKey,
}

/// report_data_v1: [u8; 64] =
///   [version(2 bytes big endian) || sha384(TLS pub key) || zero padding]
impl ReportDataV1 {
    /// V1-specific format constants
    const PUBLIC_KEYS_OFFSET: usize = BINARY_VERSION_OFFSET + BINARY_VERSION_SIZE;
    const PUBLIC_KEYS_HASH_SIZE: usize = 48;

    // Compile-time assertions for V1 format.
    const _V1_LAYOUT_CHECK: () = {
        assert!(
            BINARY_VERSION_SIZE + Self::PUBLIC_KEYS_HASH_SIZE <= REPORT_DATA_SIZE,
            "V1: Version and public key must not exceed report data size."
        );
    };

    /// Generates the binary representation of V1 report data.
    pub fn to_bytes(&self) -> [u8; REPORT_DATA_SIZE] {
        let mut report_data = [0u8; REPORT_DATA_SIZE];

        // Copy binary version (2 bytes, big endian)
        let version_bytes = ReportDataVersion::V1.to_be_bytes();
        report_data[BINARY_VERSION_OFFSET..BINARY_VERSION_OFFSET + BINARY_VERSION_SIZE]
            .copy_from_slice(&version_bytes);

        // Generate and copy hash of public keys
        let public_keys_hash = self.public_keys_hash();
        report_data
            [Self::PUBLIC_KEYS_OFFSET..Self::PUBLIC_KEYS_OFFSET + Self::PUBLIC_KEYS_HASH_SIZE]
            .copy_from_slice(&public_keys_hash);

        // Remaining bytes are already zero-padded by default
        report_data
    }

    /// Parses V1 report data from bytes. Returns the hash of public keys.
    /// Note: This only extracts the hash, not the original public keys.
    pub fn from_bytes(bytes: &[u8; REPORT_DATA_SIZE]) -> [u8; Self::PUBLIC_KEYS_HASH_SIZE] {
        // Extract hash using V1 format
        let mut hash = [0u8; Self::PUBLIC_KEYS_HASH_SIZE];
        hash.copy_from_slice(
            &bytes
                [Self::PUBLIC_KEYS_OFFSET..Self::PUBLIC_KEYS_OFFSET + Self::PUBLIC_KEYS_HASH_SIZE],
        );
        hash
    }

    /// Generates SHA3-384 hash of TLS public key only.
    fn public_keys_hash(&self) -> [u8; Self::PUBLIC_KEYS_HASH_SIZE] {
        let mut hasher = Sha3_384::new();
        // Skip first byte as it is used for identifier for the curve type.
        let key_data = &self.tls_public_key.as_bytes()[1..];
        hasher.update(key_data);
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone)]
pub enum ReportData {
    V1(ReportDataV1),
}

impl ReportData {
    pub fn version(&self) -> ReportDataVersion {
        match self {
            ReportData::V1(_) => ReportDataVersion::V1,
        }
    }

    /// Generates the binary representation of report data.
    pub fn to_bytes(&self) -> [u8; REPORT_DATA_SIZE] {
        match self {
            ReportData::V1(v1) => v1.to_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report_data::ReportData;
    use alloc::vec::Vec;
    use dcap_qvl::quote::Quote;
    use near_sdk::PublicKey;
    use test_utils::attestation::{p2p_tls_key, quote};

    #[test]
    fn test_from_str_valid() {
        let valid_quote: Vec<u8> =
            serde_json::from_str(&serde_json::to_string(&quote()).unwrap()).unwrap();
        let quote = Quote::parse(&valid_quote).unwrap();

        let td_report = quote.report.as_td10().expect("Should be a TD 1.0 report");

        let near_p2p_public_key: PublicKey = p2p_tls_key();
        let report_data = ReportData::V1(ReportDataV1::new(near_p2p_public_key));
        assert_eq!(report_data.to_bytes(), td_report.report_data,);
    }

    fn create_test_key() -> PublicKey {
        "secp256k1:qMoRgcoXai4mBPsdbHi1wfyxF9TdbPCF4qSDQTRP3TfescSRoUdSx6nmeQoN3aiwGzwMyGXAb1gUjBTv5AY8DXj"
            .parse()
            .unwrap()
    }

    #[test]
    fn test_binary_version_serialization() {
        let version = ReportDataVersion::V1;
        assert_eq!(version.to_be_bytes(), [0, 1]);

        let parsed = ReportDataVersion::from_be_bytes([0, 1]).unwrap();
        assert_eq!(parsed, ReportDataVersion::V1);

        assert!(ReportDataVersion::from_be_bytes([0, 2]).is_none());
    }

    #[test]
    fn test_report_data_enum_structure() {
        let tls_key = create_test_key();
        let data = ReportData::V1(ReportDataV1::new(tls_key.clone()));

        match &data {
            ReportData::V1(v1) => {
                assert_eq!(&v1.tls_public_key, &tls_key);
            }
        }

        assert_eq!(data.version(), ReportDataVersion::V1);
    }

    #[test]
    fn test_report_data_v1_struct() {
        let tls_key = create_test_key();

        let v1 = ReportDataV1::new(tls_key.clone());
        assert_eq!(v1.tls_public_key, tls_key);
    }

    #[test]
    fn test_from_bytes() {
        let tls_key = create_test_key();
        let report_data_v1 = ReportDataV1::new(tls_key);
        let bytes = report_data_v1.to_bytes();

        let hash = ReportDataV1::from_bytes(&bytes);
        assert_eq!(hash, report_data_v1.public_keys_hash());

        let report_data = ReportData::V1(report_data_v1);
        assert_eq!(report_data.to_bytes(), bytes);
    }

    #[test]
    fn test_binary_version_placement() {
        let tls_key = create_test_key();
        let bytes = ReportDataV1::new(tls_key).to_bytes();

        let version_bytes =
            &bytes[BINARY_VERSION_OFFSET..BINARY_VERSION_OFFSET + BINARY_VERSION_SIZE];
        assert_eq!(version_bytes, &[0, 1]);
    }

    #[test]
    fn test_public_key_hash_placement() {
        let tls_key = create_test_key();
        let report_data_v1 = ReportDataV1::new(tls_key.clone());
        let bytes = report_data_v1.to_bytes();

        let report_data = ReportData::V1(report_data_v1);
        assert_eq!(report_data.to_bytes(), bytes);

        let hash_bytes = &bytes[ReportDataV1::PUBLIC_KEYS_OFFSET
            ..ReportDataV1::PUBLIC_KEYS_OFFSET + ReportDataV1::PUBLIC_KEYS_HASH_SIZE];
        assert_ne!(hash_bytes, &[0u8; ReportDataV1::PUBLIC_KEYS_HASH_SIZE]);

        let mut hasher = Sha3_384::new();
        // Skip first byte as it is used for identifier for the curve type.
        let key_data = &tls_key.as_bytes()[1..];
        hasher.update(key_data);
        let expected: [u8; ReportDataV1::PUBLIC_KEYS_HASH_SIZE] = hasher.finalize().into();

        assert_eq!(hash_bytes, &expected);
    }

    #[test]
    fn test_zero_padding() {
        let tls_key = create_test_key();
        let bytes = ReportDataV1::new(tls_key).to_bytes();

        let padding =
            &bytes[ReportDataV1::PUBLIC_KEYS_OFFSET + ReportDataV1::PUBLIC_KEYS_HASH_SIZE..];
        assert!(padding.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_report_data_size() {
        let tls_key = create_test_key();
        let bytes = ReportDataV1::new(tls_key);
        assert_eq!(bytes.to_bytes().len(), REPORT_DATA_SIZE);
    }
}
