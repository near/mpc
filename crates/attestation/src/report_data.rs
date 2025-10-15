use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::{AsRef, Deref, From};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_384};

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

#[derive(Debug, Clone)]
pub struct ReportDataV1 {
    tls_public_key: Ed25519PublicKey,
    account_public_key: Ed25519PublicKey,
}

#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Deref,
    AsRef,
    From,
    Serialize,
    Deserialize,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct Ed25519PublicKey([u8; 32]);

impl core::borrow::Borrow<[u8]> for Ed25519PublicKey {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

/// report_data_v1: [u8; 64] =
/// [version(2 bytes big endian) || sha384(TLS pub key || account_pubkey) || zero padding]
impl ReportDataV1 {
    /// V1-specific format constants
    const PUBLIC_KEYS_OFFSET: usize = BINARY_VERSION_OFFSET + BINARY_VERSION_SIZE;
    const PUBLIC_KEYS_HASH_SIZE: usize = 48;

    pub fn new(
        tls_public_key: impl Into<Ed25519PublicKey>,
        account_public_key: impl Into<Ed25519PublicKey>,
    ) -> Self {
        Self {
            tls_public_key: tls_public_key.into(),
            account_public_key: account_public_key.into(),
        }
    }

    // Compile-time assertions for V1 format.
    const _V1_LAYOUT_CHECK: () = {
        assert!(
            BINARY_VERSION_SIZE + Self::PUBLIC_KEYS_HASH_SIZE <= REPORT_DATA_SIZE,
            "V1: Version and public key must not exceed report data size."
        );
    };

    /// Computes a SHA3-384 hash over two public keys.
    ///
    /// Returns and arraySha384 (tls_public_key || account_public_key)
    fn compute_public_keys_hash(
        tls_public_key: impl AsRef<[u8]>,
        account_public_key: impl AsRef<[u8]>,
    ) -> [u8; 48] {
        let mut hasher = Sha3_384::new();
        hasher.update(tls_public_key.as_ref());
        hasher.update(account_public_key.as_ref());
        hasher.finalize().into()
    }

    // Hash both TLS and account public keys and return the hash.
    pub fn to_bytes(&self) -> [u8; REPORT_DATA_SIZE] {
        let mut report_data = [0u8; REPORT_DATA_SIZE];

        // Copy binary version (2 bytes, big endian)
        let version_bytes = ReportDataVersion::V1.to_be_bytes();
        report_data[BINARY_VERSION_OFFSET..BINARY_VERSION_OFFSET + BINARY_VERSION_SIZE]
            .copy_from_slice(&version_bytes);

        let public_keys_hash = Self::compute_public_keys_hash(
            self.tls_public_key.as_ref(),
            self.account_public_key.as_ref(),
        );

        report_data
            [Self::PUBLIC_KEYS_OFFSET..Self::PUBLIC_KEYS_OFFSET + Self::PUBLIC_KEYS_HASH_SIZE]
            .copy_from_slice(&public_keys_hash);

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
}

#[derive(Debug, Clone)]
pub enum ReportData {
    V1(ReportDataV1),
}
impl ReportData {
    /// Creates a new ReportData instance.
    ///
    /// * `tls_public_key`: The TLS key of the MPC node
    /// * `account_public_key`: The NEAR account signing key
    pub fn new(
        tls_public_key: impl Into<Ed25519PublicKey>,
        account_public_key: impl Into<Ed25519PublicKey>,
    ) -> Self {
        ReportData::V1(ReportDataV1::new(
            tls_public_key.into(),
            account_public_key.into(),
        ))
    }

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
    use test_utils::attestation::{account_key, p2p_tls_key, quote};

    #[test]
    #[ignore] // TODO(#1269): update quote from node
    fn test_from_str_valid() {
        let valid_quote: Vec<u8> =
            serde_json::from_str(&serde_json::to_string(&quote()).unwrap()).unwrap();
        let quote = Quote::parse(&valid_quote).unwrap();

        let td_report = quote.report.as_td10().expect("Should be a TD 1.0 report");

        let p2p_tls_public_key = p2p_tls_key();
        let account_key = account_key();
        let report_data = ReportData::V1(ReportDataV1::new(p2p_tls_public_key, account_key));
        assert_eq!(report_data.to_bytes(), td_report.report_data);
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
        let tls_key = p2p_tls_key();
        let account_key = account_key();
        let data = ReportData::V1(ReportDataV1::new(tls_key, account_key));

        let ReportData::V1(v1) = &data;
        assert_eq!(data.version(), ReportDataVersion::V1);
        assert_eq!(v1.tls_public_key, Ed25519PublicKey(tls_key));
        assert_eq!(v1.account_public_key, Ed25519PublicKey(account_key));
    }

    #[test]
    fn test_report_data_v1_struct() {
        let tls_key = p2p_tls_key();
        let account_key = account_key();

        let v1 = ReportDataV1::new(tls_key, account_key);
        assert_eq!(v1.tls_public_key, Ed25519PublicKey(tls_key));
        assert_eq!(v1.account_public_key, Ed25519PublicKey(account_key));
    }

    #[test]
    fn test_from_bytes() {
        let tls_key = p2p_tls_key();
        let account_key = account_key();
        let report_data_v1 = ReportDataV1::new(tls_key, account_key);
        let bytes = report_data_v1.to_bytes();

        let hash = ReportDataV1::from_bytes(&bytes);

        // Expected hash = sha3_384(tls_key || account_key)
        let public_keys_hash = ReportDataV1::compute_public_keys_hash(
            report_data_v1.tls_public_key.as_ref(),
            report_data_v1.account_public_key.as_ref(),
        );

        assert_eq!(hash, public_keys_hash);

        let report_data = ReportData::V1(report_data_v1);
        assert_eq!(report_data.to_bytes(), bytes);
    }

    #[test]
    fn test_binary_version_placement() {
        let tls_key = p2p_tls_key();
        let account_key = account_key();
        let bytes = ReportDataV1::new(tls_key, account_key).to_bytes();

        let version_bytes =
            &bytes[BINARY_VERSION_OFFSET..BINARY_VERSION_OFFSET + BINARY_VERSION_SIZE];
        assert_eq!(version_bytes, &[0, 1]);
    }

    #[test]
    fn test_public_key_hash_placement() {
        let tls_key = p2p_tls_key();
        let account_key = account_key();
        let report_data_v1 = ReportDataV1::new(tls_key, account_key);
        let bytes = report_data_v1.to_bytes();

        let report_data = ReportData::V1(report_data_v1.clone());
        assert_eq!(report_data.to_bytes(), bytes);

        let hash_bytes = &bytes[ReportDataV1::PUBLIC_KEYS_OFFSET
            ..ReportDataV1::PUBLIC_KEYS_OFFSET + ReportDataV1::PUBLIC_KEYS_HASH_SIZE];
        assert_ne!(hash_bytes, &[0u8; ReportDataV1::PUBLIC_KEYS_HASH_SIZE]);

        // Expected hash = sha3_384(tls_key || account_key)
        let expected =
            ReportDataV1::compute_public_keys_hash(tls_key.as_ref(), account_key.as_ref());

        assert_eq!(hash_bytes, &expected);
    }

    #[test]
    fn test_zero_padding() {
        let tls_key = p2p_tls_key();
        let account_key = account_key();
        let bytes = ReportDataV1::new(tls_key, account_key).to_bytes();

        let padding =
            &bytes[ReportDataV1::PUBLIC_KEYS_OFFSET + ReportDataV1::PUBLIC_KEYS_HASH_SIZE..];
        assert!(padding.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_report_data_size() {
        let tls_key = p2p_tls_key();
        let account_key = account_key();
        let bytes = ReportDataV1::new(tls_key, account_key);
        assert_eq!(bytes.to_bytes().len(), REPORT_DATA_SIZE);
    }
}
