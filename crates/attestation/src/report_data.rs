use interfaces::{
    attestation::{ReportData, ReportDataV1, ReportDataVersion},
    crypto::Ed25519PublicKey,
};
use sha3::{Digest, Sha3_384};

/// Number of bytes for the report data.
const REPORT_DATA_SIZE: usize = 64;

/// Common constants for all [`ReportData`] versions.
const BINARY_VERSION_OFFSET: usize = 0;
const BINARY_VERSION_SIZE: usize = 2;
const PUBLIC_KEYS_HASH_SIZE: usize = 48;

// Compile-time assertions for V1 format.
const _V1_LAYOUT_CHECK: () = {
    assert!(
        BINARY_VERSION_SIZE + PUBLIC_KEYS_HASH_SIZE <= REPORT_DATA_SIZE,
        "V1: Version and public key must not exceed report data size."
    );
};

/// V1-specific format constants
const PUBLIC_KEYS_OFFSET: usize = BINARY_VERSION_OFFSET + BINARY_VERSION_SIZE;

pub trait ReportDataV1Ext {
    fn to_bytes(&self) -> [u8; REPORT_DATA_SIZE];
    fn from_bytes(bytes: &[u8; REPORT_DATA_SIZE]) -> [u8; PUBLIC_KEYS_HASH_SIZE];
    fn public_keys_hash(&self) -> [u8; PUBLIC_KEYS_HASH_SIZE];
}

/// report_data_v1: [u8; 64] =
///   [version(2 bytes big endian) || sha384(TLS pub key) || zero padding]
impl ReportDataV1Ext for ReportDataV1 {
    /// Generates the binary representation of V1 report data.
    fn to_bytes(&self) -> [u8; REPORT_DATA_SIZE] {
        let mut report_data = [0u8; REPORT_DATA_SIZE];

        // Copy binary version (2 bytes, big endian)
        let version_bytes = ReportDataVersion::V1.to_be_bytes();
        report_data[BINARY_VERSION_OFFSET..BINARY_VERSION_OFFSET + BINARY_VERSION_SIZE]
            .copy_from_slice(&version_bytes);

        // Generate and copy hash of public keys
        let public_keys_hash = self.public_keys_hash();
        report_data[PUBLIC_KEYS_OFFSET..PUBLIC_KEYS_OFFSET + PUBLIC_KEYS_HASH_SIZE]
            .copy_from_slice(&public_keys_hash);

        // Remaining bytes are already zero-padded by default
        report_data
    }

    /// Parses V1 report data from bytes. Returns the hash of public keys.
    /// Note: This only extracts the hash, not the original public keys.
    fn from_bytes(bytes: &[u8; REPORT_DATA_SIZE]) -> [u8; PUBLIC_KEYS_HASH_SIZE] {
        // Extract hash using V1 format
        let mut hash = [0u8; PUBLIC_KEYS_HASH_SIZE];
        hash.copy_from_slice(
            &bytes[PUBLIC_KEYS_OFFSET..PUBLIC_KEYS_OFFSET + PUBLIC_KEYS_HASH_SIZE],
        );
        hash
    }

    /// Generates SHA3-384 hash of TLS public key only.
    fn public_keys_hash(&self) -> [u8; PUBLIC_KEYS_HASH_SIZE] {
        let mut hasher = Sha3_384::new();
        hasher.update(&self.tls_public_key);
        hasher.finalize().into()
    }
}

pub trait ReportDataExt {
    fn new(tls_public_key: Ed25519PublicKey) -> Self;
    fn version(&self) -> ReportDataVersion;
    fn to_bytes(&self) -> [u8; REPORT_DATA_SIZE];
}

impl ReportDataExt for ReportData {
    fn new(tls_public_key: Ed25519PublicKey) -> Self {
        ReportData::V1(ReportDataV1::new(tls_public_key))
    }

    fn version(&self) -> ReportDataVersion {
        match self {
            ReportData::V1(_) => ReportDataVersion::V1,
        }
    }

    /// Generates the binary representation of report data.
    fn to_bytes(&self) -> [u8; REPORT_DATA_SIZE] {
        match self {
            ReportData::V1(v1) => v1.to_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let tls_key: Ed25519PublicKey = [0; 32].into();
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
        let tls_key: Ed25519PublicKey = [0; 32].into();

        let v1 = ReportDataV1::new(tls_key.clone());
        assert_eq!(v1.tls_public_key, tls_key);
    }

    #[test]
    fn test_from_bytes() {
        let tls_key: Ed25519PublicKey = [0; 32].into();

        let report_data_v1 = ReportDataV1::new(tls_key);
        let bytes = report_data_v1.to_bytes();

        let hash = ReportDataV1::from_bytes(&bytes);
        assert_eq!(hash, report_data_v1.public_keys_hash());

        let report_data = ReportData::V1(report_data_v1);
        assert_eq!(report_data.to_bytes(), bytes);
    }

    #[test]
    fn test_binary_version_placement() {
        let tls_key: Ed25519PublicKey = [0; 32].into();

        let bytes = ReportDataV1::new(tls_key).to_bytes();

        let version_bytes =
            &bytes[BINARY_VERSION_OFFSET..BINARY_VERSION_OFFSET + BINARY_VERSION_SIZE];
        assert_eq!(version_bytes, &[0, 1]);
    }

    #[test]
    fn test_public_key_hash_placement() {
        let tls_key: Ed25519PublicKey = [9; 32].into();

        let report_data_v1 = ReportDataV1::new(tls_key.clone());
        let bytes = report_data_v1.to_bytes();

        let report_data = ReportData::V1(report_data_v1);
        assert_eq!(report_data.to_bytes(), bytes);

        let hash_bytes = &bytes[PUBLIC_KEYS_OFFSET..PUBLIC_KEYS_OFFSET + PUBLIC_KEYS_HASH_SIZE];
        assert_ne!(hash_bytes, &[0u8; PUBLIC_KEYS_HASH_SIZE]);

        let mut hasher = Sha3_384::new();
        // Skip first byte as it is used for identifier for the curve type.
        let key_data = tls_key.as_bytes();
        hasher.update(key_data);
        let expected: [u8; PUBLIC_KEYS_HASH_SIZE] = hasher.finalize().into();

        assert_eq!(hash_bytes, &expected);
    }

    #[test]
    fn test_zero_padding() {
        let tls_key: Ed25519PublicKey = [9; 32].into();
        let bytes = ReportDataV1::new(tls_key).to_bytes();

        let padding = &bytes[PUBLIC_KEYS_OFFSET + PUBLIC_KEYS_HASH_SIZE..];
        assert!(padding.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_report_data_size() {
        let tls_key: Ed25519PublicKey = [9; 32].into();
        let bytes = ReportDataV1::new(tls_key);
        assert_eq!(bytes.to_bytes().len(), REPORT_DATA_SIZE);
    }
}
