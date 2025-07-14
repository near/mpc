use near_crypto::PublicKey;
use sha3::{Digest, Sha3_384};

/// Number of bytes for the report data.
/// report_data: [u8; 64] =
///   [version(2 bytes big endian) || sha384(TLS pub key || account pub key) || zero padding]
const REPORT_DATA_SIZE: usize = 64;

const BINARY_VERSION_OFFSET: usize = 0;
const BINARY_VERSION_SIZE: usize = 2;

const PUBLIC_KEYS_OFFSET: usize = 3;
const PUBLIC_KEYS_SIZE: usize = 48;

pub const BINARY_VERSION: BinaryVersion = BinaryVersion(1);

// Compile-time assertions
const _: () = {
    assert!(
        BINARY_VERSION_SIZE + PUBLIC_KEYS_SIZE <= REPORT_DATA_SIZE,
        "Version and public key must not exceed report data size."
    );
    assert!(
        BINARY_VERSION_OFFSET + BINARY_VERSION_SIZE + 1 == PUBLIC_KEYS_OFFSET,
        "Public key offset must be after binary version."
    );
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BinaryVersion(pub u16);

#[derive(Debug, Clone)]
pub struct ReportData {
    pub version: BinaryVersion,
    pub tls_public_key: PublicKey,
    pub account_public_key: PublicKey,
}

impl ReportData {
    pub fn new(tls_public_key: PublicKey, account_public_key: PublicKey) -> Self {
        Self {
            version: BINARY_VERSION,
            tls_public_key,
            account_public_key,
        }
    }

    /// Generates the binary representation of the report data.
    ///
    /// Format:
    /// [version(2 bytes big endian) || sha384(TLS pub key || account pub key) || zero padding]
    pub fn to_bytes(&self) -> [u8; REPORT_DATA_SIZE] {
        let mut report_data = [0u8; REPORT_DATA_SIZE];

        // Copy binary version (2 bytes, big endian)
        let version_bytes = self.version.0.to_be_bytes();
        report_data[BINARY_VERSION_OFFSET..BINARY_VERSION_OFFSET + BINARY_VERSION_SIZE]
            .copy_from_slice(&version_bytes);

        // Generate and copy hash of public keys (48 bytes)
        let public_keys_hash = self.generate_public_keys_hash();
        report_data[PUBLIC_KEYS_OFFSET..PUBLIC_KEYS_OFFSET + PUBLIC_KEYS_SIZE]
            .copy_from_slice(&public_keys_hash);

        // Remaining bytes are already zero-padded by default
        report_data
    }

    /// Generates SHA3-384 hash of concatenated TLS and account public keys.
    fn generate_public_keys_hash(&self) -> [u8; PUBLIC_KEYS_SIZE] {
        let mut hasher = Sha3_384::new();
        hasher.update(self.tls_public_key.key_data());
        hasher.update(self.account_public_key.key_data());
        hasher.finalize().into()
    }
}

impl From<ReportData> for [u8; REPORT_DATA_SIZE] {
    fn from(report_data: ReportData) -> Self {
        report_data.to_bytes()
    }
}

impl From<&ReportData> for [u8; REPORT_DATA_SIZE] {
    fn from(report_data: &ReportData) -> Self {
        report_data.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_crypto::{KeyType, SecretKey};

    fn create_test_keys() -> (PublicKey, PublicKey) {
        let tls_key = SecretKey::from_random(KeyType::ED25519).public_key();
        let account_key = SecretKey::from_random(KeyType::ED25519).public_key();
        (tls_key, account_key)
    }

    #[test]
    fn test_binary_version_serialization() {
        let version = BinaryVersion(1);
        assert_eq!(version.0.to_be_bytes(), [0, 1]);
    }

    #[test]
    fn test_conversion_methods_consistency() {
        let (tls_key, account_key) = create_test_keys();
        let data = ReportData::new(tls_key, account_key);

        let owned: [u8; REPORT_DATA_SIZE] = data.clone().into();
        let referenced: [u8; REPORT_DATA_SIZE] = (&data).into();
        let direct = data.to_bytes();

        assert_eq!(owned, referenced);
        assert_eq!(referenced, direct);
    }

    #[test]
    fn test_binary_version_placement() {
        let (tls_key, account_key) = create_test_keys();
        let bytes = ReportData::new(tls_key, account_key).to_bytes();

        let version_bytes = &bytes[0..2];
        assert_eq!(version_bytes, &[0, 1]);
    }

    #[test]
    fn test_public_key_hash_placement() {
        let (tls_key, account_key) = create_test_keys();
        let data = ReportData::new(tls_key.clone(), account_key.clone());
        let bytes = data.to_bytes();

        let hash_bytes = &bytes[3..51];
        assert_ne!(hash_bytes, &[0u8; 48]);

        let mut hasher = Sha3_384::new();
        hasher.update(tls_key.key_data());
        hasher.update(account_key.key_data());
        let expected: [u8; 48] = hasher.finalize().into();

        assert_eq!(hash_bytes, &expected);
    }

    #[test]
    fn test_zero_padding() {
        let (tls_key, account_key) = create_test_keys();
        let bytes = ReportData::new(tls_key, account_key).to_bytes();

        let padding = &bytes[51..];
        assert!(padding.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_report_data_size() {
        let (tls_key, account_key) = create_test_keys();
        let bytes = ReportData::new(tls_key, account_key).to_bytes();
        assert_eq!(bytes.len(), 64);
    }
}
