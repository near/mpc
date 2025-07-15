use alloc::string::String;
use core::marker::PhantomData;
use derive_more::{AsRef, Deref, Into};

#[derive(Deref, AsRef, Into)]
pub struct Hash32<T> {
    #[deref]
    #[as_ref]
    #[into]
    bytes: [u8; 32],
    #[into(skip)]
    _marker: PhantomData<T>,
}

impl<T> From<[u8; 32]> for Hash32<T> {
    fn from(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            _marker: PhantomData,
        }
    }
}

impl<T> Hash32<T> {
    pub fn as_hex(&self) -> String {
        hex::encode(self.as_ref())
    }
}

// Marker types
pub struct Image;
pub struct Compose;

/// Hash of an MPC Docker image running in the TEE environment. Used as a proposal for a new TEE
/// code hash to add to the whitelist, together with the TEE quote (which includes the RTMR3
/// measurement and more).
pub type MpcDockerImageHash = Hash32<Image>;

/// Hash of the launcher's Docker Compose file used to run the MPC node in the TEE environment. It
/// is computed from the launcher's Docker Compose template populated with the MPC node's Docker
/// image hash.
pub type LauncherDockerComposeHash = Hash32<Compose>;

#[cfg(test)]
mod tests {
    use super::*;

    struct TestMarker;
    type TestHash = Hash32<TestMarker>;

    #[test]
    fn test_from_bytes_array() {
        let bytes = [1u8; 32];
        let hash: TestHash = bytes.into();
        assert_eq!(*hash, bytes);
    }

    #[test]
    fn test_from_trait() {
        let bytes = [42u8; 32];
        let hash = TestHash::from(bytes);
        assert_eq!(*hash, bytes);
    }

    #[test]
    fn test_into_bytes_array() {
        let bytes = [123u8; 32];
        let hash = TestHash::from(bytes);
        let converted_bytes: [u8; 32] = hash.into();
        assert_eq!(converted_bytes, bytes);
    }

    #[test]
    fn test_deref() {
        let bytes = [255u8; 32];
        let hash = TestHash::from(bytes);

        assert_eq!(hash.len(), 32);
        assert_eq!(hash[0], 255);
        assert_eq!(&hash[..4], &[255, 255, 255, 255]);
    }

    #[test]
    fn test_as_ref() {
        let bytes = [42u8; 32];
        let hash = TestHash::from(bytes);

        // Test AsRef<[u8; 32]> works
        let bytes_ref: &[u8; 32] = hash.as_ref();
        assert_eq!(bytes_ref, &bytes);

        // Test can be used where &[u8; 32] is expected
        fn takes_bytes_ref(b: &[u8; 32]) -> u8 {
            b[0]
        }
        assert_eq!(takes_bytes_ref(hash.as_ref()), 42);
    }

    #[test]
    fn test_as_hex() {
        let bytes = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let hash = TestHash::from(bytes);

        let expected_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        assert_eq!(hash.as_hex(), expected_hex);
    }

    #[test]
    fn test_zero_hash() {
        let zero_bytes = [0u8; 32];
        let hash = TestHash::from(zero_bytes);

        assert_eq!(hash.as_hex(), "0".repeat(64));
        assert_eq!(hash.len(), 32);
        assert!(hash.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_max_hash() {
        let max_bytes = [255u8; 32];
        let hash = TestHash::from(max_bytes);

        assert_eq!(hash.as_hex(), "f".repeat(64));
        assert_eq!(hash.len(), 32);
        assert!(hash.iter().all(|&b| b == 255));
    }

    #[test]
    fn test_type_aliases() {
        let bytes = [1u8; 32];

        let image_hash = MpcDockerImageHash::from(bytes);
        let compose_hash = LauncherDockerComposeHash::from(bytes);

        assert_eq!(*image_hash, bytes);
        assert_eq!(*compose_hash, bytes);
        assert_eq!(image_hash.as_hex(), compose_hash.as_hex());
    }

    #[test]
    fn test_different_marker_types() {
        let bytes = [42u8; 32];

        // Ensure different marker types create different types
        let image_hash = MpcDockerImageHash::from(bytes);
        let compose_hash = LauncherDockerComposeHash::from(bytes);

        // They should have the same data but be different types
        assert_eq!(*image_hash, *compose_hash);

        // This wouldn't compile (different types):
        // let _: MpcDockerImageHash = compose_hash;
    }

    #[test]
    fn test_slice_operations() {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let hash = TestHash::from(bytes);

        assert_eq!(&hash[0..4], &[0, 1, 2, 3]);
        assert_eq!(&hash[28..32], &[28, 29, 30, 31]);
        assert_eq!(hash.first(), Some(&0));
        assert_eq!(hash.last(), Some(&31));
    }

    #[test]
    fn test_conversion_roundtrip() {
        let original_bytes = [137u8; 32];

        // Test full roundtrip: bytes -> Hash32 -> bytes
        let hash = TestHash::from(original_bytes);
        let converted_back: [u8; 32] = hash.into();

        assert_eq!(original_bytes, converted_back);
    }
}
