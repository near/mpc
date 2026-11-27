use serde::{Serialize, de::DeserializeOwned};
use std::io;
use zeroize::Zeroizing;

/// Plaintext JSON of a secret, wiped on drop.
pub struct SecretJson(Zeroizing<Vec<u8>>);

impl SecretJson {
    /// Serializes into a buffer that is sized up front and never reallocates.
    pub(crate) fn serialize<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<Self> {
        let mut counter = ByteCounter(0);
        serde_json::to_writer(&mut counter, value)?;
        let mut json = Zeroizing::new(Vec::with_capacity(counter.0));
        serde_json::to_writer(&mut *json, value)?;
        Ok(Self(json))
    }

    pub(crate) fn deserialize<T: DeserializeOwned>(&self) -> serde_json::Result<T> {
        serde_json::from_slice(&self.0)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for SecretJson {
    fn from(plaintext: Vec<u8>) -> Self {
        Self(Zeroizing::new(plaintext))
    }
}

struct ByteCounter(usize);

impl io::Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(buf.len())
            .ok_or_else(|| io::Error::other("JSON length overflow"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::SecretJson;
    use crate::keyshare::test_utils::KeysetBuilder;
    use rand::SeedableRng as _;

    #[test]
    fn serialize__should_match_serde_json_without_spare_capacity() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let keyset = KeysetBuilder::new_populated(0, 8, &mut rng);

        // When
        let json = SecretJson::serialize(keyset.keyshares()).unwrap();

        // Then
        assert_eq!(*json.0, serde_json::to_vec(keyset.keyshares()).unwrap());
        assert_eq!(json.0.capacity(), json.0.len());
    }
}
