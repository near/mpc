use serde::Serialize;
use std::io;
use zeroize::Zeroizing;

/// Serializes to JSON in a buffer that is wiped on drop.
/// The buffer is sized up front and never reallocates.
pub(crate) fn to_json_zeroizing<T: Serialize + ?Sized>(
    value: &T,
) -> serde_json::Result<Zeroizing<Vec<u8>>> {
    let mut counter = ByteCounter(0);
    serde_json::to_writer(&mut counter, value)?;
    let mut json = Zeroizing::new(Vec::with_capacity(counter.0));
    serde_json::to_writer(&mut *json, value)?;
    Ok(json)
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
    use super::to_json_zeroizing;
    use crate::keyshare::test_utils::KeysetBuilder;
    use rand::SeedableRng as _;

    #[test]
    fn to_json_zeroizing__should_match_serde_json_without_spare_capacity() {
        // Given
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let keyset = KeysetBuilder::new_populated(0, 8, &mut rng);

        // When
        let json = to_json_zeroizing(keyset.keyshares()).unwrap();

        // Then
        assert_eq!(*json, serde_json::to_vec(keyset.keyshares()).unwrap());
        assert_eq!(json.capacity(), json.len());
    }
}
