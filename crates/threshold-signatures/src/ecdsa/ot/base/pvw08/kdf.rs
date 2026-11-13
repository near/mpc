use frost_core::Group;
use sha2::{Digest, Sha256};

use crate::{
    Ciphersuite, Element,
    crypto::constants::NEAR_PVW08_KDF_LABEL,
    ecdsa::ot::bits::{BitVector, SEC_PARAM_8},
    errors::ProtocolError,
};

/// Derives the key of branch `branch` of transfer `index` from the shared
/// group element `v`.
///
/// `p`, `q`, `u` and `v` are serialized group elements, so they have a fixed
/// length and the concatenation is unambiguous.
pub(super) fn derive_key(
    sid: &[u8],
    index: usize,
    branch: u8,
    p: &[u8],
    q: &[u8],
    u: &[u8],
    v: &[u8],
) -> Result<BitVector, ProtocolError> {
    let sid_len = u64::try_from(sid.len()).map_err(|_| ProtocolError::IntegerOverflow)?;
    let index = u64::try_from(index).map_err(|_| ProtocolError::IntegerOverflow)?;

    let mut hasher = Sha256::new();
    hasher.update(NEAR_PVW08_KDF_LABEL);
    hasher.update(sid_len.to_le_bytes());
    hasher.update(sid);
    hasher.update(index.to_le_bytes());
    hasher.update([branch]);
    hasher.update(p);
    hasher.update(q);
    hasher.update(u);
    hasher.update(v);

    let digest: [u8; 32] = hasher.finalize().into();
    let key = digest
        .first_chunk::<SEC_PARAM_8>()
        .ok_or(ProtocolError::HashingError)?;
    Ok(BitVector::from_bytes(key))
}

pub(super) fn serialize<C: Ciphersuite>(
    element: &Element<C>,
) -> Result<<C::Group as Group>::Serialization, ProtocolError> {
    <C::Group as Group>::serialize(element).map_err(|_| ProtocolError::PointSerialization)
}

#[cfg(test)]
#[expect(non_snake_case)]
mod test {
    use super::*;

    fn key(sid: &[u8], index: usize, branch: u8, points: [&[u8]; 4]) -> BitVector {
        let [p, q, u, v] = points;
        derive_key(sid, index, branch, p, q, u, v).unwrap()
    }

    #[test]
    fn derive_key__should_be_deterministic() {
        // Given
        let points: [&[u8]; 4] = [b"p", b"q", b"u", b"v"];

        // When
        let first = key(b"sid", 7, 1, points);
        let second = key(b"sid", 7, 1, points);

        // Then
        assert_eq!(first, second);
    }

    #[test]
    fn derive_key__should_depend_on_every_input() {
        // Given
        let points: [&[u8]; 4] = [b"p", b"q", b"u", b"v"];
        let reference = key(b"sid", 7, 1, points);

        // When
        let variants = [
            key(b"sid'", 7, 1, points),
            key(b"sid", 8, 1, points),
            key(b"sid", 7, 0, points),
            key(b"sid", 7, 1, [b"x", b"q", b"u", b"v"]),
            key(b"sid", 7, 1, [b"p", b"x", b"u", b"v"]),
            key(b"sid", 7, 1, [b"p", b"q", b"x", b"v"]),
            key(b"sid", 7, 1, [b"p", b"q", b"u", b"x"]),
        ];

        // Then
        for variant in variants {
            assert_ne!(variant, reference);
        }
    }

    #[test]
    fn derive_key__should_not_confuse_the_sid_with_what_follows() {
        // Given
        let points: [&[u8]; 4] = [b"p", b"q", b"u", b"v"];
        let index = usize::from(b'a');
        let longer_sid = [
            b"sid".as_slice(),
            &u64::try_from(index).unwrap().to_le_bytes(),
        ]
        .concat();

        // When
        let short = key(b"sid", index, 1, points);
        let long = key(&longer_sid, index, 1, points);

        // Then
        assert_ne!(short, long);
    }
}
