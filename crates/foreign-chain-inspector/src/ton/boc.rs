//! Minimal decoder for a TON
//! [Bag of Cells](https://docs.ton.org/blockchain-basics/primitives/serialization/boc):
//! enough to pull a message body's data bits and the
//! [representation hashes](https://docs.ton.org/foundations/serialization/cells#standard-cell-representation-and-its-hash)
//! of its child cells, which is all [`super::normalize_body_boc`] needs.

use sha2::{Digest, Sha256};

/// Generic BoC magic prefix (`serialized_boc#b5ee9c72`).
const GENERIC_BOC_MAGIC: u32 = 0xb5ee_9c72;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BocError {
    #[error("invalid base64 in TON BoC")]
    Base64,
    #[error("malformed TON BoC: {0}")]
    Malformed(&'static str),
}

/// The root cell of a decoded BoC: its data bits (packed big-endian, length
/// `⌈bit_len / 8⌉`, any non-byte-aligned tail's unused low bits zeroed), its
/// significant `bit_len`, the representation hashes of its direct children in
/// order, and the cell's own representation hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedCell {
    pub data: Vec<u8>,
    pub bit_len: u16,
    pub ref_hashes: Vec<[u8; 32]>,
    /// This cell's own representation hash. Not needed by
    /// [`super::normalize_body_boc`] (which carries the body bits and child
    /// hashes), but the TON HTTP API reports the same value as a message body's
    /// `message_content.hash`, making it a convenient cross-check oracle.
    pub hash: [u8; 32],
}

/// A cell as read from the stream: its raw descriptor bytes and data (already in
/// the standard-representation form the hash consumes, borrowed from the input
/// buffer) plus its references' indices.
struct RawCell<'a> {
    d1: u8,
    d2: u8,
    data: &'a [u8],
    refs: Vec<usize>,
}

/// Parse a base64 single-root BoC and return its root cell with every child
/// reference resolved to a representation hash.
pub fn parse_single_root_boc(body_boc_b64: &str) -> Result<DecodedCell, BocError> {
    let bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        body_boc_b64.as_bytes(),
    )
    .map_err(|_| BocError::Base64)?;

    let mut r = Reader::new(&bytes);

    if r.u32()? != GENERIC_BOC_MAGIC {
        return Err(BocError::Malformed("unsupported magic"));
    }
    let flags = r.u8()?;
    let has_idx = flags & 0b1000_0000 != 0;
    let ref_size = usize::from(flags & 0b0000_0111);
    let off_size = usize::from(r.u8()?);

    let cell_count = r.var(ref_size)?;
    let root_count = r.var(ref_size)?;
    let _absent = r.var(ref_size)?;
    let _tot_size = r.var(off_size)?;

    if root_count != 1 {
        return Err(BocError::Malformed("expected a single root"));
    }
    let root = r.var(ref_size)?;
    if root >= cell_count {
        return Err(BocError::Malformed("root index out of range"));
    }

    if has_idx {
        for _ in 0..cell_count {
            r.var(off_size)?;
        }
    }

    let mut cells = Vec::with_capacity(cell_count);
    for index in 0..cell_count {
        cells.push(read_cell(&mut r, ref_size, index, cell_count)?);
    }

    Ok(resolve(&cells, root))
}

fn read_cell<'a>(
    r: &mut Reader<'a>,
    ref_size: usize,
    index: usize,
    cell_count: usize,
) -> Result<RawCell<'a>, BocError> {
    let d1 = r.u8()?;
    let d2 = r.u8()?;

    if d1 & 0b0001_0000 != 0 {
        // `with_hashes`: stored hashes precede the data. Providers never emit
        // this; rejecting it keeps the reader straightforward.
        return Err(BocError::Malformed("stored cell hashes unsupported"));
    }

    let ref_count = usize::from(d1 & 0b0000_0111);
    let data_len = usize::from((d2 >> 1) + (d2 & 1));
    let data = r.bytes(data_len)?;

    let mut refs = Vec::with_capacity(ref_count);
    for _ in 0..ref_count {
        let to = r.var(ref_size)?;
        if to >= cell_count {
            return Err(BocError::Malformed("reference index out of range"));
        }
        // References must point strictly forward (BoC's canonical ordering).
        // This rules out cycles, so hashing can run bottom-up without recursion.
        if to <= index {
            return Err(BocError::Malformed("non-forward reference"));
        }
        refs.push(to);
    }

    Ok(RawCell { d1, d2, data, refs })
}

/// Compute each cell's representation hash and depth bottom-up (forward
/// references guarantee a child is done before its parent), then return the root.
fn resolve(cells: &[RawCell<'_>], root: usize) -> DecodedCell {
    let mut hashes = vec![[0u8; 32]; cells.len()];
    let mut depths = vec![0u16; cells.len()];

    for index in (0..cells.len()).rev() {
        let cell = &cells[index];

        let depth = cell
            .refs
            .iter()
            .map(|&c| depths[c].saturating_add(1))
            .max()
            .unwrap_or(0);
        depths[index] = depth;

        // Standard representation: d1 ‖ d2 ‖ data ‖ child depths ‖ child hashes.
        // `d1`, `d2` and `data` are reused verbatim from the stream — that is
        // already the standard-representation form.
        let mut hasher = Sha256::new();
        hasher.update([cell.d1, cell.d2]);
        hasher.update(cell.data);
        for &c in &cell.refs {
            hasher.update(depths[c].to_be_bytes());
        }
        for &c in &cell.refs {
            hasher.update(hashes[c]);
        }
        hashes[index] = hasher.finalize().into();
    }

    let root_cell = &cells[root];
    let (data, bit_len) = root_body(root_cell);
    let ref_hashes = root_cell.refs.iter().map(|&c| hashes[c]).collect();
    DecodedCell {
        data,
        bit_len,
        ref_hashes,
        hash: hashes[root],
    }
}

/// The root's significant data bits and length. A byte-aligned cell is taken
/// as-is; a non-byte-aligned one has its augmentation `1` bit (and the zero
/// padding after it) stripped so the bytes are canonical.
fn root_body(cell: &RawCell<'_>) -> (Vec<u8>, u16) {
    // `data.len() <= 128`, so `len * 8 <= 1024` always fits in u16.
    let bits = (cell.data.len() as u16) * 8;
    if cell.d2 & 1 == 0 {
        return (cell.data.to_vec(), bits);
    }
    let mut data = cell.data.to_vec();
    if let Some(last) = data.last_mut()
        && *last != 0
    {
        let trailing = last.trailing_zeros() as u16;
        *last &= !(1u8 << trailing);
        return (data, bits - (trailing + 1));
    }
    // Degenerate augmentation (no data or all-zero final byte); bit_len stays a
    // multiple of 8 so the caller rejects it as non-byte-aligned rather than
    // acting on it.
    (data, bits)
}

/// A bounds-checked, big-endian byte reader: every accessor returns
/// [`BocError::Malformed`] rather than panicking when the buffer is exhausted.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], BocError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(BocError::Malformed("length overflow"))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(BocError::Malformed("unexpected end of input"))?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, BocError> {
        Ok(self.bytes(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, BocError> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read an `n`-byte big-endian unsigned integer as a `usize` (`n <= 8`).
    fn var(&mut self, n: usize) -> Result<usize, BocError> {
        if n > 8 {
            return Err(BocError::Malformed("oversized length field"));
        }
        let mut value: u64 = 0;
        for &byte in self.bytes(n)? {
            value = (value << 8) | u64::from(byte);
        }
        usize::try_from(value).map_err(|_| BocError::Malformed("length too large"))
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use test_utils::ton::{
        BYTE_ALIGNED, BYTE_ALIGNED_HASH, EMPTY, EMPTY_HASH, NESTED, NESTED_CHILD_HASH,
        NON_BYTE_ALIGNED, ONE_REF, ONE_REF_CHILD_HASH,
    };

    #[test]
    fn parse_single_root_boc__should_decode_byte_aligned_cell() {
        let cell = parse_single_root_boc(BYTE_ALIGNED).unwrap();
        assert_eq!(cell.data, vec![0x99, 0x00, 0x00, 0x01]);
        assert_eq!(cell.bit_len, 32);
        assert!(cell.ref_hashes.is_empty());
        assert_eq!(hex::encode(cell.hash), BYTE_ALIGNED_HASH);
    }

    #[test]
    fn parse_single_root_boc__should_decode_empty_cell() {
        let cell = parse_single_root_boc(EMPTY).unwrap();
        assert_eq!(cell.data, Vec::<u8>::new());
        assert_eq!(cell.bit_len, 0);
        assert_eq!(hex::encode(cell.hash), EMPTY_HASH);
    }

    #[test]
    fn parse_single_root_boc__should_strip_augmentation_of_non_byte_aligned_cell() {
        let cell = parse_single_root_boc(NON_BYTE_ALIGNED).unwrap();
        assert_eq!(cell.data, vec![0xde, 0xa0]);
        assert_eq!(cell.bit_len, 12);
    }

    #[test]
    fn parse_single_root_boc__should_resolve_reference_hashes() {
        let cell = parse_single_root_boc(ONE_REF).unwrap();
        assert_eq!(cell.data, vec![0xde, 0xad]);
        assert_eq!(
            cell.ref_hashes.iter().map(hex::encode).collect::<Vec<_>>(),
            vec![ONE_REF_CHILD_HASH],
        );
    }

    #[test]
    fn parse_single_root_boc__should_hash_nested_references_recursively() {
        // The direct child's hash depends on the grandchild's, so matching the
        // golden proves the bottom-up hashing is correct.
        let cell = parse_single_root_boc(NESTED).unwrap();
        assert_eq!(
            cell.ref_hashes.iter().map(hex::encode).collect::<Vec<_>>(),
            vec![NESTED_CHILD_HASH],
        );
    }

    #[test]
    fn parse_single_root_boc__should_reject_invalid_base64() {
        assert_matches!(parse_single_root_boc("!!!"), Err(BocError::Base64));
    }

    #[test]
    fn parse_single_root_boc__should_reject_garbage_without_panicking() {
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [0xff, 0xff, 0xff, 0xff],
        );
        assert_matches!(parse_single_root_boc(&b64), Err(BocError::Malformed(_)));
    }

    #[test]
    fn parse_single_root_boc__should_reject_out_of_range_root_index_without_panicking() {
        // One cell declared, but root index 5 — the shape that makes tonlib
        // underflow and panic. We must return an error instead.
        let bytes = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x02, 0x05, 0x00, 0x00,
        ];
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes);
        assert_matches!(parse_single_root_boc(&b64), Err(BocError::Malformed(_)));
    }
}
