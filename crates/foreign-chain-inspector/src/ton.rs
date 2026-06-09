use near_mpc_bounded_collections::BoundedVecOutOfBounds;
use near_mpc_contract_interface::types::{
    Hash256, TonCellBody, TonCellBodyError, TonCellData, TonCellRefs,
};
use tonlib_core::cell::{BagOfCells, TonCellError};

pub mod inspector;
pub mod rpc_client;
pub mod types;

/// Errors raised during [BoC](https://docs.ton.org/blockchain-basics/primitives/serialization/boc) cell normalization.
#[derive(Debug, thiserror::Error)]
pub enum TonBocError {
    #[error("failed to parse TON BoC: {0}")]
    Parse(TonCellError),

    #[error("TON BoC is not a single-root BoC (expected exactly one root)")]
    NotSingleRoot,

    #[error("TON cell body is not byte-aligned (bit_len={bit_len}, must be divisible by 8)")]
    NonByteAlignedBody { bit_len: usize },

    #[error("TON cell bit length {bit_len} does not fit in u16")]
    BitLengthTooLarge { bit_len: usize },

    #[error("TON cell body is not a valid contract cell body: {0}")]
    InvalidCellBody(TonCellBodyError),

    #[error("TON cell exceeds contract bounds: {0}")]
    OutOfBounds(BoundedVecOutOfBounds),
}

#[derive(Debug, thiserror::Error)]
pub enum TonInspectionError {
    #[error("TON RPC error: {0}")]
    RpcError(#[from] crate::ton::rpc_client::TonRpcError),

    #[error("no transaction found on TON for hash {tx_hash_hex}")]
    TransactionNotFound { tx_hash_hex: String },

    #[error("TON transaction account mismatch: request asked for {expected}, RPC returned {got}")]
    AccountMismatch { expected: String, got: String },

    #[error("TON transaction hash mismatch: request asked for {expected}, RPC returned {got}")]
    HashMismatch { expected: String, got: String },

    #[error("TON ext-out message at index {index} has no message content")]
    MessageMissingContent { index: usize },

    #[error(
        "TON workchain {got} is not supported in v1 (only workchain 0 / basechain is supported)"
    )]
    UnsupportedWorkchain { got: i8 },

    #[error(transparent)]
    BocError(#[from] crate::ton::TonBocError),

    #[error(
        "TON ext-out message is missing `created_lt`; cannot establish deterministic message order"
    )]
    MessageMissingCreatedLt,

    #[error("TON ext-out message has unparseable `created_lt`: {value}")]
    MessageMalformedCreatedLt { value: String },

    #[error(
        "TON ext-out messages share `created_lt` {value}; ordering is nondeterministic across nodes"
    )]
    MessageDuplicateCreatedLt { value: u64 },
}

impl TonInspectionError {
    /// Whether this error is a transient failure (a failed RPC round-trip) as
    /// opposed to a substantive verdict about the transaction. See
    /// [`crate::ForeignChainInspectionError::is_transient`].
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::RpcError(_))
    }
}

/// Decompose a TON cell (supplied as a base64-encoded BoC) into the contract's
/// canonical [`TonCellBody`] / [`TonCellRefs`] representation.
///
/// The cell's inline data becomes the [`TonCellBody`]; each child cell is
/// represented by its 256-bit representation hash ([`tonlib_core::cell::Cell::cell_hash`]),
/// matching the contract's `body_refs: `[`TonCellRefs`] shape. Only byte-aligned
/// bodies are accepted — TON message bodies are byte-aligned in practice, and
/// rejecting the rest keeps the signed payload unambiguous across nodes.
pub fn normalize_body_boc(body_boc_b64: &str) -> Result<(TonCellBody, TonCellRefs), TonBocError> {
    let boc = BagOfCells::parse_base64(body_boc_b64).map_err(TonBocError::Parse)?;

    let root = boc.single_root().map_err(|_| TonBocError::NotSingleRoot)?;

    let bit_len = root.bit_len();
    if bit_len % 8 != 0 {
        return Err(TonBocError::NonByteAlignedBody { bit_len });
    }
    let byte_len = bit_len / 8;

    // Top-level cell's inline data, packed to `bit_len / 8` bytes.
    let body_bits = root.data().get(..byte_len).unwrap_or(root.data()).to_vec();
    let bit_length =
        u16::try_from(bit_len).map_err(|_| TonBocError::BitLengthTooLarge { bit_len })?;
    let body = ton_cell_body(body_bits, bit_length)?;

    // Each reference is identified by its representation hash — the canonical,
    // deterministic 32-byte identity TON uses for child cells.
    let ref_hashes: Vec<Hash256> = root
        .references()
        .iter()
        .map(|r| Hash256(r.cell_hash().into()))
        .collect();
    let body_refs: TonCellRefs = ref_hashes.try_into().map_err(TonBocError::OutOfBounds)?;

    Ok((body, body_refs))
}

/// The `(body, refs)` pair for an ext-out message that carries no content cell.
pub fn empty_body() -> Result<(TonCellBody, TonCellRefs), TonBocError> {
    let body = ton_cell_body(Vec::new(), 0)?;
    let body_refs: TonCellRefs = Vec::new().try_into().map_err(TonBocError::OutOfBounds)?;
    Ok((body, body_refs))
}

/// Build a contract [`TonCellBody`] from `bits` (packed big-endian) and the
/// significant `bit_length`, mapping the bound/consistency checks to
/// [`TonBocError`].
fn ton_cell_body(bits: Vec<u8>, bit_length: u16) -> Result<TonCellBody, TonBocError> {
    let data: TonCellData = bits.try_into().map_err(TonBocError::OutOfBounds)?;
    TonCellBody::new(data, bit_length).map_err(TonBocError::InvalidCellBody)
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use base64::Engine;
    use tonlib_core::cell::{ArcCell, Cell};

    fn cell_from_bytes(data: Vec<u8>, bit_len: usize, refs: Vec<ArcCell>) -> ArcCell {
        std::sync::Arc::new(Cell::new(data, bit_len, refs, false).unwrap())
    }

    fn encode_boc(root: ArcCell) -> String {
        base64::engine::general_purpose::STANDARD
            .encode(BagOfCells::new(&[root]).serialize(false).unwrap())
    }

    fn cell_body(bits: Vec<u8>, bit_length: u16) -> TonCellBody {
        TonCellBody::new(bits.try_into().unwrap(), bit_length).unwrap()
    }

    #[test]
    fn normalize_body_boc__should_return_empty_body_and_no_refs_for_empty_cell() {
        let root = cell_from_bytes(vec![], 0, vec![]);
        let b64 = encode_boc(root);

        let (body, refs) = normalize_body_boc(&b64).unwrap();
        assert_eq!(body, cell_body(vec![], 0));
        assert!(refs.is_empty());
    }

    #[test]
    fn normalize_body_boc__should_return_inline_bytes_for_byte_aligned_body() {
        // 4 bytes of payload: op=0x99000001 style.
        let payload = vec![0x99, 0x00, 0x00, 0x01];
        let root = cell_from_bytes(payload.clone(), payload.len() * 8, vec![]);
        let b64 = encode_boc(root);

        let (body, refs) = normalize_body_boc(&b64).unwrap();
        assert_eq!(body, cell_body(payload, 32));
        assert!(refs.is_empty());
    }

    #[test]
    fn normalize_body_boc__should_return_reference_cell_hashes() {
        let ref1 = cell_from_bytes(vec![0xaa, 0xbb], 16, vec![]);
        let ref2 = cell_from_bytes(vec![0x01, 0x02, 0x03], 24, vec![]);
        let root = cell_from_bytes(vec![0xde, 0xad], 16, vec![ref1.clone(), ref2.clone()]);

        let b64 = encode_boc(root);
        let (body, refs) = normalize_body_boc(&b64).unwrap();

        assert_eq!(body, cell_body(vec![0xde, 0xad], 16));
        // Refs are the children's representation hashes, in cell order.
        let expected = vec![
            Hash256(ref1.cell_hash().into()),
            Hash256(ref2.cell_hash().into()),
        ];
        assert_eq!(refs.as_slice(), expected.as_slice());
    }

    #[test]
    fn normalize_body_boc__should_be_deterministic_across_runs() {
        // Same input ⇒ identical output (the determinism guarantee MPC relies on).
        let ref1 = cell_from_bytes(vec![0xaa], 8, vec![]);
        let root = cell_from_bytes(vec![0xde, 0xad, 0xbe, 0xef], 32, vec![ref1]);
        let b64 = encode_boc(root);

        let first = normalize_body_boc(&b64).unwrap();
        let second = normalize_body_boc(&b64).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn empty_body__should_return_zero_bit_body_and_no_refs() {
        let (body, refs) = empty_body().unwrap();
        assert_eq!(body, cell_body(vec![], 0));
        assert!(refs.is_empty());
    }

    #[test]
    fn normalize_body_boc__should_reject_non_byte_aligned_body() {
        // 12 bits of data isn't byte-aligned.
        let root = cell_from_bytes(vec![0xab, 0xc0], 12, vec![]);
        let b64 = encode_boc(root);

        let err = normalize_body_boc(&b64).unwrap_err();
        assert_matches!(err, TonBocError::NonByteAlignedBody { bit_len: 12 });
    }

    #[test]
    fn normalize_body_boc__should_reject_malformed_base64() {
        let err = normalize_body_boc("!!!not base64!!!").unwrap_err();
        assert_matches!(err, TonBocError::Parse(_));
    }

    #[test]
    fn normalize_body_boc__should_reject_non_cell_bytes() {
        // Valid base64 but not a valid BoC.
        let garbage = base64::engine::general_purpose::STANDARD.encode([0xff, 0xff, 0xff, 0xff]);
        let err = normalize_body_boc(&garbage).unwrap_err();
        assert_matches!(err, TonBocError::Parse(_));
    }
}
