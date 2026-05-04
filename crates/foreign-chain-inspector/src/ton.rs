use near_mpc_contract_interface::types::TonLog;
use tonlib_core::cell::{BagOfCells, TonCellError};

pub mod inspector;
pub mod rpc_client;

/// A value extracted by [`inspector::TonInspector`] — the node-side analog of
/// [`near_mpc_contract_interface::types::TonExtractedValue`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TonExtractedValue {
    Log(TonLog),
}

/// Errors raised during BoC cell normalization.
#[derive(Debug, thiserror::Error)]
pub enum TonBocError {
    #[error("failed to parse TON BoC: {0}")]
    Parse(TonCellError),

    #[error("TON BoC is not a single-root BoC (expected exactly one root)")]
    NotSingleRoot,

    #[error("TON cell body is not byte-aligned (bit_len={bit_len}, must be divisible by 8)")]
    NonByteAlignedBody { bit_len: usize },

    #[error("failed to canonically re-serialize TON cell reference: {0}")]
    SerializeRef(TonCellError),
}

/// All errors specific to the TON inspector.
///
/// Bundled into one enum so the cross-chain
/// [`crate::ForeignChainInspectionError`] only needs a single TON variant
/// instead of leaking every TON-specific failure mode.
#[derive(Debug, thiserror::Error)]
pub enum TonInspectionError {
    #[error("toncenter RPC error: {0}")]
    RpcError(#[from] crate::ton::rpc_client::TonRpcError),

    #[error("no transaction found on TON for hash {tx_hash_hex}")]
    TransactionNotFound { tx_hash_hex: String },

    #[error("TON transaction account mismatch: request asked for {expected}, RPC returned {got}")]
    AccountMismatch { expected: String, got: String },

    #[error("TON transaction hash mismatch: request asked for {expected}, RPC returned {got}")]
    HashMismatch { expected: String, got: String },

    #[error("TON message at index {index} is not an ext-out message")]
    NotAnExtOutMessage { index: u64 },

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
}

/// Split a TON cell (supplied as a base64-encoded BoC) into the
/// `(body_bits, body_refs)` pair consumed by the bridge's TON log parser.
pub fn normalize_body_boc(body_boc_b64: &str) -> Result<(Vec<u8>, Vec<Vec<u8>>), TonBocError> {
    let boc = BagOfCells::parse_base64(body_boc_b64).map_err(TonBocError::Parse)?;

    let root = boc.single_root().map_err(|_| TonBocError::NotSingleRoot)?;

    let bit_len = root.bit_len();
    if bit_len % 8 != 0 {
        return Err(TonBocError::NonByteAlignedBody { bit_len });
    }
    let byte_len = bit_len / 8;

    // Top-level cell's inline data, packed to `bit_len / 8` bytes.
    let body_bits = root.data().get(..byte_len).unwrap_or(root.data()).to_vec();

    // Each reference cell re-serialized as its own canonical single-root BoC,
    // so downstream consumers can lazy-decode refs without parsing the parent.
    let body_refs: Vec<Vec<u8>> = root
        .references()
        .iter()
        .map(|r| {
            BagOfCells::new(std::slice::from_ref(r))
                .serialize(false)
                .map_err(TonBocError::SerializeRef)
        })
        .collect::<Result<_, _>>()?;

    Ok((body_bits, body_refs))
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

    #[test]
    fn normalize_body_boc__should_return_empty_bits_and_no_refs_for_empty_cell() {
        let root = cell_from_bytes(vec![], 0, vec![]);
        let b64 = encode_boc(root);

        let (bits, refs) = normalize_body_boc(&b64).unwrap();
        assert!(bits.is_empty());
        assert!(refs.is_empty());
    }

    #[test]
    fn normalize_body_boc__should_return_inline_bytes_for_byte_aligned_body() {
        // 4 bytes of payload: op=0x99000001 style.
        let payload = vec![0x99, 0x00, 0x00, 0x01];
        let root = cell_from_bytes(payload.clone(), payload.len() * 8, vec![]);
        let b64 = encode_boc(root);

        let (bits, refs) = normalize_body_boc(&b64).unwrap();
        assert_eq!(bits, payload);
        assert!(refs.is_empty());
    }

    #[test]
    fn normalize_body_boc__should_preserve_refs_round_trip() {
        let ref1 = cell_from_bytes(vec![0xaa, 0xbb], 16, vec![]);
        let ref2 = cell_from_bytes(vec![0x01, 0x02, 0x03], 24, vec![]);
        let root = cell_from_bytes(vec![0xde, 0xad], 16, vec![ref1.clone(), ref2.clone()]);

        let b64 = encode_boc(root);
        let (bits, refs) = normalize_body_boc(&b64).unwrap();

        assert_eq!(bits, vec![0xde, 0xad]);
        assert_eq!(refs.len(), 2);

        // Each ref should round-trip back to the same cell tree.
        let parsed_ref1 = BagOfCells::parse(&refs[0]).unwrap().single_root().unwrap();
        let parsed_ref2 = BagOfCells::parse(&refs[1]).unwrap().single_root().unwrap();
        assert_eq!(parsed_ref1.data(), ref1.data());
        assert_eq!(parsed_ref2.data(), ref2.data());
    }

    #[test]
    fn normalize_body_boc__should_be_deterministic_across_runs() {
        // Same input ⇒ byte-identical output (the determinism guarantee MPC relies on).
        let ref1 = cell_from_bytes(vec![0xaa], 8, vec![]);
        let root = cell_from_bytes(vec![0xde, 0xad, 0xbe, 0xef], 32, vec![ref1]);
        let b64 = encode_boc(root);

        let (bits1, refs1) = normalize_body_boc(&b64).unwrap();
        let (bits2, refs2) = normalize_body_boc(&b64).unwrap();
        assert_eq!(bits1, bits2);
        assert_eq!(refs1, refs2);
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
