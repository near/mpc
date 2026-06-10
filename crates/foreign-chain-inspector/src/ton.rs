use crate::ton::boc::BocError;
use near_mpc_bounded_collections::BoundedVecOutOfBounds;
use near_mpc_contract_interface::types::{
    Hash256, TonCellBody, TonCellBodyError, TonCellData, TonCellRefs,
};

pub mod boc;
pub mod inspector;
pub mod rpc_client;
pub mod types;

/// Errors raised during [BoC](https://docs.ton.org/blockchain-basics/primitives/serialization/boc) cell normalization.
#[derive(Debug, thiserror::Error)]
pub enum TonBocError {
    #[error("failed to decode TON BoC: {0}")]
    Boc(#[from] BocError),

    #[error("TON cell body is not byte-aligned (bit_len={bit_len}, must be divisible by 8)")]
    NonByteAlignedBody { bit_len: u16 },

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
    /// Whether this error is a transient failure as opposed to a substantive
    /// verdict about the transaction. See
    /// [`crate::ForeignChainInspectionError::is_transient`].
    ///
    /// [`Self::TransactionNotFound`] is transient: a provider that has not yet
    /// indexed the transaction is indistinguishable from one that never will,
    /// exactly like [`crate::ForeignChainInspectionError::NotFinalized`] — a
    /// lagging provider in a [`crate::FanOut`] must be tolerated, not treated
    /// as a disagreeing verdict.
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::RpcError(_) | Self::TransactionNotFound { .. })
    }
}

/// Decompose a TON cell (supplied as a base64-encoded BoC) into the contract's
/// canonical [`TonCellBody`] / [`TonCellRefs`] representation.
///
/// The cell's inline data becomes the [`TonCellBody`]; each child cell is
/// represented by its 256-bit
/// [representation hash](https://docs.ton.org/foundations/serialization/cells#standard-cell-representation-and-its-hash),
/// matching the contract's `body_refs: `[`TonCellRefs`] shape. Only byte-aligned
/// bodies are accepted — TON message bodies are byte-aligned in practice, and
/// rejecting the rest keeps the signed payload unambiguous across nodes.
pub fn normalize_body_boc(body_boc_b64: &str) -> Result<(TonCellBody, TonCellRefs), TonBocError> {
    let cell = boc::parse_single_root_boc(body_boc_b64)?;

    if cell.bit_len % 8 != 0 {
        return Err(TonBocError::NonByteAlignedBody {
            bit_len: cell.bit_len,
        });
    }
    let body = ton_cell_body(cell.data, cell.bit_len)?;

    // Each reference is identified by its representation hash — the canonical,
    // deterministic 32-byte identity TON uses for child cells.
    let ref_hashes: Vec<Hash256> = cell.ref_hashes.into_iter().map(Hash256).collect();
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

    fn cell_body(bits: Vec<u8>, bit_length: u16) -> TonCellBody {
        TonCellBody::new(bits.try_into().unwrap(), bit_length).unwrap()
    }

    // A byte-aligned 4-byte body cell `0x99000001` (32 bits), no references.
    const BYTE_ALIGNED_BODY: &str = "te6ccgEBAQEABgAACJkAAAE=";
    // A 2-byte body cell `0xdead` (16 bits) referencing one child cell `0xaa`.
    const ONE_REF_BODY: &str = "te6ccgEBAgEACAABBN6tAQACqg==";
    const ONE_REF_CHILD_HASH: &str =
        "08da99aa8eb36c5c627a221005ca60f004f392de79b18e90be10c0cb420ab332";
    // A non-byte-aligned body cell (12 bits).
    const NON_BYTE_ALIGNED_BODY: &str = "te6ccgEBAQEABAAAA96o";

    #[test]
    fn normalize_body_boc__should_return_inline_bytes_for_byte_aligned_body() {
        let (body, refs) = normalize_body_boc(BYTE_ALIGNED_BODY).unwrap();
        assert_eq!(body, cell_body(vec![0x99, 0x00, 0x00, 0x01], 32));
        assert!(refs.is_empty());
    }

    #[test]
    fn normalize_body_boc__should_map_references_to_their_cell_hashes() {
        let (body, refs) = normalize_body_boc(ONE_REF_BODY).unwrap();
        assert_eq!(body, cell_body(vec![0xde, 0xad], 16));
        assert_eq!(
            refs.as_slice(),
            &[Hash256(
                hex::decode(ONE_REF_CHILD_HASH).unwrap().try_into().unwrap()
            )],
        );
    }

    #[test]
    fn normalize_body_boc__should_reject_non_byte_aligned_body() {
        let err = normalize_body_boc(NON_BYTE_ALIGNED_BODY).unwrap_err();
        assert_matches!(err, TonBocError::NonByteAlignedBody { bit_len: 12 });
    }

    #[test]
    fn normalize_body_boc__should_surface_decode_errors_as_boc_error() {
        // Malformed input must produce an error (never a panic — the production
        // binary aborts on panic).
        assert_matches!(
            normalize_body_boc("!!!not base64!!!"),
            Err(TonBocError::Boc(_))
        );
    }

    #[test]
    fn empty_body__should_return_zero_bit_body_and_no_refs() {
        let (body, refs) = empty_body().unwrap();
        assert_eq!(body, cell_body(vec![], 0));
        assert!(refs.is_empty());
    }

    #[test]
    fn is_transient__should_treat_transaction_not_found_as_transient() {
        // A provider that has not indexed the transaction yet must be tolerated
        // by the fan-out, like a not-yet-finalized transaction.
        let err = TonInspectionError::TransactionNotFound {
            tx_hash_hex: "de".repeat(32),
        };

        assert!(err.is_transient());
    }

    #[test]
    fn is_transient__should_treat_account_mismatch_as_substantive() {
        let err = TonInspectionError::AccountMismatch {
            expected: "0:aa".to_string(),
            got: "0:bb".to_string(),
        };

        assert!(!err.is_transient());
    }
}
