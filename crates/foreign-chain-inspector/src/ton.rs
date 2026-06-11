use crate::ton::boc::BocError;
use near_mpc_bounded_collections::BoundedVecOutOfBounds;
use near_mpc_contract_interface::types::{
    Hash256, TonCellBody, TonCellBodyError, TonCellData, TonCellRefs,
};

pub mod boc;
pub mod inspector;
pub mod rpc_client;
#[cfg(test)]
pub(crate) mod test_support;
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

    #[error("TON ext-out message at index {index} has no message content")]
    MessageMissingContent { index: usize },

    #[error(transparent)]
    BocError(#[from] crate::ton::TonBocError),
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

    /// Whether two errors represent the same failure mode (same variant,
    /// inner fields ignored) for the [`crate::FanOut`] agreement check. See
    /// [`crate::ForeignChainInspectionError::same_failure_mode`].
    pub fn same_failure_mode(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
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

    let ref_hashes: Vec<Hash256> = cell.ref_hashes.into_iter().map(Hash256).collect();
    let body_refs: TonCellRefs = ref_hashes.try_into().map_err(TonBocError::OutOfBounds)?;

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
    use super::test_support::{
        BYTE_ALIGNED, NON_BYTE_ALIGNED, ONE_REF, ONE_REF_CHILD_HASH, cell_body,
    };
    use super::*;
    use assert_matches::assert_matches;

    #[test]
    fn normalize_body_boc__should_return_inline_bytes_for_byte_aligned_body() {
        let (body, refs) = normalize_body_boc(BYTE_ALIGNED).unwrap();
        assert_eq!(body, cell_body(vec![0x99, 0x00, 0x00, 0x01], 32));
        assert!(refs.is_empty());
    }

    #[test]
    fn normalize_body_boc__should_map_references_to_their_cell_hashes() {
        let (body, refs) = normalize_body_boc(ONE_REF).unwrap();
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
        let err = normalize_body_boc(NON_BYTE_ALIGNED).unwrap_err();
        assert_matches!(err, TonBocError::NonByteAlignedBody { bit_len: 12 });
    }

    #[test]
    fn normalize_body_boc__should_surface_decode_errors_as_boc_error() {
        assert_matches!(
            normalize_body_boc("!!!not base64!!!"),
            Err(TonBocError::Boc(_))
        );
    }

    #[test]
    fn is_transient__should_treat_transaction_not_found_as_transient() {
        let err = TonInspectionError::TransactionNotFound {
            tx_hash_hex: "de".repeat(32),
        };

        assert!(err.is_transient());
    }

    #[test]
    fn is_transient__should_treat_missing_message_content_as_substantive() {
        let err = TonInspectionError::MessageMissingContent { index: 0 };

        assert!(!err.is_transient());
    }
}
