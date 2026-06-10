//! In-memory record of recently submitted transactions, shown on the
//! `/debug/recent_transactions` web page.
//!
//! A successful submission only means the RPC accepted the transaction, not
//! that it was included in a block or had its intended effect. That effect is
//! observed later (see `crate::indexer::tx_sender`) but otherwise only
//! aggregated into a prometheus counter. This buffer keeps a per-transaction
//! record (txid, nonce, signer access key, ...) so an operator can debug
//! failures such as out-of-order nonce rejections.

use near_account_id::AccountId;
use near_crypto::Signature;
use near_indexer_primitives::{
    CryptoHash,
    types::{BlockHeight, Nonce},
};
use near_mpc_contract_interface::types::Ed25519PublicKey;
use near_time::Utc;
use std::collections::VecDeque;
use std::fmt::Write;
use std::sync::{Arc, Mutex};

/// The most recent submitted transactions to retain; older entries are evicted
/// once the buffer is full.
const NUM_RECENT_TRANSACTIONS_TO_KEEP: usize = 2000;

/// Capacity of the channel that carries [`SubmittedTransaction`] records from
/// the indexer's transaction processor to the web server's drain task.
pub const RECENT_TRANSACTIONS_CHANNEL_SIZE: usize = 10000;

/// The observed lifecycle outcome of a submitted transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmittedTransactionStatus {
    /// Building, signing, or routing the transaction failed locally; it never
    /// reached the network.
    SubmitFailed,
    /// The transaction's intended effect was observed on chain.
    Executed,
    /// The transaction's intended effect was not observed before the timeout
    /// (it may have been rejected, e.g. for a stale nonce, or simply delayed).
    NotExecuted,
    /// The transaction type has no on-chain effect we verify, so the outcome is
    /// not determinable from contract state.
    Unknown,
    /// An error occurred while trying to observe the on-chain effect.
    ObserveError,
}

/// A single submitted transaction and its final status.
#[derive(Clone, Debug, PartialEq, Eq, derive_more::Display)]
#[display(
    "  {submitted_at}  {:<12}  method={method:<24}  signer={signer_account_id} key={}  {}",
    format!("{status:?}"),
    String::from(signer_public_key),
    metadata
        .as_ref()
        .map_or_else(|| "(not submitted)".to_string(), |m| m.to_string())
)]
pub struct SubmittedTransaction {
    /// The built-and-signed transaction details (txid, nonce, signature, block
    /// height). Absent if building/signing failed before they were produced;
    /// present otherwise, all together.
    pub metadata: Option<SubmittedTxMetadata>,
    /// The account the transaction was submitted from.
    pub signer_account_id: AccountId,
    /// The access key (public key) the transaction was signed with.
    pub signer_public_key: Ed25519PublicKey,
    /// The contract method invoked (e.g. `respond`, `respond_ckd`).
    pub method: &'static str,
    /// Wall-clock time at which the transaction was routed (or, on the
    /// submit-failed path, at which the failure was recorded). Captured at
    /// submission time, not when the outcome was later observed.
    pub submitted_at: Utc,
    /// The final observed outcome.
    pub status: SubmittedTransactionStatus,
}

/// The signer-specific context for a submission, known before the transaction
/// is built and shared by every record produced for that submission.
pub struct SignerContext {
    pub account_id: AccountId,
    pub public_key: Ed25519PublicKey,
    pub method: &'static str,
}

/// The metadata of a successfully built-and-submitted transaction, captured in
/// `crate::indexer::tx_sender`.
#[derive(Clone, Debug, PartialEq, Eq, derive_more::Display)]
#[display("txid={tx_hash}  nonce={nonce}  block={block_height}  sig={signature}")]
pub struct SubmittedTxMetadata {
    pub tx_hash: CryptoHash,
    pub nonce: Nonce,
    pub signature: Signature,
    pub block_height: BlockHeight,
}

impl SubmittedTransaction {
    /// A record for a transaction that was successfully built and routed, with
    /// its observed on-chain [`SubmittedTransactionStatus`]. `submitted_at` is
    /// the time the transaction was routed, captured by the caller before it
    /// waited to observe the outcome.
    pub fn submitted(
        signer: SignerContext,
        metadata: SubmittedTxMetadata,
        status: SubmittedTransactionStatus,
        submitted_at: Utc,
    ) -> Self {
        Self::new(signer, Some(metadata), status, submitted_at)
    }

    /// A record for a transaction that could not be built, signed, or routed and
    /// so never reached the network. `submitted_at` is the time the failure was
    /// recorded.
    pub fn submit_failed(signer: SignerContext, submitted_at: Utc) -> Self {
        Self::new(
            signer,
            None,
            SubmittedTransactionStatus::SubmitFailed,
            submitted_at,
        )
    }

    /// Builds a record from the signer context and, when the transaction was
    /// successfully built, its metadata.
    fn new(
        signer: SignerContext,
        metadata: Option<SubmittedTxMetadata>,
        status: SubmittedTransactionStatus,
        submitted_at: Utc,
    ) -> Self {
        Self {
            metadata,
            signer_account_id: signer.account_id,
            signer_public_key: signer.public_key,
            method: signer.method,
            submitted_at,
            status,
        }
    }
}

/// A bounded log of recently submitted transactions, one row per submission.
/// Newest entries are at the back; the oldest are evicted once the buffer is
/// full.
///
/// A row is recorded once, after its outcome is observed (or after a local
/// submit failure), so every row carries its final [`SubmittedTransactionStatus`]
/// and rows are never mutated in place.
#[derive(Default)]
pub struct RecentTransactions {
    /// One row per submission, front oldest / back newest.
    rows: VecDeque<SubmittedTransaction>,
}

impl RecentTransactions {
    /// Records a submitted (or submit-failed) transaction, evicting the oldest
    /// entry first if the buffer is full.
    pub fn record(&mut self, transaction: SubmittedTransaction) {
        if self.rows.len() >= NUM_RECENT_TRANSACTIONS_TO_KEEP {
            self.rows.pop_front();
        }
        self.rows.push_back(transaction);
    }

    /// Clones the retained entries, newest first, for rendering.
    pub fn snapshot(&self) -> Vec<SubmittedTransaction> {
        self.rows.iter().rev().cloned().collect()
    }

    /// Number of entries currently retained. Exposed for tests.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.rows.len()
    }
}

/// Shared handle to a [`RecentTransactions`] buffer: a cheap-to-clone owner of
/// the `Arc<Mutex<_>>` that the web server's drain task writes to and the
/// request handler reads from. Encapsulates the locking so callers never touch
/// the mutex directly.
#[derive(Clone, Default)]
pub struct SharedRecentTransactions(Arc<Mutex<RecentTransactions>>);

impl SharedRecentTransactions {
    /// Records one submitted (or submit-failed) transaction. See
    /// [`RecentTransactions::record`].
    pub fn record(&self, transaction: SubmittedTransaction) {
        self.0.lock().unwrap().record(transaction);
    }

    /// Returns the retained entries, newest first. See
    /// [`RecentTransactions::snapshot`].
    pub fn snapshot(&self) -> Vec<SubmittedTransaction> {
        self.0.lock().unwrap().snapshot()
    }
}

/// Renders a snapshot (newest first, as returned by
/// [`RecentTransactions::snapshot`]) into the human-readable page served at
/// `/debug/recent_transactions`.
pub fn render(transactions: &[SubmittedTransaction]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Recently submitted transactions (newest first, up to {NUM_RECENT_TRANSACTIONS_TO_KEEP} retained):"
    );
    if transactions.is_empty() {
        let _ = writeln!(out, "  (none)");
        return out;
    }
    for tx in transactions {
        let _ = writeln!(out, "{tx}");
    }
    out
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// A submitted (Executed) transaction whose hash is fixed
    /// (`CryptoHash::default()`). Used by the `Display` tests, which pin the
    /// exact rendered txid. Buffer tests that keep entries distinct should use
    /// [`test_transaction_with_hash`].
    fn test_transaction(method: &'static str) -> SubmittedTransaction {
        test_transaction_with_hash(method, CryptoHash::default())
    }

    /// A submitted (Executed) transaction with the given method and hash.
    fn test_transaction_with_hash(
        method: &'static str,
        tx_hash: CryptoHash,
    ) -> SubmittedTransaction {
        SubmittedTransaction {
            metadata: Some(SubmittedTxMetadata {
                tx_hash,
                nonce: 7,
                signature: Signature::empty(near_crypto::KeyType::ED25519),
                block_height: 42,
            }),
            signer_account_id: AccountId::from_str("responder.near").unwrap(),
            signer_public_key: Ed25519PublicKey::from([7u8; 32]),
            method,
            submitted_at: Utc::from_unix_timestamp(1_700_000_000).unwrap(),
            status: SubmittedTransactionStatus::Executed,
        }
    }

    /// A distinct hash per index, so buffer tests can keep many entries apart.
    fn hash(i: u64) -> CryptoHash {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&i.to_le_bytes());
        CryptoHash(bytes)
    }

    #[test]
    fn recent_transactions__should_keep_only_most_recent_when_over_capacity() {
        // Given
        let mut buffer = RecentTransactions::default();

        // When
        for i in 0..(NUM_RECENT_TRANSACTIONS_TO_KEEP as u64 + 50) {
            buffer.record(test_transaction_with_hash("respond", hash(i)));
        }

        // Then
        assert_eq!(buffer.len(), NUM_RECENT_TRANSACTIONS_TO_KEEP);
    }

    #[test]
    fn recent_transactions__should_record_one_row_per_submission_newest_first() {
        // Given three interleaved submissions.
        let (a, b, c) = (
            test_transaction_with_hash("a", hash(1)),
            test_transaction_with_hash("b", hash(2)),
            test_transaction_with_hash("c", hash(3)),
        );
        let mut buffer = RecentTransactions::default();

        // When
        buffer.record(a.clone());
        buffer.record(b.clone());
        buffer.record(c.clone());

        // Then each is its own row, newest first.
        assert_eq!(buffer.snapshot(), vec![c, b, a]);
    }

    #[test]
    fn recent_transactions__should_keep_both_rows_for_a_repeated_tx_hash() {
        // Given two submissions that (defensively) share a tx hash. The page must
        // faithfully list every submission, so neither is merged or dropped.
        let first = test_transaction_with_hash("respond", hash(1));
        let second = SubmittedTransaction {
            method: "respond_again",
            ..test_transaction_with_hash("respond_again", hash(1))
        };
        let mut buffer = RecentTransactions::default();

        // When
        buffer.record(first.clone());
        buffer.record(second.clone());

        // Then both rows are retained, newest first.
        assert_eq!(buffer.snapshot(), vec![second, first]);
    }

    #[test]
    fn recent_transactions__should_keep_submit_failed_row_in_order() {
        // Given a submit-failed row (no metadata) interleaved with a submitted one.
        let failed = SubmittedTransaction {
            metadata: None,
            status: SubmittedTransactionStatus::SubmitFailed,
            ..test_transaction("failed")
        };
        let submitted = test_transaction_with_hash("respond", hash(1));
        let mut buffer = RecentTransactions::default();

        // When
        buffer.record(submitted.clone());
        buffer.record(failed.clone());

        // Then the failed row appears in the snapshot, newest first.
        assert_eq!(buffer.snapshot(), vec![failed, submitted]);
    }

    #[test]
    fn submitted_transaction_display__should_render_exact_line_with_padding() {
        // Given
        let transaction = test_transaction("respond");

        // When
        let rendered = transaction.to_string();

        // Then
        let expected = "  2023-11-14 22:13:20.0 +00:00:00  Executed      method=respond                   signer=responder.near key=ed25519:US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx  txid=11111111111111111111111111111111  nonce=7  block=42  sig=ed25519:1111111111111111111111111111111111111111111111111111111111111111";
        assert_eq!(rendered, expected);
    }

    #[test]
    fn submitted_transaction_display__should_render_marker_without_metadata() {
        // Given
        let transaction = SubmittedTransaction {
            metadata: None,
            status: SubmittedTransactionStatus::SubmitFailed,
            ..test_transaction("respond")
        };

        // When
        let rendered = transaction.to_string();

        // Then
        let expected = "  2023-11-14 22:13:20.0 +00:00:00  SubmitFailed  method=respond                   signer=responder.near key=ed25519:US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx  (not submitted)";
        assert_eq!(rendered, expected);
    }

    #[test]
    fn render__should_report_empty_buffer() {
        // Given
        let buffer = RecentTransactions::default();

        // When
        let rendered = render(&buffer.snapshot());

        // Then
        let expected = format!(
            "Recently submitted transactions (newest first, up to {NUM_RECENT_TRANSACTIONS_TO_KEEP} retained):\n  (none)\n"
        );
        assert_eq!(rendered, expected);
    }

    #[test]
    fn snapshot__should_return_entries_newest_first() {
        // Given
        let oldest = test_transaction_with_hash("respond", hash(1));
        let newest = test_transaction_with_hash("respond_ckd", hash(2));
        let mut buffer = RecentTransactions::default();
        buffer.record(oldest.clone());
        buffer.record(newest.clone());

        // When
        let snapshot = buffer.snapshot();

        // Then
        assert_eq!(snapshot, vec![newest, oldest]);
    }
}
