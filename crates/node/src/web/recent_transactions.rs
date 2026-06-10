//! In-memory storage and rendering for the `/debug/recent_transactions` web
//! page. The record types live in `crate::types`, so neither the indexer nor
//! this module depends on the other.
//!
//! A successful submission only means the RPC accepted the transaction, not
//! that it was included in a block or had its intended effect. That effect is
//! observed later (see `crate::indexer::tx_sender`) but otherwise only
//! aggregated into a prometheus counter. This buffer keeps a per-transaction
//! record (txid, nonce, signer access key, ...) so an operator can debug
//! failures such as out-of-order nonce rejections.

use crate::types::{SubmittedTransaction, TransactionLogger};
use std::collections::VecDeque;
use std::fmt::Write;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// The most recent submitted transactions to retain; older entries are evicted
/// once the buffer is full.
const NUM_RECENT_TRANSACTIONS_TO_KEEP: usize = 2000;

/// Capacity of the channel carrying [`SubmittedTransaction`] records from the
/// indexer's transaction processor to the drain task spawned in `run.rs`. One
/// record per submitted transaction, so a full channel (a dropped record) is
/// not expected in practice; sized to cap worst-case memory.
pub const RECENT_TRANSACTIONS_CHANNEL_SIZE: usize = 10000;

/// A bounded log of recently submitted transactions, one row per submission.
/// Newest entries are at the back; the oldest are evicted once the buffer is
/// full.
///
/// A row is recorded once, after its outcome is observed (or after a local
/// submit failure), so every row carries its final
/// [`SubmittedTransactionStatus`](crate::types::SubmittedTransactionStatus) and
/// rows are never mutated in place.
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

/// Shared handle to a [`RecentTransactions`] buffer. It is fed over a bounded
/// channel by the indexer's [`RecentTransactionsLogger`], drained into it by the
/// task [`spawn_recent_transactions_drain`] starts in `run.rs`, and read by the
/// request handler, with the synchronization encapsulated so callers just
/// `record` and `snapshot`.
#[derive(Clone, Default)]
pub struct SharedRecentTransactions(Arc<Mutex<RecentTransactions>>);

impl SharedRecentTransactions {
    /// Records one submitted (or submit-failed) transaction. See
    /// [`RecentTransactions::record`].
    pub fn record(&self, transaction: SubmittedTransaction) {
        self.0
            .lock()
            .expect("lock must not be poisoned")
            .record(transaction);
    }

    /// Returns the retained entries, newest first. See
    /// [`RecentTransactions::snapshot`].
    pub fn snapshot(&self) -> Vec<SubmittedTransaction> {
        self.0.lock().expect("lock must not be poisoned").snapshot()
    }
}

/// [`TransactionLogger`] that forwards records over a bounded channel to the
/// drain task spawned in `run.rs`.
#[derive(Clone)]
pub struct RecentTransactionsLogger {
    sender: mpsc::Sender<SubmittedTransaction>,
}

impl RecentTransactionsLogger {
    /// Wraps the producing end of the recent-transactions channel; the
    /// consuming end is drained by [`spawn_recent_transactions_drain`].
    pub fn new(sender: mpsc::Sender<SubmittedTransaction>) -> Self {
        Self { sender }
    }
}

impl TransactionLogger for RecentTransactionsLogger {
    fn log_transaction(&self, transaction: SubmittedTransaction) {
        match self.sender.try_send(transaction) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!(
                    target: "mpc",
                    "recent-transactions channel full; dropping debug record"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!(
                    target: "mpc",
                    "recent-transactions drain task gone; dropping debug record"
                );
            }
        }
    }
}

/// Spawns the task that drains the recent-transactions channel into `buffer`,
/// recording each record the indexer's [`RecentTransactionsLogger`] forwards.
/// The loop ends if every sender drops (`recv` returns `None`); at shutdown the
/// task is usually just aborted when the runtime is dropped. Must be called
/// within a Tokio runtime.
pub fn spawn_recent_transactions_drain(
    mut receiver: mpsc::Receiver<SubmittedTransaction>,
    buffer: SharedRecentTransactions,
) {
    tokio::spawn(async move {
        while let Some(transaction) = receiver.recv().await {
            buffer.record(transaction);
        }
        tracing::warn!(
            target: "mpc",
            "recent-transactions channel closed; drain task exiting"
        );
    });
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
    use crate::types::{SubmittedTransactionStatus, SubmittedTxMetadata};
    use near_account_id::AccountId;
    use near_crypto::Signature;
    use near_indexer_primitives::CryptoHash;
    use near_mpc_contract_interface::types::Ed25519PublicKey;
    use near_time::Utc;
    use std::str::FromStr;

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
            ..test_transaction_with_hash("failed", CryptoHash::default())
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
