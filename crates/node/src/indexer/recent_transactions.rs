//! In-memory record of recently submitted transactions, shown on the
//! `/debug/recent_transactions` web page.
//!
//! A successful submission only means the RPC accepted the transaction, not
//! that it was included in a block or had its intended effect. That effect is
//! observed later (see [`super::tx_sender`]) but otherwise only aggregated into
//! a prometheus counter. This buffer keeps a per-transaction record (txid,
//! nonce, signer access key, ...) so an operator can debug failures such as
//! out-of-order nonce rejections.
//!
//! Unlike the other debug pages (recent blocks/signatures/CKDs), which pull
//! their data from the MPC client on demand and so only work while the node is
//! `Running`, this buffer is written by the always-on transaction processor
//! (see [`super::tx_sender`]) and shared directly with the web server as
//! `Arc<Mutex<RecentTransactions>>`. The node submits transactions even while
//! not `Running` (e.g. `vote_pk` while `Initializing`), and those states are
//! exactly when an operator needs to inspect submission failures, so reading
//! the buffer directly keeps the page available regardless of the node's
//! running state.

use near_account_id::AccountId;
use near_crypto::Signature;
use near_indexer_primitives::{
    CryptoHash,
    types::{BlockHeight, Nonce},
};
use near_mpc_contract_interface::types::Ed25519PublicKey;
use near_time::{Clock, Utc};
use std::collections::VecDeque;
use std::fmt::Write;

/// The most recent submitted transactions to retain; older entries are evicted
/// once the buffer is full.
const NUM_RECENT_TRANSACTIONS_TO_KEEP: usize = 2000;

/// The observed lifecycle outcome of a submitted transaction. Every variant
/// except `Submitting` is recorded as an `outcome` label on the
/// `MPC_OUTGOING_TRANSACTION_OUTCOMES` metric (in
/// [`super::tx_sender::ensure_send_transaction`]), so the page and the metric
/// stay in step. `Submitting` is the pending state before an outcome is
/// observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmittedTransactionStatus {
    /// The transaction was routed and we are waiting to observe its effect.
    Submitting,
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

/// A single submitted transaction and its current status.
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
    /// Wall-clock time at which the transaction was recorded as submitted.
    pub submitted_at: Utc,
    /// The current observed outcome.
    pub status: SubmittedTransactionStatus,
}

/// The signer-specific context for a submission, known before the transaction
/// is built and shared by every record produced for that submission.
pub struct SignerContext {
    pub account_id: AccountId,
    pub public_key: Ed25519PublicKey,
    pub method: &'static str,
}

/// The metadata of a successfully built-and-submitted transaction, captured by
/// [`super::tx_sender::submit_tx`].
#[derive(Clone, Debug, PartialEq, Eq, derive_more::Display)]
#[display("txid={tx_hash}  nonce={nonce}  block={block_height}  sig={signature}")]
pub struct SubmittedTxMetadata {
    pub tx_hash: CryptoHash,
    pub nonce: Nonce,
    pub signature: Signature,
    pub block_height: BlockHeight,
}

impl SubmittedTransaction {
    /// A record for a transaction that was successfully built and routed and is
    /// now awaiting on-chain observation.
    pub fn submitting(signer: SignerContext, metadata: SubmittedTxMetadata) -> Self {
        Self::new(
            signer,
            Some(metadata),
            SubmittedTransactionStatus::Submitting,
        )
    }

    /// A record for a transaction that could not be built, signed, or routed and
    /// so never reached the network.
    pub fn submit_failed(signer: SignerContext) -> Self {
        Self::new(signer, None, SubmittedTransactionStatus::SubmitFailed)
    }

    /// Builds a record from the signer context and, when the transaction was
    /// successfully built, its metadata.
    fn new(
        signer: SignerContext,
        metadata: Option<SubmittedTxMetadata>,
        status: SubmittedTransactionStatus,
    ) -> Self {
        Self {
            metadata,
            signer_account_id: signer.account_id,
            signer_public_key: signer.public_key,
            method: signer.method,
            submitted_at: Clock::real().now_utc(),
            status,
        }
    }
}

/// Identifies one recorded transaction so its status can be updated later.
///
/// Ids are assigned from a monotonically increasing counter, one per recorded
/// transaction, and never reused. Because the buffer is a strict FIFO (one
/// entry pushed per id, oldest evicted first), the live ids are always a
/// contiguous range and an id maps to a deque position by subtraction. A
/// submission is recorded immediately, but its outcome is only known after a
/// timeout (see `tx_sender::ensure_send_transaction`), by which point newer
/// submissions may have evicted the entry; [`RecentTransactions::update_status`]
/// then finds it in O(1) if it still exists and no-ops if it was evicted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionRecordId(u64);

/// A bounded log of recently submitted transactions. Newest entries are at the
/// back; the oldest are evicted once the buffer is full.
///
/// Entries are stored in id order, so lookup by [`TransactionRecordId`] is O(1)
/// with no auxiliary index: the entry for id `q` (when live) is at deque index
/// `q - (next_id - len)`.
///
/// Not internally synchronized: it is shared as `Arc<Mutex<RecentTransactions>>`
/// and every method runs under the caller's lock, so concurrent
/// `record_submitted` / `update_status` / `snapshot` calls are serialized.
#[derive(Default)]
pub struct RecentTransactions {
    /// Retained transactions in id order; front is oldest, back is newest.
    entries: VecDeque<SubmittedTransaction>,
    /// Monotonically increasing id assigned to the next recorded transaction.
    next_id: u64,
}

impl RecentTransactions {
    /// Records a newly submitted transaction, evicting the oldest entry if the
    /// buffer is full. Returns a handle that can later update the entry's
    /// status via [`Self::update_status`].
    pub fn record_submitted(&mut self, transaction: SubmittedTransaction) -> TransactionRecordId {
        let id = TransactionRecordId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);

        if self.entries.len() >= NUM_RECENT_TRANSACTIONS_TO_KEEP {
            self.entries.pop_front();
        }
        self.entries.push_back(transaction);
        id
    }

    /// Deque index of the entry with the given id, or `None` if it was evicted
    /// (id below the oldest live id) or never issued (id at or after
    /// `next_id`). The live window is `[next_id - len, next_id)`; it is empty
    /// when the buffer is empty. The subtraction runs only after the
    /// lower-bound check, so it cannot underflow, and the result is
    /// `< len <= NUM_RECENT_TRANSACTIONS_TO_KEEP`.
    ///
    /// Example: after 5 records of which the oldest 2 were evicted, the buffer
    /// holds ids 2, 3, 4 (front to back) with `next_id == 5`, so
    /// `oldest_id == 5 - 3 == 2` and the live window is `2..5`. Then:
    /// - id 3 -> `Some(3 - 2) == Some(1)` (the middle entry),
    /// - id 2 -> `Some(0)` (the front, oldest live entry),
    /// - id 0 -> `None` (below the window: evicted),
    /// - id 5 -> `None` (at `next_id`: never issued).
    fn index_of(&self, id: TransactionRecordId) -> Option<usize> {
        let oldest_id = self.next_id - self.entries.len() as u64;
        (oldest_id..self.next_id)
            .contains(&id.0)
            .then(|| (id.0 - oldest_id) as usize)
    }

    /// Updates the status of a previously recorded transaction in O(1). A no-op
    /// if the entry has already been evicted.
    pub fn update_status(&mut self, id: TransactionRecordId, status: SubmittedTransactionStatus) {
        // `index_of` only returns indices within `0..len`, so direct indexing
        // cannot panic.
        if let Some(index) = self.index_of(id) {
            self.entries[index].status = status;
        }
    }

    /// Clones the retained entries, newest first, for rendering. The clone lets
    /// the caller drop the lock before doing the (potentially non-trivial)
    /// string formatting, so it does not block concurrent `record_submitted` /
    /// `update_status` writes from the transaction processor.
    pub fn snapshot(&self) -> Vec<SubmittedTransaction> {
        self.entries.iter().rev().cloned().collect()
    }

    /// Number of entries currently retained. Exposed for tests.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
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

    fn test_transaction(method: &'static str) -> SubmittedTransaction {
        SubmittedTransaction {
            metadata: Some(SubmittedTxMetadata {
                tx_hash: CryptoHash::default(),
                nonce: 7,
                signature: Signature::empty(near_crypto::KeyType::ED25519),
                block_height: 42,
            }),
            signer_account_id: AccountId::from_str("responder.near").unwrap(),
            signer_public_key: Ed25519PublicKey::from([7u8; 32]),
            method,
            submitted_at: Utc::from_unix_timestamp(1_700_000_000).unwrap(),
            status: SubmittedTransactionStatus::Submitting,
        }
    }

    #[test]
    fn recent_transactions__should_keep_only_most_recent_when_over_capacity() {
        // Given
        let mut buffer = RecentTransactions::default();

        // When
        for _ in 0..(NUM_RECENT_TRANSACTIONS_TO_KEEP + 50) {
            buffer.record_submitted(test_transaction("respond"));
        }

        // Then
        assert_eq!(buffer.len(), NUM_RECENT_TRANSACTIONS_TO_KEEP);
    }

    #[test]
    fn recent_transactions__should_update_status_in_place() {
        // Given
        let transaction = test_transaction("respond");
        let mut buffer = RecentTransactions::default();
        let id = buffer.record_submitted(transaction.clone());

        // When
        buffer.update_status(id, SubmittedTransactionStatus::Executed);

        // Then
        let expected = SubmittedTransaction {
            status: SubmittedTransactionStatus::Executed,
            ..transaction
        };
        assert_eq!(buffer.entries, VecDeque::from([expected]));
    }

    #[test]
    fn recent_transactions__should_update_buried_entry() {
        // Given a buffer where the target is at the very front (maximally buried
        // but not yet evicted), which is the realistic case: the outcome is only
        // observed after a timeout, by which point many newer entries sit behind
        // it.
        let buried_tx = test_transaction("buried");
        let mut buffer = RecentTransactions::default();
        let buried_id = buffer.record_submitted(buried_tx.clone());
        for _ in 0..(NUM_RECENT_TRANSACTIONS_TO_KEEP - 1) {
            buffer.record_submitted(test_transaction("respond"));
        }

        // When
        buffer.update_status(buried_id, SubmittedTransactionStatus::Executed);

        // Then only the buried (oldest) entry changed.
        let snapshot = buffer.snapshot();
        let buried = snapshot.last().expect("buffer is non-empty");
        let expected = SubmittedTransaction {
            status: SubmittedTransactionStatus::Executed,
            ..buried_tx
        };
        assert_eq!(*buried, expected);
        assert!(
            snapshot[..snapshot.len() - 1]
                .iter()
                .all(|tx| tx.status == SubmittedTransactionStatus::Submitting),
            "only the targeted entry should change"
        );
    }

    #[test]
    fn recent_transactions__should_ignore_status_update_for_evicted_entry() {
        // Given an entry that is then evicted by enough newer submissions.
        let mut buffer = RecentTransactions::default();
        let evicted_id = buffer.record_submitted(test_transaction("evicted"));
        for _ in 0..NUM_RECENT_TRANSACTIONS_TO_KEEP {
            buffer.record_submitted(test_transaction("respond"));
        }

        // When
        buffer.update_status(evicted_id, SubmittedTransactionStatus::Executed);

        // Then the evicted entry is gone and no retained entry was changed.
        let snapshot = buffer.snapshot();
        assert_eq!(snapshot.len(), NUM_RECENT_TRANSACTIONS_TO_KEEP);
        assert!(
            snapshot.iter().all(|tx| tx.method == "respond"),
            "evicted entry must not reappear"
        );
        assert!(
            snapshot
                .iter()
                .all(|tx| tx.status == SubmittedTransactionStatus::Submitting),
            "update for an evicted id must not land on a live entry"
        );
    }

    #[test]
    fn recent_transactions__should_ignore_status_update_for_never_issued_id() {
        // Given
        let transaction = test_transaction("respond");
        let mut buffer = RecentTransactions::default();
        buffer.record_submitted(transaction.clone());

        // When updating ids at and beyond `next_id` (never issued)
        buffer.update_status(
            TransactionRecordId(buffer.next_id),
            SubmittedTransactionStatus::Executed,
        );
        buffer.update_status(
            TransactionRecordId(buffer.next_id + 5),
            SubmittedTransactionStatus::Executed,
        );

        // Then the live entry is untouched.
        assert_eq!(buffer.snapshot(), vec![transaction]);
    }

    #[test]
    fn recent_transactions__should_ignore_status_update_on_empty_buffer() {
        // Given
        let mut buffer = RecentTransactions::default();

        // When
        buffer.update_status(TransactionRecordId(0), SubmittedTransactionStatus::Executed);

        // Then it does not panic and stays empty.
        assert_eq!(buffer.snapshot(), vec![]);
    }

    #[test]
    fn recent_transactions__should_update_only_the_targeted_entry() {
        // Given three interleaved entries
        let (a, b, c) = (
            test_transaction("a"),
            test_transaction("b"),
            test_transaction("c"),
        );
        let mut buffer = RecentTransactions::default();
        buffer.record_submitted(a.clone());
        let id_b = buffer.record_submitted(b.clone());
        buffer.record_submitted(c.clone());

        // When
        buffer.update_status(id_b, SubmittedTransactionStatus::Executed);

        // Then only b changed and the snapshot is newest-first.
        let executed_b = SubmittedTransaction {
            status: SubmittedTransactionStatus::Executed,
            ..b
        };
        assert_eq!(buffer.snapshot(), vec![c, executed_b, a]);
    }

    #[test]
    fn submitted_transaction_display__should_render_exact_line_with_padding() {
        // Given
        let transaction = test_transaction("respond");

        // When
        let rendered = transaction.to_string();

        // Then
        let expected = "  2023-11-14 22:13:20.0 +00:00:00  Submitting    method=respond                   signer=responder.near key=ed25519:US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx  txid=11111111111111111111111111111111  nonce=7  block=42  sig=ed25519:1111111111111111111111111111111111111111111111111111111111111111";
        assert_eq!(rendered, expected);
    }

    #[test]
    fn submitted_transaction_display__should_render_marker_without_metadata() {
        // Given
        let transaction = SubmittedTransaction {
            metadata: None,
            ..test_transaction("respond")
        };

        // When
        let rendered = transaction.to_string();

        // Then
        let expected = "  2023-11-14 22:13:20.0 +00:00:00  Submitting    method=respond                   signer=responder.near key=ed25519:US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx  (not submitted)";
        assert_eq!(rendered, expected);
    }

    #[test]
    fn render__should_report_empty_buffer() {
        // Given
        let buffer = RecentTransactions::default();

        // When
        let rendered = render(&buffer.snapshot());

        // Then
        assert!(
            rendered.contains("(none)"),
            "empty buffer must render `(none)`: {rendered}"
        );
    }

    #[test]
    fn snapshot__should_return_entries_newest_first() {
        // Given
        let mut buffer = RecentTransactions::default();
        buffer.record_submitted(test_transaction("respond"));
        buffer.record_submitted(test_transaction("respond_ckd"));

        // When
        let snapshot = buffer.snapshot();

        // Then
        let methods: Vec<&str> = snapshot.iter().map(|tx| tx.method).collect();
        assert_eq!(methods, vec!["respond_ckd", "respond"]);
    }
}
