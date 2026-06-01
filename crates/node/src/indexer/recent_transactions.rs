//! In-memory record of recently submitted transactions, surfaced on the
//! `/debug/recent_transactions` web endpoint.
//!
//! Nodes submit transactions to the chain "fire and forget": a successful
//! submission only means the transaction was routed, not that it was included
//! or had its intended effect. The transaction processor already observes the
//! on-chain effect after a delay (see [`super::tx_sender`]), but that outcome
//! is otherwise only aggregated into a prometheus counter. This buffer keeps a
//! per-transaction record so an operator can see exactly which transactions a
//! node submitted, with enough detail (txid, nonce, signer access key, ...) to
//! debug failures such as out-of-order nonce rejections.

use near_account_id::AccountId;
use near_crypto::Signature;
use near_indexer_primitives::CryptoHash;
use near_indexer_primitives::types::{BlockHeight, Nonce};
use near_mpc_contract_interface::types::Ed25519PublicKey;
use near_time::{Clock, Utc};
use std::collections::VecDeque;
use std::fmt::{self, Display};

/// The most recent submitted transactions to retain. Each entry is small, so a
/// generous bound is fine; older entries are evicted once the buffer is full.
const NUM_RECENT_TRANSACTIONS_TO_KEEP: usize = 200;

/// The observed lifecycle outcome of a submitted transaction. The terminal
/// variants mirror the arms of `MPC_OUTGOING_TRANSACTION_OUTCOMES` recorded in
/// [`super::tx_sender::ensure_send_transaction`], so the page and the metric
/// never disagree.
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmittedTransaction {
    /// The transaction hash (txid), present once the transaction was built and
    /// signed. Absent if building/signing failed before a hash was computed.
    pub tx_hash: Option<CryptoHash>,
    /// The nonce of the access key the transaction was signed with. Each access
    /// key has an independent nonce sequence, so this is reported alongside the
    /// signer key.
    pub nonce: Option<Nonce>,
    /// The account the transaction was submitted from.
    pub signer_account_id: AccountId,
    /// The access key (public key) the transaction was signed with.
    pub signer_public_key: Ed25519PublicKey,
    /// The signature over the transaction. Absent if building/signing failed
    /// before a signed transaction was produced.
    pub signature: Option<Signature>,
    /// The contract method invoked (e.g. `respond`, `respond_ckd`).
    pub method: &'static str,
    /// The height of the reference block the transaction was built against.
    pub block_height: Option<BlockHeight>,
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
        Self {
            tx_hash: Some(metadata.tx_hash),
            nonce: Some(metadata.nonce),
            signer_account_id: signer.account_id,
            signer_public_key: signer.public_key,
            signature: Some(metadata.signature),
            method: signer.method,
            block_height: Some(metadata.block_height),
            submitted_at: Clock::real().now_utc(),
            status: SubmittedTransactionStatus::Submitting,
        }
    }

    /// A record for a transaction that could not be built, signed, or routed and
    /// so never reached the network.
    pub fn submit_failed(signer: SignerContext) -> Self {
        Self {
            tx_hash: None,
            nonce: None,
            signer_account_id: signer.account_id,
            signer_public_key: signer.public_key,
            signature: None,
            method: signer.method,
            block_height: None,
            submitted_at: Clock::real().now_utc(),
            status: SubmittedTransactionStatus::SubmitFailed,
        }
    }
}

/// Opaque handle to an entry, used to update its status later. The entry may
/// have been evicted by the time the update arrives, in which case the update
/// is a no-op.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionRecordId(u64);

/// A bounded, append-mostly log of recently submitted transactions. Newest
/// entries are at the back; the oldest are evicted once the buffer is full.
pub struct RecentTransactions {
    entries: VecDeque<(TransactionRecordId, SubmittedTransaction)>,
    /// Monotonically increasing id assigned to the next recorded transaction.
    next_id: u64,
}

impl Default for RecentTransactions {
    fn default() -> Self {
        Self {
            entries: VecDeque::with_capacity(NUM_RECENT_TRANSACTIONS_TO_KEEP),
            next_id: 0,
        }
    }
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
        self.entries.push_back((id, transaction));
        id
    }

    /// Updates the status of a previously recorded transaction. A no-op if the
    /// entry has already been evicted.
    pub fn update_status(&mut self, id: TransactionRecordId, status: SubmittedTransactionStatus) {
        // The entry being updated was almost always the most recently recorded
        // one, so scan from the back to find it in O(1) for the common case.
        if let Some((_, transaction)) = self
            .entries
            .iter_mut()
            .rev()
            .find(|(entry_id, _)| *entry_id == id)
        {
            transaction.status = status;
        }
    }

    /// Clones the retained entries, newest first, for rendering. The clone lets
    /// the caller drop the lock before doing the (potentially non-trivial)
    /// string formatting, so it does not block concurrent `record_submitted` /
    /// `update_status` writes from the transaction processor.
    pub fn snapshot(&self) -> Vec<SubmittedTransaction> {
        self.entries
            .iter()
            .rev()
            .map(|(_, tx)| tx.clone())
            .collect()
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
    use std::fmt::Write;

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

impl Display for SubmittedTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tx_hash = self
            .tx_hash
            .map_or_else(|| "-".to_string(), |hash| hash.to_string());
        let nonce = self
            .nonce
            .map_or_else(|| "-".to_string(), |nonce| nonce.to_string());
        let block_height = self
            .block_height
            .map_or_else(|| "-".to_string(), |height| height.to_string());
        let signature = self
            .signature
            .as_ref()
            .map_or_else(|| "-".to_string(), |signature| signature.to_string());
        write!(
            f,
            "  {submitted_at}  {status:<12}  method={method:<24}  txid={tx_hash}  nonce={nonce}  block={block_height}  signer={signer_account_id} key={signer_public_key} sig={signature}",
            submitted_at = self.submitted_at,
            status = format!("{:?}", self.status),
            method = self.method,
            signer_account_id = self.signer_account_id,
            signer_public_key = String::from(&self.signer_public_key),
        )
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn test_transaction(method: &'static str) -> SubmittedTransaction {
        SubmittedTransaction {
            tx_hash: Some(CryptoHash::default()),
            nonce: Some(7),
            signer_account_id: AccountId::from_str("responder.near").unwrap(),
            signer_public_key: Ed25519PublicKey::from([7u8; 32]),
            signature: Some(Signature::empty(near_crypto::KeyType::ED25519)),
            method,
            block_height: Some(42),
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
        let mut buffer = RecentTransactions::default();
        let id = buffer.record_submitted(test_transaction("respond"));

        // When
        buffer.update_status(id, SubmittedTransactionStatus::Executed);

        // Then
        let expected = SubmittedTransaction {
            status: SubmittedTransactionStatus::Executed,
            ..test_transaction("respond")
        };
        assert_eq!(buffer.entries, VecDeque::from([(id, expected)]),);
    }

    #[test]
    fn recent_transactions__should_ignore_status_update_for_evicted_entry() {
        // Given
        let mut buffer = RecentTransactions::default();
        let evicted_id = buffer.record_submitted(test_transaction("respond"));
        for _ in 0..NUM_RECENT_TRANSACTIONS_TO_KEEP {
            buffer.record_submitted(test_transaction("respond"));
        }

        // When
        buffer.update_status(evicted_id, SubmittedTransactionStatus::Executed);

        // Then
        assert_eq!(buffer.len(), NUM_RECENT_TRANSACTIONS_TO_KEEP);
        assert!(
            buffer.entries.iter().all(|(id, _)| *id != evicted_id),
            "evicted entry must not reappear"
        );
    }

    #[test]
    fn render__should_include_all_fields() {
        // Given
        let mut buffer = RecentTransactions::default();
        buffer.record_submitted(test_transaction("respond"));

        // When
        let rendered = render(&buffer.snapshot());

        // Then
        assert!(rendered.contains("respond"), "method missing: {rendered}");
        assert!(rendered.contains("nonce=7"), "nonce missing: {rendered}");
        assert!(
            rendered.contains("block=42"),
            "block height missing: {rendered}"
        );
        assert!(
            rendered.contains("responder.near"),
            "signer account missing: {rendered}"
        );
        assert!(
            rendered.contains("key=ed25519:"),
            "signer key not rendered in canonical form: {rendered}"
        );
        assert!(
            rendered.contains("sig=ed25519:"),
            "signature not rendered in canonical form: {rendered}"
        );
        assert!(
            rendered.contains(&CryptoHash::default().to_string()),
            "txid missing: {rendered}"
        );
        assert!(
            rendered.contains("Submitting"),
            "status missing: {rendered}"
        );
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
