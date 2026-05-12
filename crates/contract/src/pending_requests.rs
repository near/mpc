//! FIFO chain of yield-resume promises per pending request.
//!
//! When a duplicate request lands while the original is still in flight, we
//! cannot reuse the original yield (NEAR binds each yield's resumption to the
//! transaction that called `promise_yield_create`). Instead we append the new
//! yield to a FIFO chain rooted at the original request. `respond` only resumes
//! the head; each callback walks one link forward and resumes the next using
//! its own caller's reserved `callback_gas`, so `respond` stays O(1) regardless
//! of chain depth.
//!
//! Both maps below are keyed by `CryptoHash` (the yield `data_id`), which is
//! globally unique, so one `ChainState` instance is shared across all three
//! request types (sign / CKD / verify-foreign-tx).
//!
//! Invariants:
//! - `pending[k]` always points to the *current* head of the chain.
//! - `next[d]` exists iff `d` has a successor; the tail has no entry in `next`.
//! - `tail_of_head[d]` exists iff `d` is the current head and chain length > 1.
//!   When the head advances, this entry is re-keyed under the new head (or
//!   removed if the chain collapses to length 1).

use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::{near, store::LookupMap, CryptoHash};
use serde::{Deserialize, Serialize};

use crate::{primitives::signature::YieldIndex, storage_keys::StorageKey};

#[derive(Debug)]
#[near(serializers = [borsh])]
pub struct ChainState {
    /// `prev_data_id → next_data_id`. One entry per non-tail link in any chain.
    next: LookupMap<CryptoHash, CryptoHash>,
    /// `current_head_data_id → tail_data_id`. Present iff chain length > 1.
    tail_of_head: LookupMap<CryptoHash, CryptoHash>,
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainState {
    pub fn new() -> Self {
        Self {
            next: LookupMap::new(StorageKey::YieldChainNext),
            tail_of_head: LookupMap::new(StorageKey::YieldChainTail),
        }
    }

    /// Append `new_data_id` to the chain rooted at `k`. Returns `true` if `k`
    /// already had a pending entry (the chain was extended) and `false` if
    /// this is the first request for `k`.
    pub fn enqueue<K>(
        &mut self,
        pending: &mut LookupMap<K, YieldIndex>,
        k: &K,
        new_data_id: CryptoHash,
    ) -> bool
    where
        K: BorshSerialize + BorshDeserialize + Ord + Clone,
    {
        if let Some(head) = pending.get(k).cloned() {
            let old_tail = self
                .tail_of_head
                .get(&head.data_id)
                .copied()
                .unwrap_or(head.data_id);
            self.next.insert(old_tail, new_data_id);
            self.tail_of_head.insert(head.data_id, new_data_id);
            true
        } else {
            pending.insert(
                k.clone(),
                YieldIndex {
                    data_id: new_data_id,
                },
            );
            false
        }
    }

    /// Advance the chain rooted at `k` by one link. Called from the resumed
    /// callback. If the current head has a successor, advances the head
    /// pointer to it (re-keying the tail entry) and returns its `data_id` so
    /// the caller can `promise_yield_resume` it. Otherwise removes the chain
    /// entirely and returns `None`. Also returns `None` if there is no head
    /// at all — a defensive no-op for the rare callback that fires after the
    /// pending entry has already been removed (e.g. concurrent cleanup paths).
    pub fn advance<K>(
        &mut self,
        pending: &mut LookupMap<K, YieldIndex>,
        k: &K,
    ) -> Option<CryptoHash>
    where
        K: BorshSerialize + BorshDeserialize + Ord + Clone,
    {
        let head_data_id = pending.get(k).map(|y| y.data_id)?;

        if let Some(next_data_id) = self.next.remove(&head_data_id) {
            pending.insert(
                k.clone(),
                YieldIndex {
                    data_id: next_data_id,
                },
            );
            // Re-key the tail pointer under the new head, unless the new head
            // is itself the tail (chain just collapsed to length 1).
            if let Some(tail) = self.tail_of_head.remove(&head_data_id) {
                if tail != next_data_id {
                    self.tail_of_head.insert(next_data_id, tail);
                }
            }
            Some(next_data_id)
        } else {
            pending.remove(k);
            // Defensive: a length-1 chain has no tail entry, but if somehow
            // one exists (e.g. corrupted state) clean it up.
            self.tail_of_head.remove(&head_data_id);
            None
        }
    }
}

/// What `respond*` writes into `promise_yield_resume` and what each callback
/// then deserializes via `#[callback_result]`. Wrapping the response lets a
/// failing link propagate `Failure` to subsequent links instead of forcing
/// each duplicate caller to wait for its own yield to time out.
///
/// This is contract-internal: only our own callbacks ever decode it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema)
)]
pub enum ResumedPayload<T> {
    Success(T),
    Failure,
}

#[cfg(test)]
impl ChainState {
    /// Returns the successor of `data_id` if one is recorded.
    pub fn next_after(&self, data_id: &CryptoHash) -> Option<CryptoHash> {
        self.next.get(data_id).copied()
    }

    /// Returns the tail of the chain whose current head is `head_data_id`,
    /// when chain length > 1.
    pub fn tail_for_head(&self, head_data_id: &CryptoHash) -> Option<CryptoHash> {
        self.tail_of_head.get(head_data_id).copied()
    }
}
