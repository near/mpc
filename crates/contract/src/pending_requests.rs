//! Storage and bookkeeping for pending request fan-out.
//!
//! Each pending-request map stores a `Vec<YieldIndex>` so that duplicate
//! submissions of the same request key queue up and all receive the same MPC
//! response. This module owns:
//!
//! * the cap on how many yields may be queued for a single key,
//! * the queue mutations (`push`, FIFO pop, drain),
//! * the read/write policy on the fan-out map: `push_pending_yield` appends,
//!   `resolve_yields_for` drains the full queue on a response, and
//!   `pop_oldest_pending_yield` removes the head entry on a timeout.
//!
//! Callers in [`crate::api`] go through these helpers rather than touching the maps
//! directly, so the queue policy lives in one place.

use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_contract_interface::types::YieldIndex;
use near_sdk::{CryptoHash, env, require, store::LookupMap};

use crate::errors::{Error, InvalidParameters, RequestError};

/// Maximum number of concurrent yield-resume promises that can be queued for a single
/// request key (i.e. the number of duplicate submissions whose responses fan out from
/// one MPC reply).
///
/// The ceiling is needed because `respond*` drains the entire queue in one call: every
/// queued yield triggers a host-side `promise_yield_resume`, paid for out of the
/// responder's 300 TGas budget. Without a cap, an attacker could enqueue enough
/// duplicates to make `respond*` run out of gas and strand every queued caller.
///
/// 128 is validated empirically by the sandbox test
/// `respond__should_drain_saturated_fan_out_queue`, which fills the queue to this cap
/// across all four signature schemes and confirms `respond*` drains it inside its 300 TGas
/// budget.
pub const MAX_PENDING_REQUEST_FAN_OUT: u8 = 128;

/// Append a yield index to the pending-request fan-out queue for `request`.
///
/// Panics with [`RequestError::PendingRequestQueueFull`] if the resulting queue would
/// exceed `MAX_PENDING_REQUEST_FAN_OUT`.
pub(crate) fn push_pending_yield<K>(
    requests: &mut LookupMap<K, Vec<YieldIndex>>,
    request: K,
    data_id: CryptoHash,
) where
    K: BorshSerialize + BorshDeserialize + Clone + Ord,
{
    let queue = requests.entry(request).or_default();
    require!(
        queue.len() < usize::from(MAX_PENDING_REQUEST_FAN_OUT),
        RequestError::PendingRequestQueueFull {
            limit: MAX_PENDING_REQUEST_FAN_OUT,
        }
        .to_string()
    );
    queue.push(YieldIndex { data_id });
}

/// Resume every yield queued for `request` with `response_bytes`, draining the
/// fan-out map in one pass. Returns `Err(RequestNotFound)` if the map held no entry.
///
/// Resuming a yield that has already timed out is a no-op at the SDK level.
pub(crate) fn resolve_yields_for<K>(
    requests: &mut LookupMap<K, Vec<YieldIndex>>,
    request: &K,
    response_bytes: Vec<u8>,
) -> Result<(), Error>
where
    K: BorshSerialize + BorshDeserialize + Clone + Ord,
{
    let resumed = requests
        .remove(request)
        .unwrap_or_default()
        .into_iter()
        .map(|YieldIndex { data_id }| {
            env::promise_yield_resume(&data_id, &response_bytes);
        })
        .count();

    if resumed > 0 {
        Ok(())
    } else {
        Err(InvalidParameters::RequestNotFound.into())
    }
}

/// Account for one timed-out yield against `request`: pop the oldest queued yield
/// from the fan-out for `request`. A no-op if the request is absent (e.g. `respond*`
/// already drained it) or the stored queue had no entries to pop.
///
/// Yields are removed in FIFO order because they were appended in submission order
/// and time out in that same order — so the timing-out yield is always the head.
/// If the queue empties (or was already empty), the map entry itself is removed.
pub(crate) fn pop_oldest_pending_yield<K>(requests: &mut LookupMap<K, Vec<YieldIndex>>, request: &K)
where
    K: BorshSerialize + BorshDeserialize + Clone + Ord,
{
    let Some(queue) = requests.get_mut(request) else {
        return;
    };
    if queue.is_empty() {
        requests.remove(request);
        return;
    }
    queue.remove(0);
    if queue.is_empty() {
        requests.remove(request);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic;

    #[test]
    #[expect(non_snake_case)]
    fn push_pending_yield__should_reject_an_entry_after_the_fan_out_limit() {
        // Given: a pending-request queue filled to the configured fan-out cap
        let mut requests: LookupMap<u64, Vec<YieldIndex>> = LookupMap::new(b"t");
        let test_key: u64 = 42;

        for i in 0..MAX_PENDING_REQUEST_FAN_OUT {
            push_pending_yield(&mut requests, test_key, [i; 32]);
        }

        let queue = requests.get(&test_key).expect("queue should exist");
        assert_eq!(
            queue.len(),
            usize::from(MAX_PENDING_REQUEST_FAN_OUT),
            "queue should contain exactly the configured fan-out limit"
        );
        assert_queue_matches_insertion_order(&queue);

        // When: pushing one more entry beyond the cap
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            push_pending_yield(&mut requests, test_key, [0xff; 32]);
        }));

        // Then: the push panics with the exact expected message and the queue is unchanged
        let err = result.expect_err("appending past the cap should panic");
        let msg = err
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| err.downcast_ref::<&str>().copied())
            .unwrap_or_default();
        // The NEAR SDK mock wraps the panic in HostError(GuestPanic { panic_msg: "..." })
        // Extract the actual panic message from the wrapper.
        let msg = msg
            .strip_prefix("called `Result::unwrap()` on an `Err` value: HostError(GuestPanic { panic_msg: \"")
            .and_then(|s| s.strip_suffix("\" })"))
            .unwrap_or(msg);
        let expected = RequestError::PendingRequestQueueFull {
            limit: MAX_PENDING_REQUEST_FAN_OUT,
        }
        .to_string();
        assert_eq!(msg, expected, "unexpected panic message: {msg}");

        let queue = requests.get(&test_key).expect("queue should still exist");
        assert_eq!(
            queue.len(),
            usize::from(MAX_PENDING_REQUEST_FAN_OUT),
            "queue should not grow past the configured fan-out limit"
        );
        assert_queue_matches_insertion_order(&queue);
    }
}

/// Helper to verify that the queue entries match the expected insertion order.
/// Iterates over the u8 range directly to avoid `as` conversions.
#[allow(dead_code)]
fn assert_queue_matches_insertion_order(queue: &[YieldIndex]) {
    for (expected, yield_idx) in (0..MAX_PENDING_REQUEST_FAN_OUT).zip(queue) {
        assert_eq!(
            yield_idx.data_id, [expected; 32],
            "entry {expected} should match insertion order"
        );
    }
}
