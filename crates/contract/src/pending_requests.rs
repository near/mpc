//! Storage and bookkeeping for pending request fan-out.
//!
//! Each pending-request map stores a `Vec<YieldIndex>` so that duplicate
//! submissions of the same request key queue up and all receive the same MPC
//! response. This module owns:
//!
//! * the cap on how many yields may be queued for a single key,
//! * the queue mutations (`push`, FIFO pop, drain),
//! * the read/write policy across the new fan-out map and the legacy
//!   single-yield map ([`LegacyPendingRequests`]) inherited from before the
//!   fan-out upgrade.
//!
//! Callers in `lib.rs` go through these helpers rather than touching the maps
//! directly, so the legacy-fallback policy lives in one place.
//!
//! ## Single-map invariant during the legacy window
//!
//! A request key `K` can in principle exist in both the new fan-out map and the
//! [`LegacyPendingRequests`] map at the same time: a caller might submit `K`
//! before the upgrade (entry in legacy map) and re-submit the identical `K`
//! after the upgrade (entry in new map). The two helpers below ([`pop_one_yield_for`],
//! [`resolve_yields_for`]) only consult one map at a time, so a dual-presence
//! state would mis-route resumes and timeouts and silently drop responses.
//!
//! To prevent that, [`push_pending_yield`] migrates any legacy entry for `K`
//! into the head of the new queue on the first post-upgrade push. From that
//! point on the fan-out map is the single source of truth for `K`, and the
//! other helpers stay simple.

use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_contract_interface::types::VerifyForeignTransactionRequest;
use near_sdk::{env, store::LookupMap, CryptoHash};

use crate::{
    errors::{Error, InvalidParameters},
    primitives::{
        ckd::CKDRequest,
        signature::{SignatureRequest, YieldIndex},
    },
    storage_keys::StorageKey,
};

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
/// `test_contract_request_duplicate_requests_fan_out`, which fills the queue to this
/// cap across all four signature schemes and confirms `respond*` drains it inside its
/// 300 TGas budget.
pub(crate) const MAX_PENDING_REQUEST_FAN_OUT: u8 = 128;

/// In-flight requests inherited from the previous on-chain schema.
///
/// The duplicate-request fan-out feature changed the pending-request value type
/// from `YieldIndex` to `Vec<YieldIndex>` and rehomed the maps under new storage
/// keys. These fields are rooted at the *previous* storage keys with the *previous*
/// singular value type, so requests that were already yielded before the upgrade
/// can still be answered through `respond*` (or cleaned up by their timeout
/// handler) until they expire.
///
/// Unlike a write-once cleanup buffer, these maps are read and written on every
/// `respond*`, every timeout handler, and every `get_pending_*` call — they are
/// operationally live for the lifetime of the legacy window. They should be
/// dropped (along with the now-unused storage keys) in the next upgrade after
/// this has been released — same lifecycle as the V2→V3 cleanup in #2940.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub(crate) struct LegacyPendingRequests {
    pub(crate) signature_requests: LookupMap<SignatureRequest, YieldIndex>,
    pub(crate) ckd_requests: LookupMap<CKDRequest, YieldIndex>,
    pub(crate) verify_foreign_tx_requests: LookupMap<VerifyForeignTransactionRequest, YieldIndex>,
}

impl LegacyPendingRequests {
    pub(crate) fn new() -> Self {
        Self {
            signature_requests: LookupMap::new(StorageKey::PendingSignatureRequestsV3),
            ckd_requests: LookupMap::new(StorageKey::PendingCKDRequestsV2),
            verify_foreign_tx_requests: LookupMap::new(StorageKey::PendingVerifyForeignTxRequests),
        }
    }
}

/// Append a yield index to the pending-request fan-out queue for `request`.
///
/// On the first post-upgrade push for `request`, any pre-existing entry in
/// `legacy_map` is migrated into the head of the new queue. The legacy yield
/// was created before the new yield and therefore times out first, so
/// prepending it preserves the FIFO ordering that [`pop_oldest_pending_yield`]
/// relies on. After migration, `legacy_map` no longer holds `request` and the
/// fan-out map is the single source of truth — see the module-level docs.
///
/// Panics with `InvalidParameters::PendingRequestQueueFull` if the resulting
/// queue would exceed `MAX_PENDING_REQUEST_FAN_OUT`.
pub(crate) fn push_pending_yield<K>(
    new_map: &mut LookupMap<K, Vec<YieldIndex>>,
    legacy_map: &mut LookupMap<K, YieldIndex>,
    request: K,
    data_id: CryptoHash,
) where
    K: BorshSerialize + BorshDeserialize + Clone + Ord,
{
    let new_yield = YieldIndex { data_id };

    if let Some(queue) = new_map.get_mut(&request) {
        // The new-map entry was created on an earlier push, which already
        // drained any legacy entry for `request`. The legacy map cannot still
        // hold `request`, so there is nothing to migrate here.
        if queue.len() >= usize::from(MAX_PENDING_REQUEST_FAN_OUT) {
            env::panic_str(
                &InvalidParameters::PendingRequestQueueFull {
                    limit: MAX_PENDING_REQUEST_FAN_OUT,
                }
                .to_string(),
            );
        }
        queue.push(new_yield);
    } else {
        let queue = match legacy_map.remove(&request) {
            Some(legacy_yield) => vec![legacy_yield, new_yield],
            None => vec![new_yield],
        };
        new_map.insert(request, queue);
    }
}

/// Remove the oldest queued yield from the pending-request fan-out for `request`.
/// If the queue empties, the map entry itself is removed. Returns `true` if a yield
/// was popped, `false` if the request was absent (e.g. `respond*` already drained it
/// before the timeout fired, or the request originated from the legacy map).
///
/// Yields are removed in FIFO order because they were appended in submission order
/// and time out in that same order — so the timing-out yield is always the head.
fn pop_oldest_pending_yield<K>(map: &mut LookupMap<K, Vec<YieldIndex>>, request: &K) -> bool
where
    K: BorshSerialize + BorshDeserialize + Clone + Ord,
{
    let became_empty = match map.get_mut(request) {
        Some(queue) if !queue.is_empty() => {
            queue.remove(0);
            queue.is_empty()
        }
        _ => return false,
    };
    if became_empty {
        map.remove(request);
    }
    true
}

/// Resume every yield queued for `request` with `response_bytes`, draining whichever
/// map currently holds the request. The new fan-out map is checked first; on miss,
/// falls back to the single-yield legacy map (covering pre-upgrade requests that were
/// never re-submitted post-upgrade). Returns `Err(RequestNotFound)` if neither map has
/// an entry.
///
/// The single-map invariant established by [`push_pending_yield`] guarantees that
/// `request` cannot be present in both maps at the same time, so the early return on
/// new-map hit is correct.
///
/// Resuming a yield that has already timed out is a no-op at the SDK level.
pub(crate) fn resolve_yields_for<K>(
    new_map: &mut LookupMap<K, Vec<YieldIndex>>,
    legacy_map: &mut LookupMap<K, YieldIndex>,
    request: &K,
    response_bytes: Vec<u8>,
) -> Result<(), Error>
where
    K: BorshSerialize + BorshDeserialize + Clone + Ord,
{
    if let Some(yield_indices) = new_map.remove(request) {
        for YieldIndex { data_id } in yield_indices {
            env::promise_yield_resume(&data_id, response_bytes.clone());
        }
        Ok(())
    } else if let Some(YieldIndex { data_id }) = legacy_map.remove(request) {
        // Legacy entries never accepted duplicates, so there is at most one yield.
        env::promise_yield_resume(&data_id, response_bytes);
        Ok(())
    } else {
        Err(InvalidParameters::RequestNotFound.into())
    }
}

/// Account for one timed-out yield against `request`: pop the oldest entry from
/// the new fan-out queue if one is present, otherwise remove the legacy single-yield
/// entry. A no-op if neither map has the request (e.g. `respond*` already drained it).
///
/// The single-map invariant established by [`push_pending_yield`] guarantees that
/// `request` is in at most one map, so the order in which the maps are consulted
/// does not change which yield is accounted for.
pub(crate) fn pop_one_yield_for<K>(
    new_map: &mut LookupMap<K, Vec<YieldIndex>>,
    legacy_map: &mut LookupMap<K, YieldIndex>,
    request: &K,
) where
    K: BorshSerialize + BorshDeserialize + Clone + Ord,
{
    if !pop_oldest_pending_yield(new_map, request) {
        legacy_map.remove(request);
    }
}
