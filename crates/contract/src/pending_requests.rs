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
/// one MPC reply). This is a somewhat arbitrary bound, set high enough so that we should
/// never hit it in practice (famous last words...), while still providing a ceiling to
/// keep the theoretical number of resumed promises bounded.
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
/// Panics with `InvalidParameters::PendingRequestQueueFull` if the queue is already at
/// `MAX_PENDING_REQUEST_FAN_OUT`.
pub(crate) fn push_pending_yield<K>(
    map: &mut LookupMap<K, Vec<YieldIndex>>,
    request: K,
    data_id: CryptoHash,
) where
    K: BorshSerialize + BorshDeserialize + Clone + Ord,
{
    let yield_index = YieldIndex { data_id };
    if let Some(queue) = map.get_mut(&request) {
        if queue.len() >= usize::from(MAX_PENDING_REQUEST_FAN_OUT) {
            env::panic_str(
                &InvalidParameters::PendingRequestQueueFull {
                    limit: MAX_PENDING_REQUEST_FAN_OUT,
                }
                .to_string(),
            );
        }
        queue.push(yield_index);
    } else {
        map.insert(request, vec![yield_index]);
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
/// falls back to the single-yield legacy map. Returns `Err(RequestNotFound)` if
/// neither map has an entry.
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
