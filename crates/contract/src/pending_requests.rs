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
//! ## Legacy-window policy
//!
//! During the legacy window a request key `K` can exist in both the new
//! fan-out map and the [`LegacyPendingRequests`] map at the same time: a
//! caller might submit `K` before the upgrade (entry in legacy map) and
//! re-submit the identical `K` after the upgrade (entry in new map). The
//! helpers below handle this without ever migrating entries between maps:
//!
//! * [`push_pending_yield`] only writes to the new map.
//! * [`resolve_yields_for`] drains both maps when a response arrives, so every
//!   pre- and post-upgrade caller for `K` is resumed by a single `respond*`.
//! * [`pop_one_yield_for`] consults the legacy map first on timeout, because a
//!   legacy entry is pre-upgrade and therefore older than any yield in the new
//!   queue — popping it first preserves FIFO timeout semantics.

use borsh::{BorshDeserialize, BorshSerialize};
use near_mpc_contract_interface::types::VerifyForeignTransactionRequest;
use near_sdk::{env, store::LookupMap, CryptoHash};

use crate::{
    errors::{Error, InvalidParameters, RequestError},
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
pub const MAX_PENDING_REQUEST_FAN_OUT: u8 = 128;

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
/// Always writes to the new fan-out map; the legacy single-yield map is untouched.
/// During the legacy window the same key may already exist in the legacy map — that
/// entry is preserved and drained together with this queue when a response arrives
/// (see [`resolve_yields_for`]) or popped first on timeout (see [`pop_one_yield_for`]).
///
/// Panics with `RequestError::PendingRequestQueueFull` if the resulting queue would
/// exceed `MAX_PENDING_REQUEST_FAN_OUT`.
pub(crate) fn push_pending_yield<K>(
    new_map: &mut LookupMap<K, Vec<YieldIndex>>,
    request: K,
    data_id: CryptoHash,
) where
    K: BorshSerialize + BorshDeserialize + Clone + Ord,
{
    let queue = new_map.entry(request).or_default();
    if queue.len() >= usize::from(MAX_PENDING_REQUEST_FAN_OUT) {
        env::panic_str(
            &RequestError::PendingRequestQueueFull {
                limit: MAX_PENDING_REQUEST_FAN_OUT,
            }
            .to_string(),
        );
    }
    queue.push(YieldIndex { data_id });
}

/// Remove the oldest queued yield from the pending-request fan-out for `request`.
/// If the queue empties (or was already empty), the map entry itself is removed.
/// Returns `true` if a yield was popped, `false` if the request was absent or the
/// stored queue had no entries to pop.
///
/// Yields are removed in FIFO order because they were appended in submission order
/// and time out in that same order — so the timing-out yield is always the head.
fn pop_oldest_pending_yield<K>(map: &mut LookupMap<K, Vec<YieldIndex>>, request: &K) -> bool
where
    K: BorshSerialize + BorshDeserialize + Clone + Ord,
{
    let Some(queue) = map.get_mut(request) else {
        return false;
    };
    if queue.is_empty() {
        map.remove(request);
        return false;
    }
    queue.remove(0);
    if queue.is_empty() {
        map.remove(request);
    }
    true
}

/// Resume every yield queued for `request` with `response_bytes`, draining both the
/// new fan-out map and the legacy single-yield map in one pass. Returns
/// `Err(RequestNotFound)` only if neither map held an entry.
///
/// Both maps are always drained, so a post-upgrade `respond*` cleans up any pre-upgrade
/// duplicate that was still pending. Resuming a yield that has already timed out is a
/// no-op at the SDK level.
pub(crate) fn resolve_yields_for<K>(
    new_map: &mut LookupMap<K, Vec<YieldIndex>>,
    legacy_map: &mut LookupMap<K, YieldIndex>,
    request: &K,
    response_bytes: Vec<u8>,
) -> Result<(), Error>
where
    K: BorshSerialize + BorshDeserialize + Clone + Ord,
{
    let resumed = new_map
        .remove(request)
        .unwrap_or_default()
        .into_iter()
        .chain(legacy_map.remove(request))
        .map(|YieldIndex { data_id }| {
            env::promise_yield_resume(&data_id, response_bytes.clone());
        })
        .count();

    if resumed > 0 {
        Ok(())
    } else {
        Err(InvalidParameters::RequestNotFound.into())
    }
}

/// Account for one timed-out yield against `request`: pop the legacy single-yield
/// entry if one is present, otherwise pop the oldest yield from the new fan-out queue.
/// A no-op if neither map has the request (e.g. `respond*` already drained it).
///
/// The legacy entry is consulted first because a pre-upgrade yield was created before
/// any post-upgrade yield for the same key — popping legacy first preserves
/// oldest-first FIFO timeout semantics across the legacy window.
pub(crate) fn pop_one_yield_for<K>(
    new_map: &mut LookupMap<K, Vec<YieldIndex>>,
    legacy_map: &mut LookupMap<K, YieldIndex>,
    request: &K,
) where
    K: BorshSerialize + BorshDeserialize + Clone + Ord,
{
    if legacy_map.remove(request).is_none() {
        pop_oldest_pending_yield(new_map, request);
    }
}
