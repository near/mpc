//! Bookkeeping for pending request yields, keyed by a contract-minted
//! `request_id` (#3184).
//!
//! Each `sign` / `request_app_private_key` / `verify_foreign_transaction` call
//! allocates a `request_id` from [`MpcContract::next_pending_request_id`]
//! *before* invoking `promise_yield_create`. The id is hex-encoded into a
//! `MPC_REQUEST_ID:` log so the indexer can route `respond*` back to the
//! specific yield, and it's also baked into the yield's `callback_args` so
//! the timeout callback can clean its own entry without a reverse index.
//!
//! The map stores `(SignatureRequest, YieldIndex)` because the yield's
//! runtime-allocated `data_id` is only known *after* `promise_yield_create`,
//! and we need to keep it around to call `promise_yield_resume` later. The
//! request_id is our own counter-derived hash; the data_id is NEAR's
//! per-yield identity.
//!
//! ## Legacy fallback
//!
//! Pre-upgrade in-flight yields live in [`LegacyPendingRequests`] under the
//! pre-#3184 storage keys. They have at most one yield per key (duplicates
//! were already overwritten by the buggy pre-upgrade `respond`).
//! `respond*` falls back to this map when called without a `request_id` —
//! either by an old node, or by a new node resolving a pre-upgrade yield it
//! has no `MPC_REQUEST_ID:` log for. The legacy map drains naturally and
//! can be dropped one release after every pre-upgrade yield has had a
//! chance to time out (200 blocks).

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

/// Pre-upgrade pending-request maps, kept readable through the legacy window
/// so `respond` and the timeout callback can resolve yields that were
/// created before the unique-id rework shipped.
///
/// Rooted at the *previous* storage keys with the *previous*
/// `LookupMap<RequestKey, YieldIndex>` shape, so deserializing existing
/// on-chain state is a no-op. Drains as legacy yields resolve or time out;
/// the whole struct (along with its storage keys) should be removed in the
/// next release — same lifecycle as the V2→V3 cleanup in #2940.
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

/// Register a fresh yield under `request_id`. `request_id` is minted by
/// `enqueue_yield_request` (the counter-derived hash); `yield_index` is the
/// runtime's `data_id`, needed later for `promise_yield_resume`.
pub(crate) fn insert<K>(
    by_id: &mut LookupMap<CryptoHash, (K, YieldIndex)>,
    request_id: CryptoHash,
    request: K,
    yield_index: YieldIndex,
) where
    K: BorshSerialize + BorshDeserialize + Clone + Ord,
{
    by_id.insert(request_id, (request, yield_index));
}

/// Resume the yield identified by `request_id` with `response_bytes`. The
/// stored request is checked against `expected_request` so a node can't
/// (accidentally or otherwise) route a response for request A to yield B.
///
/// Returns `Err(RequestNotFound)` if the id is unknown, and
/// `Err(RequestMismatch)` if the stored request doesn't match. On mismatch
/// the entry is re-inserted as-is so an honest retry with the correct key
/// still resolves.
pub(crate) fn resolve_by_id<K>(
    by_id: &mut LookupMap<CryptoHash, (K, YieldIndex)>,
    request_id: &CryptoHash,
    expected_request: &K,
    response_bytes: Vec<u8>,
) -> Result<(), Error>
where
    K: BorshSerialize + BorshDeserialize + Ord + PartialEq,
{
    let Some((stored_request, yield_index)) = by_id.remove(request_id) else {
        return Err(InvalidParameters::RequestNotFound.into());
    };
    if &stored_request != expected_request {
        by_id.insert(*request_id, (stored_request, yield_index));
        return Err(InvalidParameters::RequestMismatch.into());
    }
    env::promise_yield_resume(&yield_index.data_id, response_bytes);
    Ok(())
}

/// Resume the single legacy yield for `request`. Used when `respond` is
/// called without a `request_id` (old node, or pre-upgrade yield). Drains
/// the legacy entry.
pub(crate) fn resolve_legacy_by_request<K>(
    legacy: &mut LookupMap<K, YieldIndex>,
    request: &K,
    response_bytes: Vec<u8>,
) -> Result<(), Error>
where
    K: BorshSerialize + BorshDeserialize + Clone + Ord,
{
    let Some(YieldIndex { data_id }) = legacy.remove(request) else {
        return Err(InvalidParameters::RequestNotFound.into());
    };
    env::promise_yield_resume(&data_id, response_bytes);
    Ok(())
}

/// Drop the entry under `request_id`. Called from the timeout callback,
/// which has `request_id` baked into its args at yield-creation time so it
/// can target the exact yield that just expired. A no-op if the entry is
/// already gone (e.g. `respond` raced and resolved it just before the
/// timeout fired).
pub(crate) fn remove_by_id<K>(
    by_id: &mut LookupMap<CryptoHash, (K, YieldIndex)>,
    request_id: &CryptoHash,
) where
    K: BorshSerialize + BorshDeserialize + Clone + Ord,
{
    by_id.remove(request_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_keys::StorageKey;
    use assert_matches::assert_matches;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn req(byte: u8) -> SignatureRequest {
        use near_mpc_contract_interface::types::{Payload, Tweak};
        SignatureRequest {
            tweak: Tweak([byte; 32]),
            payload: Payload::from_legacy_ecdsa([byte; 32]),
            domain_id: mpc_primitives::domain::DomainId(0),
        }
    }

    fn id(byte: u8) -> CryptoHash {
        [byte; 32]
    }

    type SignatureMaps = (
        LookupMap<CryptoHash, (SignatureRequest, YieldIndex)>,
        LookupMap<SignatureRequest, YieldIndex>,
    );

    fn empty_maps() -> SignatureMaps {
        (
            LookupMap::new(StorageKey::PendingSignatureRequestsByIdV4),
            LookupMap::new(StorageKey::PendingSignatureRequestsV3),
        )
    }

    #[test]
    #[expect(non_snake_case)]
    fn insert__should_store_request_and_yield_index() {
        // Given
        testing_env!(VMContextBuilder::new().build());
        let (mut by_id, _legacy) = empty_maps();
        let r = req(1);
        let yi = YieldIndex { data_id: id(0xCC) };

        // When
        insert(&mut by_id, id(0xAA), r.clone(), yi.clone());

        // Then
        let (stored_request, stored_yield) =
            by_id.get(&id(0xAA)).expect("entry must be present").clone();
        assert_eq!(stored_request, r);
        assert_eq!(stored_yield.data_id, yi.data_id);
    }

    #[test]
    #[expect(non_snake_case)]
    fn resolve_by_id__should_error_and_preserve_state_on_request_mismatch() {
        // Given a queued yield for request A
        testing_env!(VMContextBuilder::new().build());
        let (mut by_id, _legacy) = empty_maps();
        let stored = req(1);
        let other = req(2);
        let yi = YieldIndex { data_id: id(0xCC) };
        insert(&mut by_id, id(0xAA), stored.clone(), yi);

        // When respond is called with a wrong request key against the same id
        let err = resolve_by_id(&mut by_id, &id(0xAA), &other, vec![1, 2, 3])
            .expect_err("mismatched request should not resolve");

        // Then it returns RequestMismatch, and the entry is still resolvable
        // by the correct request.
        assert_matches!(
            err,
            Error::InvalidParameters(InvalidParameters::RequestMismatch)
        );
        let (still_there, _) = by_id
            .get(&id(0xAA))
            .expect("entry must survive mismatch")
            .clone();
        assert_eq!(still_there, stored);
        resolve_by_id(&mut by_id, &id(0xAA), &stored, vec![1, 2, 3])
            .expect("retry with the right request should succeed");
        assert!(by_id.get(&id(0xAA)).is_none());
    }

    #[test]
    #[expect(non_snake_case)]
    fn remove_by_id__should_drop_only_the_targeted_entry() {
        // Given two queued yields for the same request key
        testing_env!(VMContextBuilder::new().build());
        let (mut by_id, _legacy) = empty_maps();
        let r = req(1);
        insert(
            &mut by_id,
            id(0xAA),
            r.clone(),
            YieldIndex { data_id: id(0x11) },
        );
        insert(
            &mut by_id,
            id(0xBB),
            r.clone(),
            YieldIndex { data_id: id(0x22) },
        );

        // When one id is removed
        remove_by_id(&mut by_id, &id(0xAA));

        // Then the other id is untouched.
        assert!(by_id.get(&id(0xAA)).is_none());
        assert!(by_id.get(&id(0xBB)).is_some());
    }

    #[test]
    #[expect(non_snake_case)]
    fn resolve_legacy_by_request__should_drain_legacy_entry() {
        // Given an entry that exists only in the legacy map (pre-upgrade)
        testing_env!(VMContextBuilder::new().build());
        let (_by_id, mut legacy) = empty_maps();
        let r = req(1);
        legacy.insert(r.clone(), YieldIndex { data_id: id(0x11) });

        // When respond resolves it via the legacy path
        resolve_legacy_by_request(&mut legacy, &r, vec![1, 2, 3])
            .expect("legacy entry should resolve");

        // Then the legacy entry is gone
        assert!(legacy.get(&r).is_none());
    }
}
