//! Storage for V2 foreign transaction requests, keyed by the yield id the
//! contract picks for each one.

use near_mpc_contract_interface::types::{
    BlockHeight, DomainId, ForeignChainRpcRequest, Hash256, YieldId,
};
#[cfg(feature = "foreign-tx-v2")]
use near_mpc_contract_interface::types::{
    ForeignTxSignPayload, ForeignTxSignPayloadV2, ForeignTxVerificationOutcome,
};
use near_sdk::{near, store::LookupMap};

use crate::storage_keys::StorageKey;

#[cfg(feature = "foreign-tx-v2")]
const YIELD_ID_PREFIX: &[u8] = b"verify_foreign_tx_v2";

#[near(serializers=[borsh])]
#[derive(Debug)]
pub(crate) struct PendingVerifyForeignTxRequestsV2 {
    /// Only goes up, and every migration must carry it over: a counter value
    /// used twice gives two requests the same [`YieldId`].
    next_yield_counter: u64,
    by_yield_id: LookupMap<YieldId, PendingVerifyForeignTxRequestV2>,
}

/// A V2 request as the contract keeps it while the request waits for an
/// answer. It holds the hash of the expected values, not the values.
#[near(serializers=[borsh])]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingVerifyForeignTxRequestV2 {
    pub(crate) request: ForeignChainRpcRequest,
    pub(crate) domain_id: DomainId,
    pub(crate) expected_values_hash: Hash256,
    pub(crate) request_block_height: BlockHeight,
}

impl Default for PendingVerifyForeignTxRequestsV2 {
    fn default() -> Self {
        Self {
            next_yield_counter: 0,
            by_yield_id: LookupMap::new(StorageKey::PendingVerifyForeignTxV2RequestsByYieldId),
        }
    }
}

#[cfg(feature = "foreign-tx-v2")]
impl PendingVerifyForeignTxRequestsV2 {
    /// Returns a yield id no earlier call returned:
    /// `sha256(YIELD_ID_PREFIX || next_yield_counter)`, with the counter in little endian.
    pub(crate) fn take_next_yield_id(&mut self) -> YieldId {
        let counter = self.next_yield_counter;
        self.next_yield_counter = counter
            .checked_add(1)
            .unwrap_or_else(|| near_sdk::env::panic_str("the yield counter overflowed"));
        let preimage = [YIELD_ID_PREFIX, &counter.to_le_bytes()].concat();
        YieldId(near_sdk::env::sha256_array(&preimage))
    }

    pub(crate) fn insert(&mut self, yield_id: YieldId, request: PendingVerifyForeignTxRequestV2) {
        self.by_yield_id.insert(yield_id, request);
    }

    pub(crate) fn remove(&mut self, yield_id: &YieldId) -> Option<PendingVerifyForeignTxRequestV2> {
        self.by_yield_id.remove(yield_id)
    }

    pub(crate) fn get(&self, yield_id: &YieldId) -> Option<&PendingVerifyForeignTxRequestV2> {
        self.by_yield_id.get(yield_id)
    }
}

#[cfg(feature = "foreign-tx-v2")]
impl PendingVerifyForeignTxRequestV2 {
    /// The payload the MPC network signs to answer the request stored under
    /// `yield_id` with `outcome`.
    pub(crate) fn sign_payload(
        &self,
        yield_id: YieldId,
        outcome: ForeignTxVerificationOutcome,
    ) -> ForeignTxSignPayload {
        ForeignTxSignPayload::V2(ForeignTxSignPayloadV2 {
            request: self.request.clone(),
            expected_values_hash: self.expected_values_hash.clone(),
            request_block_height: self.request_block_height,
            yield_id,
            outcome,
        })
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[cfg(all(feature = "__abi-generate", not(target_arch = "wasm32")))]
    #[test]
    fn pending_verify_foreign_tx_request_v2_borsh_schema__should_not_change() {
        let schema =
            borsh::schema::BorshSchemaContainer::for_type::<PendingVerifyForeignTxRequestV2>();
        insta::assert_debug_snapshot!(schema);
    }

    #[test]
    fn take_next_yield_id__should_hash_the_prefix_and_the_counter() {
        // Given
        let mut requests = PendingVerifyForeignTxRequestsV2 {
            next_yield_counter: 7,
            ..Default::default()
        };

        // When
        let yield_id = requests.take_next_yield_id();

        // Then
        let preimage = [b"verify_foreign_tx_v2".as_slice(), &7u64.to_le_bytes()].concat();
        assert_eq!(yield_id, YieldId(near_sdk::env::sha256_array(&preimage)));
        assert_eq!(requests.next_yield_counter, 8);
    }

    #[test]
    fn take_next_yield_id__should_never_repeat_an_id() {
        // Given
        let mut requests = PendingVerifyForeignTxRequestsV2::default();

        // When
        let ids: std::collections::BTreeSet<_> =
            (0..100).map(|_| requests.take_next_yield_id()).collect();

        // Then
        assert_eq!(ids.len(), 100);
    }

    #[test]
    #[should_panic(expected = "the yield counter overflowed")]
    fn take_next_yield_id__should_panic_when_the_counter_overflows() {
        // Given
        let mut requests = PendingVerifyForeignTxRequestsV2 {
            next_yield_counter: u64::MAX,
            ..Default::default()
        };

        // When
        requests.take_next_yield_id();
    }
}
