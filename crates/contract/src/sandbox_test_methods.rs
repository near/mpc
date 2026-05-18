//! View methods that expose internal contract state to sandbox tests.
//!
//! These exist purely so tests can assert invariants that aren't observable through the
//! production API surface — e.g. the *length* of a fan-out queue, not just its
//! presence. They are gated behind the `sandbox-test-methods` feature and so do not
//! contribute to the production wasm.
//!
//! Distinct from [`crate::bench`]: those methods exist so callers can measure gas
//! costs of internal operations; the methods here are behavioral introspection hooks.

use crate::primitives::ckd::CKDRequest;
use crate::primitives::signature::SignatureRequest;
use crate::MpcContract;
use near_mpc_contract_interface::types::ForeignChain;
use near_sdk::near;

// Import the generated extension trait from near
use crate::MpcContractExt;

#[near]
impl MpcContract {
    /// Returns the number of yields queued under `request` in the fan-out map.
    ///
    /// Used by the duplicate-request sandbox test to poll until the full fan-out queue
    /// has landed before calling `respond`, replacing a previous wall-clock sleep.
    /// The legacy single-yield map is not consulted; for sandbox tests starting from
    /// fresh state the new map's length is authoritative.
    ///
    /// The queue is hard-capped at [`crate::pending_requests::MAX_PENDING_REQUEST_FAN_OUT`]
    /// (a `u8`), so the `try_from` is constrained to succeed today; the `expect` is a
    /// tripwire in case the cap ever grows past `u32::MAX`.
    pub fn pending_signature_queue_len(&self, request: SignatureRequest) -> u32 {
        let len = self
            .pending_signature_requests
            .get(&request)
            .map(Vec::len)
            .unwrap_or(0);
        u32::try_from(len)
            .expect("queue length must fit in u32 — bounded by MAX_PENDING_REQUEST_FAN_OUT")
    }

    /// CKD counterpart to [`Self::pending_signature_queue_len`]; same rationale.
    pub fn pending_ckd_queue_len(&self, request: CKDRequest) -> u32 {
        let len = self
            .pending_ckd_requests
            .get(&request)
            .map(Vec::len)
            .unwrap_or(0);
        u32::try_from(len)
            .expect("queue length must fit in u32 — bounded by MAX_PENDING_REQUEST_FAN_OUT")
    }

    /// Number of pending `ProviderVotes` rows for `chain`. Used by sandbox tests to
    /// verify that `clear_chain` ran after the apply threshold was reached.
    pub fn foreign_chain_pending_vote_count(&self, chain: ForeignChain) -> u32 {
        let count = self
            .foreign_chain_rpc_whitelist
            .votes
            .pending
            .keys()
            .filter(|(_, c)| *c == chain)
            .count();
        u32::try_from(count).expect("pending vote count must fit in u32")
    }
}
