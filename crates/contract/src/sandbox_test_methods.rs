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
use near_sdk::near;

// Import the generated extension trait from near
use crate::MpcContractExt;

#[near]
impl MpcContract {
    /// Returns the number of yields queued under `request` in the fan-out map.
    ///
    /// Used by the duplicate-request sandbox test to poll until the full fan-out queue
    /// has landed before calling `respond`, replacing a previous wall-clock sleep. The
    /// legacy single-yield map is not consulted: post-upgrade pushes drain it into the
    /// head of the new queue, so the new map's length is authoritative for the test's
    /// purposes.
    pub fn pending_signature_queue_len(&self, request: SignatureRequest) -> u32 {
        self.pending_signature_requests
            .get(&request)
            .map(|q| q.len() as u32)
            .unwrap_or(0)
    }

    /// CKD counterpart to [`Self::pending_signature_queue_len`]; same rationale.
    pub fn pending_ckd_queue_len(&self, request: CKDRequest) -> u32 {
        self.pending_ckd_requests
            .get(&request)
            .map(|q| q.len() as u32)
            .unwrap_or(0)
    }
}
