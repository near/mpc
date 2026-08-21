//! Contract method name constants for the test parallel contract.
//!
//! Single source of truth for the names used by the contract itself and by its
//! host-side callers (devnet load tests, sandbox tests, E2E tests).

pub const MAKE_PARALLEL_SIGN_CALLS: &str = "make_parallel_sign_calls";
pub const MAKE_DUPLICATE_SIGN_CALLS: &str = "make_duplicate_sign_calls";
pub const MAKE_DUPLICATE_CKD_CALLS: &str = "make_duplicate_ckd_calls";
pub const HANDLE_RESULTS: &str = "handle_results";
