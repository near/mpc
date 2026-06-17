//! Raw TDX/SGX quote bytes.
//!
//! Re-exported from `tee-verifier-interface` so the quote type has a single
//! definition shared by the verifier wire, this crate's post-DCAP logic, and
//! every consumer.
pub use tee_verifier_interface::QuoteBytes;
