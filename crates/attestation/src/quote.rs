//! Raw TDX/SGX quote bytes.
//!
//! Re-exported from `tee-verifier-interface` so the quote type has a single
//! definition shared by the verifier wire, this crate's post-DCAP logic, and
//! every consumer. This crate does not define its own quote type.
pub use tee_verifier_interface::QuoteBytes;
