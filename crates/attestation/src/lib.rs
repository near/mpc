#![no_std]

extern crate alloc;

pub mod attestation;
pub mod collateral;
pub mod quote;

// DTOs and post-DCAP helpers live in `attestation-types`. Re-exported here
// so existing consumers can keep using paths like `attestation::tcb_info`
// without churn. The `attestation` crate adds only the `dcap_qvl::verify`
// entry point (`DstackAttestation::verify`) on top.
pub use attestation_types::{app_compose, measurements, report_data, tcb_info, verify_post_dcap};
