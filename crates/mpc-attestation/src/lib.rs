#![no_std]

extern crate alloc;

pub mod attestation;
pub mod report_data;

#[cfg(feature = "local-verify")]
pub use ::attestation::dcap_conversions;
pub use ::attestation::{collateral, quote, tcb_info};
