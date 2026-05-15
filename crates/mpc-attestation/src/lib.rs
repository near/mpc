#![no_std]

extern crate alloc;

pub mod attestation;
pub mod report_data;

pub use ::attestation::{collateral, collateral_from_dcap, collateral_to_dcap, quote, tcb_info};
