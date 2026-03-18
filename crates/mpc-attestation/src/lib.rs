#![no_std]

extern crate alloc;

pub mod attestation;
pub mod report_data;

pub use ::attestation::{collateral, quote, tcb_info};
