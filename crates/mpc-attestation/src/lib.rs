#![no_std]

extern crate alloc;

pub mod attestation;
pub mod report_data;

pub use ::attestation::{EventLog, TcbInfo, collateral, quote};
