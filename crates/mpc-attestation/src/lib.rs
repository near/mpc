#![no_std]

extern crate alloc;

pub mod attestation;
pub mod report_data;

pub use ::attestation::{collateral, quote, tcb_info};
pub use launcher_interface::{BACKUP_SERVICE_IMAGE_HASH_EVENT, MPC_IMAGE_HASH_EVENT};
