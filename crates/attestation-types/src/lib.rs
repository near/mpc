//! Data types shared by the TEE attestation flow: what a quote carries, what it is checked
//! against, and how those values are serialized.

#![no_std]

extern crate alloc;

pub mod app_compose;
pub mod measurements;
pub mod report_data;
pub mod tcb_info;
