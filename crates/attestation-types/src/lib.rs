//! Data types shared by the TEE attestation flow: what a quote carries, what it is checked
//! against, and how those values are serialized.

#![no_std]

extern crate alloc;

mod app_compose;
mod measurements;
mod report_data;
mod tcb_info;

pub use app_compose::{AppCompose, DockerComposeString};
pub use measurements::{ExpectedMeasurements, Measurements};
pub use report_data::{REPORT_DATA_SIZE, ReportData};
pub use tcb_info::{EventLog, HexBytes, ParsingError, TcbInfo};
