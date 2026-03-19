#![allow(dead_code)]

mod contract;
pub(super) mod localnet;
mod test_runner;

pub use test_runner::run_localnet_test;
