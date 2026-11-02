#[expect(
    clippy::allow_attributes,
    reason = "built.rs files are included verbatim and use allow()"
)]
pub(crate) mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

pub mod adapters;
pub mod backup;
pub mod cli;
pub mod keyset;
pub mod ports;
pub mod service;
pub mod types;

#[cfg(test)]
mod test_utils;
