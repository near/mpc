#[expect(
    clippy::allow_attributes,
    reason = "built.rs files are included verbatim and use allow()"
)]
pub(crate) mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

pub mod cli;
pub mod data;
pub mod output;
pub mod tcb_status;
pub mod verify;
