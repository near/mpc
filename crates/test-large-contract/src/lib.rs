//! A minimal contract padded with ~2 MiB of non-zero bytes so its assembled
//! WASM exceeds the RPC's single-transaction payload limit. Used by
//! `mpc-contract` sandbox tests to exercise the chunked-upload code path
//! end-to-end (start → upload N chunks → finalize → vote → deploy).
//!
//! `padding.bin` is produced by `build.rs`; it is not checked in.

use near_sdk::{env, near};

static PADDING: &[u8] = include_bytes!("padding.bin");

#[derive(Debug, Default)]
#[near(contract_state)]
pub struct Contract {}

#[near]
impl Contract {
    #[private]
    #[init(ignore_state)]
    #[handle_result]
    pub fn migrate() -> Result<Self, String> {
        env::log_str("Migration called on large contract");
        Ok(Self {})
    }

    /// Reads one byte from the embedded padding. Without this method the linker
    /// would strip `PADDING` from the final binary; calling it forces the entire
    /// blob to be retained.
    pub fn padding_byte(&self, index: usize) -> u8 {
        PADDING[index]
    }
}
