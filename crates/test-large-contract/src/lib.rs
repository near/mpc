use near_sdk::{env, near};

// Embed ~2 MiB of padding to produce a large WASM binary (~2 MiB).
// This ensures the compiled contract exceeds the 1.5 MiB RPC limit,
// requiring chunked upload to propose it.
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

    /// Returns a byte from the embedded padding at the given index.
    /// This view method forces the linker to retain the entire PADDING blob.
    pub fn padding_byte(&self, index: usize) -> u8 {
        PADDING[index]
    }
}
