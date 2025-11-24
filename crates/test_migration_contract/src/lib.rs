// We disallow using `near_sdk::AccountId` in our own code.
// However, the `near_bindgen` proc macro expands to code that uses it
// internally, and Clippy applies the `disallowed_types` lint to that
// generated code as well. Since the lint cannot be suppressed only for the
// macro expansion, we allow it in this file to avoid false positives.
#![allow(clippy::disallowed_types)]

use near_sdk::{
    borsh::{BorshDeserialize, BorshSerialize},
    env::log_str,
    near_bindgen,
};

#[derive(BorshDeserialize, BorshSerialize, Debug)]
#[near_bindgen]
pub struct Contract {}

#[near_bindgen]
impl Contract {
    #[private]
    #[init(ignore_state)]
    #[handle_result]
    pub fn migrate() -> Result<Self, String> {
        log_str("Migration called");
        Ok(Self {})
    }
}
