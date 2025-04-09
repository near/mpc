use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::env::log_str;
use near_sdk::near_bindgen;

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
