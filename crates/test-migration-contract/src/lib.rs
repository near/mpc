use near_sdk::{env::log_str, near};

#[derive(Debug)]
#[near(contract_state)]
pub struct Contract {}

#[near]
impl Contract {
    #[private]
    #[init(ignore_state)]
    #[handle_result]
    pub fn migrate() -> Result<Self, String> {
        log_str("Migration called");
        Ok(Self {})
    }
}
