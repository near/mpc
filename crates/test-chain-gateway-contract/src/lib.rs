use near_sdk::{env::log_str, near};

#[derive(Debug)]
#[near(contract_state)]
pub struct Contract {
    view_method_counter: u32,
    // add calls that were recorded
}

#[near]
impl Contract {
    #[private]
    #[init(ignore_state)]
    #[handle_result]
    // todo
    pub fn migrate() -> Result<Self, String> {
        log_str("Migration called");
        Ok(Self {})
    }
}
