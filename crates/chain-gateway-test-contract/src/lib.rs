use near_sdk::{env::log_str, near};

pub const DEFAULT_VALUE: &str = "hello from test";
pub const VIEW_METHOD: &str = "view_value";
pub const WRITE_METHOD: &str = "set_value";

#[derive(Debug)]
#[near(contract_state)]
pub struct Contract {
    stored_value: String,
}

impl Default for Contract {
    fn default() -> Self {
        Self {
            stored_value: DEFAULT_VALUE.to_string(),
        }
    }
}

#[near]
impl Contract {
    pub fn view_value(&self) -> &str {
        &self.stored_value
    }

    pub fn set_value(&mut self, value: String) {
        log_str(&format!("Setting value to: {value}"));
        self.stored_value = value;
    }
}
