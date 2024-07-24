use near_sdk::{env, near, PanicOnDefault};

// use crate::FailureContractExt;

#[derive(Debug, PanicOnDefault)]
#[near(serializers=[borsh, json], contract_state)]
pub struct FailureContract {
    state: String,
}

#[near]
impl FailureContract {
    #[private]
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        env::panic_str("Migrate should rollback state");
    }
}
