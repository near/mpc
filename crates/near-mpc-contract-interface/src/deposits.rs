//! Deposit amounts to attach to contract methods. One shared value for node,
//! tests, and e2e.

pub const SIGN_DEPOSIT_YOCTONEAR: u128 = 1;

pub const SUBMIT_CONTRACT_UPDATE_DEPOSIT_YOCTONEAR: u128 = 1;

pub const STORAGE_BYTE_COST_YOCTONEAR: u128 = 10_000_000_000_000_000_000;

pub const MINIMUM_NODE_MANAGEMENT_DEPOSIT_YOCTONEAR: u128 = 1;

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::STORAGE_BYTE_COST_YOCTONEAR;

    #[test]
    fn STORAGE_BYTE_COST_YOCTONEAR__should_match_env_storage_byte_cost() {
        assert_eq!(
            near_sdk::env::storage_byte_cost().as_yoctonear(),
            STORAGE_BYTE_COST_YOCTONEAR
        );
    }
}
