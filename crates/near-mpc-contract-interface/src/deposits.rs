//! Deposit amounts to attach to contract methods. One shared value for node,
//! tests, and e2e.

pub const SIGN_DEPOSIT_YOCTONEAR: u128 = 1;

pub const STORAGE_BYTE_COST_YOCTONEAR: u128 = 10_000_000_000_000_000_000;

pub const MINIMUM_NODE_MANAGEMENT_DEPOSIT_YOCTONEAR: u128 = 1;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("the required deposit exceeds u128::MAX yoctoNEAR")]
pub struct DepositOverflowError;

/// Deposit to attach to `submit_update`: the storage staking for a payload of `payload_bytes`.
/// Only the growth over the deployed code needs covering, but the contract cannot measure it,
/// so the whole payload is prepaid and the contract keeps the deposit.
pub fn submit_update_deposit_yoctonear(
    payload_bytes: usize,
    storage_byte_cost_yoctonear: u128,
) -> Result<u128, DepositOverflowError> {
    u128::try_from(payload_bytes)
        .ok()
        .and_then(|bytes| storage_byte_cost_yoctonear.checked_mul(bytes))
        .ok_or(DepositOverflowError)
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{
        DepositOverflowError, STORAGE_BYTE_COST_YOCTONEAR, submit_update_deposit_yoctonear,
    };

    #[test]
    fn submit_update_deposit__should_error_when_the_deposit_overflows() {
        // Given
        let payload_bytes = usize::MAX;

        // When
        let result = submit_update_deposit_yoctonear(payload_bytes, u128::MAX);

        // Then
        assert_eq!(result, Err(DepositOverflowError));
    }

    #[test]
    fn STORAGE_BYTE_COST_YOCTONEAR__should_match_env_storage_byte_cost() {
        assert_eq!(
            near_sdk::env::storage_byte_cost().as_yoctonear(),
            STORAGE_BYTE_COST_YOCTONEAR
        );
    }
}
