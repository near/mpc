//! Deposit amounts to attach to contract methods. One shared value for node,
//! tests, and e2e.

/// Deposit for `submit_participant_info`. The contract requires exactly this
/// flat fee to store the bounded attestation entry; nothing is refunded.
pub const SUBMIT_PARTICIPANT_INFO_DEPOSIT_MILLINEAR: u128 = 100;

pub const SIGN_DEPOSIT_YOCTONEAR: u128 = 1;

pub const STORAGE_BYTE_COST_YOCTONEAR: u128 = 10_000_000_000_000_000_000;

pub const PROPOSE_UPDATE_ENTRY_OVERHEAD_BYTES: u128 = 32_768;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("the required deposit exceeds u128::MAX yoctoNEAR")]
pub struct DepositOverflowError;

pub fn propose_update_required_deposit_yoctonear(
    payload_bytes: u128,
    storage_byte_cost_yoctonear: u128,
) -> Result<u128, DepositOverflowError> {
    PROPOSE_UPDATE_ENTRY_OVERHEAD_BYTES
        .checked_add(payload_bytes)
        .and_then(|bytes| storage_byte_cost_yoctonear.checked_mul(bytes))
        .ok_or(DepositOverflowError)
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{
        DepositOverflowError, STORAGE_BYTE_COST_YOCTONEAR,
        propose_update_required_deposit_yoctonear,
    };

    #[test]
    fn propose_update_required_deposit__should_error_when_the_deposit_overflows() {
        // Given
        let payload_bytes = u128::MAX;

        // When
        let result =
            propose_update_required_deposit_yoctonear(payload_bytes, STORAGE_BYTE_COST_YOCTONEAR);

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
