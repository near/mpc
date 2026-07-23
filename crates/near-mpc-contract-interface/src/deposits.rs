//! Deposit amounts to attach to contract methods. One shared value for node,
//! tests, and e2e.

/// Deposit for `submit_participant_info`. The contract requires exactly this
/// flat fee to store the bounded attestation entry; nothing is refunded.
pub const SUBMIT_PARTICIPANT_INFO_DEPOSIT_MILLINEAR: u128 = 100;

pub const SIGN_DEPOSIT_YOCTONEAR: u128 = 1;

/// The NEAR protocol's `storage_amount_per_byte`, for clients computing
/// deposits off-chain; must track the protocol value or clients underpay and
/// fail with `InsufficientDeposit` (the contract reads it from the host).
pub const STORAGE_BYTE_COST_YOCTONEAR: u128 = 10_000_000_000_000_000_000;

/// Storage bound for a proposed update's bookkeeping: entry metadata plus up
/// to 128 max-length participant votes (measured at 25 479 bytes by
/// `propose_update_entry_overhead__should_cover_worst_case_entry_and_votes`).
pub const PROPOSE_UPDATE_ENTRY_OVERHEAD_BYTES: u128 = 32_768;

pub fn propose_update_required_deposit_yoctonear(
    payload_bytes: u128,
    storage_byte_cost_yoctonear: u128,
) -> u128 {
    storage_byte_cost_yoctonear
        .saturating_mul(PROPOSE_UPDATE_ENTRY_OVERHEAD_BYTES.saturating_add(payload_bytes))
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{PROPOSE_UPDATE_ENTRY_OVERHEAD_BYTES, propose_update_required_deposit_yoctonear};

    #[test]
    fn propose_update_required_deposit__should_charge_overhead_plus_payload() {
        // Given
        let payload_bytes = 3;
        let storage_byte_cost = 2;

        // When
        let deposit = propose_update_required_deposit_yoctonear(payload_bytes, storage_byte_cost);

        // Then
        assert_eq!(
            deposit,
            2 * (PROPOSE_UPDATE_ENTRY_OVERHEAD_BYTES + payload_bytes)
        );
    }

    #[test]
    fn propose_update_required_deposit__should_saturate_instead_of_overflowing() {
        // Given
        let payload_bytes = u128::MAX;
        let storage_byte_cost = u128::MAX;

        // When
        let deposit = propose_update_required_deposit_yoctonear(payload_bytes, storage_byte_cost);

        // Then
        assert_eq!(deposit, u128::MAX);
    }
}
