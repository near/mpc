//! Deposit amounts to attach to contract methods, in yoctoNEAR. One shared value
//! for node, tests, and e2e.

/// Deposit for `submit_participant_info`. The contract charges the actual storage
/// cost and refunds the excess.
pub const SUBMIT_PARTICIPANT_INFO_DEPOSIT_YOCTONEAR: u128 = 1_000_000_000_000_000_000_000_000;
