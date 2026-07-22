//! Deposit amounts to attach to contract methods. One shared value for node,
//! tests, and e2e.

/// Deposit for `submit_participant_info`. The contract requires exactly this
/// flat fee to store the bounded attestation entry; nothing is refunded.
pub const SUBMIT_PARTICIPANT_INFO_DEPOSIT_MILLINEAR: u128 = 100;

pub const SIGN_DEPOSIT_YOCTONEAR: u128 = 1;

pub const PROPOSE_UPDATE_DEPOSIT_MILLINEAR: u128 = 17_000;
