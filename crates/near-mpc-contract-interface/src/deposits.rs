//! Deposit amounts to attach to contract methods. One shared value for node,
//! tests, and e2e.

/// Deposit for `submit_participant_info`. Sized to cover the worst-case
/// attestation entry; the contract keeps only the actual storage delta and
/// refunds the rest.
pub const SUBMIT_PARTICIPANT_INFO_DEPOSIT_MILLINEAR: u128 = 100;

pub const SIGN_DEPOSIT_YOCTONEAR: u128 = 1;
