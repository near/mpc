//! Bridges the two `near-account-id` major versions in our dependency graph.
//!
//! `nearcore` is on `near-account-id 3`, while the crates.io `near-sdk` / `near-kit`
//! stack that the rest of the workspace shares is still capped at 2.x. That makes
//! the two `AccountId` types distinct to rustc, even though 3.0 left the validation
//! rules byte-for-byte unchanged — it only added the `UniversalAccount` classification
//! for `0u…` addresses. Both versions therefore accept exactly the same set of strings,
//! which is what makes the conversions below infallible.

use near_account_id::AccountId;
use near_indexer_primitives::types::AccountId as NearInternalAccountId;

/// Converts an account ID into the flavour the `nearcore` internals expect.
pub fn to_near_internal(account_id: &AccountId) -> NearInternalAccountId {
    account_id
        .as_str()
        .parse()
        .expect("a `near-account-id 2` account ID is always valid under `near-account-id 3`")
}

/// Converts an account ID coming out of the `nearcore` internals into the flavour
/// the rest of the workspace uses.
pub fn from_near_internal(account_id: &NearInternalAccountId) -> AccountId {
    account_id
        .as_str()
        .parse()
        .expect("a `near-account-id 3` account ID is always valid under `near-account-id 2`")
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    const ACCOUNT_IDS: &[&str] = &[
        "alice.near",
        "v1.signer",
        "ab",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0x0123456789012345678901234567890123456789",
        "0u000g40r40m30e209185gr38e1w8124gk2gahc5rr34d1p70x3rfg",
    ];

    #[test]
    fn account_id_conversion__should_round_trip_every_account_flavour() {
        for account_id in ACCOUNT_IDS {
            // Given
            let original: AccountId = account_id.parse().expect("test account ID is valid");

            // When
            let round_tripped = from_near_internal(&to_near_internal(&original));

            // Then
            assert_eq!(round_tripped, original);
        }
    }
}
