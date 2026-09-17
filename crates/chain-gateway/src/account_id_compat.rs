//! Bridges the two `near-account-id` major versions in our dependency graph:
//! `nearcore` is on 3.x while the `near-sdk` stack the rest of the workspace
//! shares is on 2.x, making the two `AccountId` types distinct to rustc even
//! though both accept the same set of strings.

use near_account_id::{AccountId, ParseAccountError};
use near_indexer_primitives::types::AccountId as NearInternalAccountId;

/// Only pass config-derived IDs, never chain data: panics if the two versions
/// ever diverge.
pub fn to_near_internal(account_id: &AccountId) -> NearInternalAccountId {
    account_id
        .as_str()
        .parse()
        .expect("a `near-account-id 2` account ID is always valid under `near-account-id 3`")
}

pub fn from_near_internal(
    account_id: &NearInternalAccountId,
) -> Result<AccountId, ParseAccountError> {
    account_id.as_str().parse()
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    /// Named, implicit, ETH-implicit and universal (`0u…`) flavours, plus both
    /// length bounds.
    const ACCEPTED_ACCOUNT_IDS: &[&str] = &[
        "alice.near",
        "v1.signer",
        "ab",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0x0123456789012345678901234567890123456789",
        "0u000g40r40m30e209185gr38e1w8124gk2gahc5rr34d1p70x3rfg",
    ];

    /// Near-misses for the `0u…` universal-account scheme: the inputs most likely
    /// to move first if the two versions' classification rules drift.
    const UNIVERSAL_NEAR_MISS_ACCOUNT_IDS: &[&str] = &[
        "0u",
        "0ufoo.near",
        "0u000g40r40m30e209185gr38e1w8124gk2gahc5rr34d1p70x3rf",
        "0u000g40r40m30e209185gr38e1w8124gk2gahc5rr34d1p70x3rfgg",
        "0u000g40r40m30e209185gr38e1w8124gk2gahc5rr34d1p70x3rfz",
    ];

    const REJECTED_ACCOUNT_IDS: &[&str] = &[
        "a",
        "Alice.near",
        "alice..near",
        "00000000000000000000000000000000000000000000000000000000000000000",
    ];

    #[test]
    fn account_id_conversion__should_round_trip_every_account_flavour() {
        for account_id in ACCEPTED_ACCOUNT_IDS
            .iter()
            .chain(UNIVERSAL_NEAR_MISS_ACCOUNT_IDS)
        {
            // Given
            let original: AccountId = account_id.parse().expect("test account ID is valid");

            // When
            let round_tripped =
                from_near_internal(&to_near_internal(&original)).expect("round trip is lossless");

            // Then
            assert_eq!(round_tripped, original);
        }
    }

    #[test]
    fn account_id_validation__should_agree_across_both_versions() {
        for account_id in ACCEPTED_ACCOUNT_IDS
            .iter()
            .chain(UNIVERSAL_NEAR_MISS_ACCOUNT_IDS)
            .chain(REJECTED_ACCOUNT_IDS)
        {
            // Given
            let parsed_by_workspace = account_id.parse::<AccountId>();

            // When
            let parsed_by_nearcore = account_id.parse::<NearInternalAccountId>();

            // Then
            assert_eq!(
                parsed_by_workspace.is_ok(),
                parsed_by_nearcore.is_ok(),
                "`{account_id}` is accepted by one `near-account-id` version but not the other; \
                 the conversions in this module assume the two agree"
            );
        }
    }
}
