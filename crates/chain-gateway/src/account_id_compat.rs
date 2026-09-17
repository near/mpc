//! Bridges the two `near-account-id` major versions in our dependency graph.
//!
//! `nearcore` is on `near-account-id 3`, while the crates.io `near-sdk` / `near-kit`
//! stack that the rest of the workspace shares is still capped at 2.x. That makes
//! the two `AccountId` types distinct to rustc, even though 3.0 left the validation
//! rules byte-for-byte unchanged — it only added the `UniversalAccount` classification
//! for `0u…` addresses. Both versions therefore accept exactly the same set of strings.
//!
//! That equivalence is not type-checked, though: it is a property of two version pins
//! that move independently (`near-account-id` on crates.io, and whatever the nearcore
//! tag vendors). So only the config-derived direction, [`to_near_internal`], treats it
//! as an invariant; [`from_near_internal`] runs on chain data and stays fallible, so a
//! future divergence costs one skipped request instead of the whole node.

use near_account_id::{AccountId, ParseAccountError};
use near_indexer_primitives::types::AccountId as NearInternalAccountId;

/// Converts an account ID into the flavour the `nearcore` internals expect.
///
/// Infallible by the equivalence described in the module docs. Callers pass
/// config-derived IDs, already parsed at startup, so a divergence would surface
/// as an immediate crash on a value an operator can fix — not mid-stream.
pub fn to_near_internal(account_id: &AccountId) -> NearInternalAccountId {
    account_id
        .as_str()
        .parse()
        .expect("a `near-account-id 2` account ID is always valid under `near-account-id 3`")
}

/// Converts an account ID coming out of the `nearcore` internals into the flavour
/// the rest of the workspace uses.
///
/// Fallible on purpose: the inputs are receipt fields chosen by arbitrary callers, so
/// this must not be the place the node dies if the two versions ever drift apart.
pub fn from_near_internal(
    account_id: &NearInternalAccountId,
) -> Result<AccountId, ParseAccountError> {
    account_id.as_str().parse()
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    /// Accepted by both versions: the named, implicit and ETH-implicit flavours, the
    /// 2- and 64-character length bounds, and one canonical `0u…` address — the only
    /// shape 3.0 classifies differently (as a `UniversalAccount`).
    const ACCEPTED_ACCOUNT_IDS: &[&str] = &[
        "alice.near",
        "v1.signer",
        "ab",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0x0123456789012345678901234567890123456789",
        "0u000g40r40m30e209185gr38e1w8124gk2gahc5rr34d1p70x3rfg",
    ];

    /// Near-misses for the `0u…` scheme: too short, dotted, one symbol under and over the
    /// 54-character length, and a non-canonical final symbol. All are accepted by both
    /// versions today — as ordinary named accounts, since none satisfies `is_universal` —
    /// which is exactly why they are the first inputs a change to the classification rules
    /// would move. Listed separately from [`ACCEPTED_ACCOUNT_IDS`] because what matters
    /// here is that the two versions agree, not the verdict itself.
    const UNIVERSAL_NEAR_MISS_ACCOUNT_IDS: &[&str] = &[
        "0u",
        "0ufoo.near",
        "0u000g40r40m30e209185gr38e1w8124gk2gahc5rr34d1p70x3rf",
        "0u000g40r40m30e209185gr38e1w8124gk2gahc5rr34d1p70x3rfgg",
        "0u000g40r40m30e209185gr38e1w8124gk2gahc5rr34d1p70x3rfz",
    ];

    /// Rejected by both versions: below the 2-character minimum, uppercase, an empty
    /// separator-delimited part, and one over the 64-character maximum.
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
