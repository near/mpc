//! Canonical `AccountId` re-export.
//!
//! All MPC crates get their `AccountId` from here (via `mpc_primitives::AccountId`)
//! so the workspace never mixes wrappers around `near_account_id::AccountId` with
//! the real thing.

pub use near_account_id::AccountId;

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// A small, stable sample covering the length/charset bounds a real MPC
    /// participant list is likely to exercise.
    fn sample_account_ids() -> Vec<AccountId> {
        [
            "alice.near",
            "bob.near",
            "carol-42.near",
            "node0.mpc-test.testnet",
            "a.b",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]
        .into_iter()
        .map(|s| s.parse().unwrap())
        .collect()
    }

    #[test]
    fn account_id__serde_json_format_is_stable() {
        // Given
        let ids = sample_account_ids();

        // When
        let json = serde_json::to_string_pretty(&ids).unwrap();

        // Then
        insta::assert_snapshot!(json);
    }

    #[test]
    fn account_id__borsh_format_is_stable() {
        // Given
        let ids = sample_account_ids();

        // When
        let bytes = borsh::to_vec(&ids).unwrap();

        // Then — compare against a hex snapshot so the exact on-chain layout is pinned.
        insta::assert_snapshot!(hex::encode(&bytes));
    }

    #[test]
    fn account_id__serde_json_round_trip() {
        // Given
        let ids = sample_account_ids();

        // When
        let json = serde_json::to_string(&ids).unwrap();
        let decoded: Vec<AccountId> = serde_json::from_str(&json).unwrap();

        // Then
        assert_eq!(decoded, ids);
    }

    #[test]
    fn account_id__borsh_round_trip() {
        // Given
        let ids = sample_account_ids();

        // When
        let bytes = borsh::to_vec(&ids).unwrap();
        let decoded: Vec<AccountId> = borsh::from_slice(&bytes).unwrap();

        // Then
        assert_eq!(decoded, ids);
    }
}
