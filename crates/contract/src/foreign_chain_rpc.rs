//! On-chain whitelist of RPC providers for foreign-chain transaction validation.
//!
//! The MPC network agrees, by vote, on which RPC providers each node may use to verify
//! foreign-chain transactions. Operators reference providers from this whitelist by
//! `provider_id` in their local `foreign_chains.yaml`; the full URL is assembled from
//! `base_url` + `chain_routing` + the operator's token (placed per `auth_scheme`).
//!
//! This module ships the *data structures* only — see [`ForeignChainRpcWhitelist`] for the
//! contract state shape. Vote endpoints (`vote_add_foreign_chain_provider` /
//! `vote_remove_foreign_chain_provider`) land in a follow-up PR and will mutate the
//! whitelist's inner `entries` / `votes` fields. Until that PR ships, every chain uses
//! [`DEFAULT_PROVIDER_VOTE_THRESHOLD`] for its vote threshold.

use std::collections::BTreeMap;

use near_mpc_contract_interface::types::{
    ForeignChain, ProviderEntry, ProviderId, ProviderVoteAction,
};
use near_sdk::near;

use crate::primitives::key_state::AuthenticatedParticipantId;

/// Default vote threshold used by every chain until `vote_set_foreign_chain_provider_threshold`
/// (future PR) lets the network override it per chain. Two votes is the smallest threshold
/// that still requires more than one party to agree, which is the meaningful security floor.
pub const DEFAULT_PROVIDER_VOTE_THRESHOLD: u64 = 2;

/// Per-chain set of voted-in providers. Within a chain `provider_id` is unique; uniqueness
/// is enforced on [`AllowedProviders::add`]. The same `provider_id` (e.g. `"ankr"`) showing
/// up under different chains is expected — each entry carries chain-specific connection
/// details (`base_url`, `chain_routing`), so two `"ankr"` entries are per-chain configs,
/// not duplicates.
//
// Borsh-only: `AllowedProviders` is `pub(crate)` and only ever lives in contract state.
// The view function returns `self.entries.snapshot()` — a `BTreeMap<ForeignChain, …>`,
// not `AllowedProviders` itself — so no JSON serializer is needed here.
#[near(serializers=[borsh])]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AllowedProviders {
    entries: BTreeMap<ForeignChain, Vec<ProviderEntry>>,
}

// `add` / `remove` / `get` are exercised by the unit tests in this module and will be wired
// to the vote endpoints in the follow-up PR. In the test build the dead_code lint doesn't
// fire (tests call them), so scope the expect to non-test builds only.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used by tests now; wired to vote endpoints in the follow-up PR"
    )
)]
impl AllowedProviders {
    /// Insert a new provider for `chain`. Returns `true` if the provider was added,
    /// `false` if an entry with the same `provider_id` already exists for this chain
    /// (the existing entry is left untouched).
    pub fn add(&mut self, chain: ForeignChain, entry: ProviderEntry) -> bool {
        let bucket = self.entries.entry(chain).or_default();
        if bucket.iter().any(|e| e.provider_id == entry.provider_id) {
            return false;
        }
        bucket.push(entry);
        true
    }

    /// Remove the provider with `provider_id` from `chain`. Returns `true` if an entry
    /// was removed.
    pub fn remove(&mut self, chain: ForeignChain, provider_id: &ProviderId) -> bool {
        let Some(bucket) = self.entries.get_mut(&chain) else {
            return false;
        };
        let len_before = bucket.len();
        bucket.retain(|e| &e.provider_id != provider_id);
        let removed = bucket.len() < len_before;
        // Keep the map clean: drop the chain's slot once it goes empty so views don't
        // surface chains with no providers.
        if bucket.is_empty() {
            self.entries.remove(&chain);
        }
        removed
    }

    /// All providers currently whitelisted for `chain`.
    pub fn get(&self, chain: ForeignChain) -> &[ProviderEntry] {
        self.entries.get(&chain).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Full per-chain view, suitable for returning from a view function.
    pub fn snapshot(&self) -> BTreeMap<ForeignChain, Vec<ProviderEntry>> {
        self.entries.clone()
    }
}

/// Pending votes partitioned by **target** = `(chain, provider_id)`. Within a target,
/// each participant has at most one active vote — voting again for the same target
/// overwrites their prior vote. A participant can have active votes across many targets
/// simultaneously; rounds are independent.
///
/// Methods that mutate the vote state (`vote`, `clear_target`, `get_remaining_votes`)
/// land with the vote endpoint PR.
//
// Explicit derives (not `#[near(serializers=[borsh, json])]`) so we can gate
// `serde::Deserialize` off wasm — the contract never deserializes `ProviderVotes` from
// JSON, only outputs it via the view function, and excluding the derive from the wasm
// build saves several KB of serde monomorphizations.
#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
    serde::Serialize,
)]
#[cfg_attr(not(target_arch = "wasm32"), derive(serde::Deserialize))]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct ProviderVotes {
    pub pending: BTreeMap<
        (ForeignChain, ProviderId),
        BTreeMap<AuthenticatedParticipantId, ProviderVoteAction>,
    >,
}

/// Top-level contract state for the foreign-chain RPC provider whitelist. Held as a
/// field on `MpcContract`.
#[near(serializers=[borsh])]
#[derive(Debug, Clone, Default)]
pub struct ForeignChainRpcWhitelist {
    pub(crate) entries: AllowedProviders,
    pub(crate) votes: ProviderVotes,
    /// Per-chain voting threshold. Populated by a future setter endpoint; lookups via
    /// [`Self::threshold_for`] fall back to [`DEFAULT_PROVIDER_VOTE_THRESHOLD`].
    pub(crate) chain_thresholds: BTreeMap<ForeignChain, u64>,
}

impl ForeignChainRpcWhitelist {
    /// Vote threshold required to add or remove a provider for `chain`. Returns
    /// [`DEFAULT_PROVIDER_VOTE_THRESHOLD`] when no explicit threshold has been voted in
    /// for the chain yet.
    pub fn threshold_for(&self, chain: ForeignChain) -> u64 {
        self.chain_thresholds
            .get(&chain)
            .copied()
            .unwrap_or(DEFAULT_PROVIDER_VOTE_THRESHOLD)
    }

    pub fn allowed_providers(&self) -> BTreeMap<ForeignChain, Vec<ProviderEntry>> {
        self.entries.snapshot()
    }

    pub fn provider_votes(&self) -> ProviderVotes {
        self.votes.clone()
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use near_mpc_contract_interface::types::{AuthScheme, ChainRouting};

    fn entry(provider_id: &str) -> ProviderEntry {
        ProviderEntry {
            provider_id: provider_id.to_string(),
            base_url: format!("https://{provider_id}.example.com"),
            auth_scheme: AuthScheme::None,
            chain_routing: ChainRouting::Embedded,
        }
    }

    #[test]
    fn allowed_providers__should_insert_new_entry_when_provider_id_is_unique_within_chain() {
        // Given
        let mut allowed = AllowedProviders::default();

        // When
        let added = allowed.add(ForeignChain::Ethereum, entry("alchemy"));

        // Then
        assert!(added);
        assert_eq!(allowed.get(ForeignChain::Ethereum).len(), 1);
        assert_eq!(
            allowed.get(ForeignChain::Ethereum)[0].provider_id,
            "alchemy"
        );
    }

    #[test]
    fn allowed_providers__should_reject_duplicate_provider_id_within_same_chain() {
        // Given
        let mut allowed = AllowedProviders::default();
        allowed.add(ForeignChain::Ethereum, entry("alchemy"));

        // When: adding another entry with the same provider_id (different base_url, same id)
        let mut second = entry("alchemy");
        second.base_url = "https://different.example.com".to_string();
        let added = allowed.add(ForeignChain::Ethereum, second);

        // Then
        assert!(!added);
        assert_eq!(allowed.get(ForeignChain::Ethereum).len(), 1);
        // The original entry is unchanged.
        assert_eq!(
            allowed.get(ForeignChain::Ethereum)[0].base_url,
            "https://alchemy.example.com"
        );
    }

    #[test]
    fn allowed_providers__should_accept_same_provider_id_across_different_chains() {
        // Given: same provider_id, two different chains.
        let mut allowed = AllowedProviders::default();

        // When
        let eth_added = allowed.add(ForeignChain::Ethereum, entry("ankr"));
        let polygon_added = allowed.add(ForeignChain::Polygon, entry("ankr"));

        // Then: both are accepted — per-chain entries are not duplicates.
        assert!(eth_added);
        assert!(polygon_added);
        assert_eq!(allowed.get(ForeignChain::Ethereum).len(), 1);
        assert_eq!(allowed.get(ForeignChain::Polygon).len(), 1);
    }

    #[test]
    fn allowed_providers__should_remove_existing_entry_by_provider_id() {
        // Given
        let mut allowed = AllowedProviders::default();
        allowed.add(ForeignChain::Ethereum, entry("alchemy"));
        allowed.add(ForeignChain::Ethereum, entry("ankr"));

        // When
        let removed = allowed.remove(ForeignChain::Ethereum, &"alchemy".to_string());

        // Then
        assert!(removed);
        let remaining = allowed.get(ForeignChain::Ethereum);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].provider_id, "ankr");
    }

    #[test]
    fn allowed_providers__should_return_false_when_removing_unknown_provider_id() {
        // Given
        let mut allowed = AllowedProviders::default();
        allowed.add(ForeignChain::Ethereum, entry("alchemy"));

        // When
        let removed_unknown_id =
            allowed.remove(ForeignChain::Ethereum, &"does-not-exist".to_string());
        let removed_unknown_chain = allowed.remove(ForeignChain::Polygon, &"alchemy".to_string());

        // Then
        assert!(!removed_unknown_id);
        assert!(!removed_unknown_chain);
        assert_eq!(allowed.get(ForeignChain::Ethereum).len(), 1);
    }

    #[test]
    fn allowed_providers__should_drop_chain_slot_when_last_provider_is_removed() {
        // Given: a chain with a single provider.
        let mut allowed = AllowedProviders::default();
        allowed.add(ForeignChain::Ethereum, entry("alchemy"));

        // When
        let removed = allowed.remove(ForeignChain::Ethereum, &"alchemy".to_string());

        // Then: the chain is no longer present in the snapshot at all.
        assert!(removed);
        assert!(!allowed.snapshot().contains_key(&ForeignChain::Ethereum));
    }

    #[test]
    fn whitelist__should_fall_back_to_default_threshold_when_chain_threshold_not_set() {
        // Given
        let whitelist = ForeignChainRpcWhitelist::default();

        // When / Then
        assert_eq!(
            whitelist.threshold_for(ForeignChain::Ethereum),
            DEFAULT_PROVIDER_VOTE_THRESHOLD
        );
        assert_eq!(
            whitelist.threshold_for(ForeignChain::Polygon),
            DEFAULT_PROVIDER_VOTE_THRESHOLD
        );
    }

    #[test]
    fn whitelist__should_return_configured_threshold_when_set() {
        // Given
        let mut whitelist = ForeignChainRpcWhitelist::default();
        whitelist.chain_thresholds.insert(ForeignChain::Ethereum, 5);

        // When / Then
        assert_eq!(whitelist.threshold_for(ForeignChain::Ethereum), 5);
        // Other chains still fall back to the default.
        assert_eq!(
            whitelist.threshold_for(ForeignChain::Polygon),
            DEFAULT_PROVIDER_VOTE_THRESHOLD
        );
    }
}
