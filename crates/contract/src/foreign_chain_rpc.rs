//! On-chain whitelist of RPC providers for foreign-chain transaction validation.
//!
//! The MPC network agrees, by vote, on which RPC providers any node may use to verify
//! foreign-chain transactions. Operators reference providers from this whitelist by
//! `provider_id` in their local `foreign_chains.yaml`; the full URL is assembled from
//! `base_url` + `chain_routing` + the operator's token (placed per `auth_scheme`).
//!
//! This module ships the *data structures* only — see [`ForeignChainRpcWhitelist`] for the
//! contract state shape. Vote endpoints (`vote_add_foreign_chain_provider` /
//! `vote_remove_foreign_chain_provider`), pending-vote tracking, and per-chain voting
//! thresholds land in a follow-up PR.

use std::collections::BTreeMap;

use near_mpc_contract_interface::types::{ForeignChain, ProviderEntry, ProviderId};
use near_sdk::near;

/// Per-chain set of voted-in providers. Inner `BTreeMap` is keyed by `provider_id`, so
/// uniqueness within a chain is enforced structurally by the map (no manual dedup
/// invariant). The same `provider_id` (e.g. `"ankr"`) showing up under different chains
/// is expected — each entry carries chain-specific connection details (`base_url`,
/// `chain_routing`), so two `"ankr"` entries in different chains are per-chain configs,
/// not duplicates.
//
// Borsh-only: `AllowedProviders` is `pub(crate)` and only ever lives in contract state.
// The view function returns `self.entries.snapshot()` — a `BTreeMap<ForeignChain, …>`,
// not `AllowedProviders` itself — so no JSON serializer is needed here.
#[near(serializers=[borsh])]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AllowedProviders {
    entries: BTreeMap<ForeignChain, BTreeMap<ProviderId, ProviderEntry>>,
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
    /// (the existing entry is left untouched — the new one is *not* substituted in).
    pub fn add(&mut self, chain: ForeignChain, entry: ProviderEntry) -> bool {
        let bucket = self.entries.entry(chain).or_default();
        if bucket.contains_key(&entry.provider_id) {
            return false;
        }
        bucket.insert(entry.provider_id.clone(), entry);
        true
    }

    /// Remove the provider with `provider_id` from `chain`. Returns `true` if an entry
    /// was removed.
    pub fn remove(&mut self, chain: ForeignChain, provider_id: &ProviderId) -> bool {
        let Some(bucket) = self.entries.get_mut(&chain) else {
            return false;
        };
        let removed = bucket.remove(provider_id).is_some();
        // Keep the map clean: drop the chain's slot once it goes empty so views don't
        // surface chains with no providers.
        if bucket.is_empty() {
            self.entries.remove(&chain);
        }
        removed
    }

    /// All providers currently whitelisted for `chain`, in `provider_id` order
    /// (BTreeMap iteration order). Empty iterator if the chain has no entries.
    pub fn get(&self, chain: ForeignChain) -> impl Iterator<Item = &ProviderEntry> {
        self.entries
            .get(&chain)
            .into_iter()
            .flat_map(|bucket| bucket.values())
    }

    /// Full per-chain view, suitable for returning from a view function. Each chain's
    /// `Vec` is sorted by `provider_id` (BTreeMap iteration order).
    pub fn snapshot(&self) -> BTreeMap<ForeignChain, Vec<ProviderEntry>> {
        self.entries
            .iter()
            .map(|(chain, bucket)| (*chain, bucket.values().cloned().collect()))
            .collect()
    }
}

/// Top-level contract state for the foreign-chain RPC provider whitelist. Held as a
/// field on `MpcContract`. Currently a thin wrapper around [`AllowedProviders`]; the
/// follow-up PR adds the vote state (pending votes, per-chain voting thresholds).
#[near(serializers=[borsh])]
#[derive(Debug, Clone, Default)]
pub struct ForeignChainRpcWhitelist {
    pub(crate) entries: AllowedProviders,
}

impl ForeignChainRpcWhitelist {
    pub fn allowed_providers(&self) -> BTreeMap<ForeignChain, Vec<ProviderEntry>> {
        self.entries.snapshot()
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
        let entries: Vec<&ProviderEntry> = allowed.get(ForeignChain::Ethereum).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].provider_id, "alchemy");
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
        let entries: Vec<&ProviderEntry> = allowed.get(ForeignChain::Ethereum).collect();
        assert_eq!(entries.len(), 1);
        // The original entry is unchanged.
        assert_eq!(entries[0].base_url, "https://alchemy.example.com");
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
        assert_eq!(allowed.get(ForeignChain::Ethereum).count(), 1);
        assert_eq!(allowed.get(ForeignChain::Polygon).count(), 1);
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
        let remaining: Vec<&ProviderEntry> = allowed.get(ForeignChain::Ethereum).collect();
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
        assert_eq!(allowed.get(ForeignChain::Ethereum).count(), 1);
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
}
