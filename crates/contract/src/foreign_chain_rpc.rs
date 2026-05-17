//! On-chain whitelist of RPC providers for foreign-chain transaction validation.
//! The vote endpoint, view function, and per-chain voting thresholds land in a follow-up PR.

use std::collections::{btree_map::Entry, BTreeMap};

use near_mpc_contract_interface::types::{ForeignChain, ProviderEntry, ProviderId};
use near_sdk::near;

#[near(serializers=[borsh])]
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct AllowedProviders {
    entries: BTreeMap<ForeignChain, BTreeMap<ProviderId, ProviderEntry>>,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "wired to vote endpoint + view fn in the follow-up PR"
    )
)]
impl AllowedProviders {
    /// Insert a new provider for `chain`. Returns `false` if `provider_id` is already
    /// present (existing entry is left untouched).
    pub fn add(&mut self, chain: ForeignChain, entry: ProviderEntry) -> bool {
        let bucket = self.entries.entry(chain).or_default();
        match bucket.entry(entry.provider_id.clone()) {
            Entry::Vacant(slot) => {
                slot.insert(entry);
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    /// Remove the provider with `provider_id` from `chain`. Returns `true` if an entry
    /// was removed.
    pub fn remove(&mut self, chain: ForeignChain, provider_id: &ProviderId) -> bool {
        let Some(bucket) = self.entries.get_mut(&chain) else {
            return false;
        };
        let removed = bucket.remove(provider_id).is_some();
        if bucket.is_empty() {
            self.entries.remove(&chain);
        }
        removed
    }

    /// All providers currently whitelisted for `chain`, in `provider_id` order.
    pub fn get(&self, chain: ForeignChain) -> impl Iterator<Item = &ProviderEntry> {
        self.entries
            .get(&chain)
            .into_iter()
            .flat_map(|bucket| bucket.values())
    }
}

#[near(serializers=[borsh])]
#[derive(Debug, Default)]
pub struct ForeignChainRpcWhitelist {
    pub(crate) entries: AllowedProviders,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use near_mpc_contract_interface::types::{AuthScheme, ChainRouting};

    fn entry(provider_id: &str) -> ProviderEntry {
        ProviderEntry {
            provider_id: ProviderId(provider_id.to_string()),
            base_url: format!("https://{provider_id}.example.com"),
            auth_scheme: AuthScheme::None,
            chain_routing: ChainRouting::Embedded,
        }
    }

    fn pid(s: &str) -> ProviderId {
        ProviderId(s.to_string())
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
        assert_eq!(entries[0].provider_id, pid("alchemy"));
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
        let removed = allowed.remove(ForeignChain::Ethereum, &pid("alchemy"));

        // Then
        assert!(removed);
        let remaining: Vec<&ProviderEntry> = allowed.get(ForeignChain::Ethereum).collect();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].provider_id, pid("ankr"));
    }

    #[test]
    fn allowed_providers__should_return_false_when_removing_unknown_provider_id() {
        // Given
        let mut allowed = AllowedProviders::default();
        allowed.add(ForeignChain::Ethereum, entry("alchemy"));

        // When
        let removed_unknown_id = allowed.remove(ForeignChain::Ethereum, &pid("does-not-exist"));
        let removed_unknown_chain = allowed.remove(ForeignChain::Polygon, &pid("alchemy"));

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
        let removed = allowed.remove(ForeignChain::Ethereum, &pid("alchemy"));

        // Then: the chain has no entries.
        assert!(removed);
        assert_eq!(allowed.get(ForeignChain::Ethereum).count(), 0);
    }
}
