use std::collections::BTreeSet;

use near_mpc_contract_interface::types as dtos;
use near_sdk::{near, store::IterableMap};

use crate::foreign_chain_rpc::ForeignChainRpcWhitelist;
use crate::storage_keys::StorageKey;

/// All foreign-chain state: the RPC provider whitelist, the per-node config reports, and the
/// cached available-chain set derived from them.
#[near(serializers=[borsh])]
#[derive(Debug)]
pub(crate) struct ForeignChainsMetadata {
    pub(crate) rpc_whitelist: ForeignChainRpcWhitelist,
    pub(crate) available_foreign_chains: dtos::AvailableForeignChains,
    pub(crate) foreign_chains_configs:
        IterableMap<dtos::Ed25519PublicKey, dtos::ForeignChainsConfig>,
}

impl Default for ForeignChainsMetadata {
    fn default() -> Self {
        Self {
            rpc_whitelist: Default::default(),
            available_foreign_chains: Default::default(),
            foreign_chains_configs: IterableMap::new(StorageKey::ForeignChainsConfigs),
        }
    }
}

impl ForeignChainsMetadata {
    /// Registers `foreign_chains_config` keyed by TLS key, so multiple nodes from the same operator can coexist.
    pub(crate) fn register(
        &mut self,
        tls_key: dtos::Ed25519PublicKey,
        foreign_chains_config: dtos::ForeignChainsConfig,
    ) {
        self.foreign_chains_configs
            .insert(tls_key, foreign_chains_config);
    }

    pub(crate) fn update_available_chains_config_cache(
        &mut self,
        active_tls_keys: &BTreeSet<dtos::Ed25519PublicKey>,
        threshold: u64,
    ) {
        let mut chain_to_supporter_count: std::collections::BTreeMap<dtos::ForeignChain, u64> =
            std::collections::BTreeMap::new();
        for tls_key in active_tls_keys {
            let Some(chains) = self.foreign_chains_configs.get(tls_key) else {
                continue;
            };
            for chain in chains.iter() {
                if self.rpc_whitelist.entries.is_whitelisted(chain) {
                    let count = chain_to_supporter_count.entry(*chain).or_default();
                    *count = count
                        .checked_add(1)
                        .expect("supporter count bounded by participant set size");
                }
            }
        }
        self.available_foreign_chains = chain_to_supporter_count
            .into_iter()
            .filter_map(|(chain, count)| (count >= threshold).then_some(chain))
            .collect::<BTreeSet<_>>()
            .into();
    }

    pub(crate) fn remove_stale_configs(
        &mut self,
        active_tls_keys: &BTreeSet<dtos::Ed25519PublicKey>,
    ) {
        let stale_tls_keys: Vec<dtos::Ed25519PublicKey> = self
            .foreign_chains_configs
            .keys()
            .filter(|tls_key| !active_tls_keys.contains(*tls_key))
            .cloned()
            .collect();
        for tls_key in stale_tls_keys {
            self.foreign_chains_configs.remove(&tls_key);
        }
    }

    pub(crate) fn snapshot_by_node(&self) -> dtos::ForeignChainsConfigs {
        self.foreign_chains_configs
            .iter()
            .map(|(id, chains)| (id.clone(), chains.clone()))
            .collect::<std::collections::BTreeMap<_, _>>()
            .into()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    use super::*;

    #[cfg(all(feature = "__abi-generate", not(target_arch = "wasm32")))]
    #[test]
    #[expect(non_snake_case)]
    fn foreign_chains_metadata_borsh_schema__should_not_change() {
        let schema = borsh::schema::BorshSchemaContainer::for_type::<ForeignChainsMetadata>();
        insta::assert_debug_snapshot!(schema);
    }

    fn make_key(byte: u8) -> dtos::Ed25519PublicKey {
        dtos::Ed25519PublicKey([byte; 32])
    }

    fn empty_config() -> dtos::ForeignChainsConfig {
        BTreeSet::new().into()
    }

    fn setup() -> ForeignChainsMetadata {
        testing_env!(VMContextBuilder::new().build());
        ForeignChainsMetadata::default()
    }

    #[test]
    #[expect(non_snake_case)]
    fn register__should_allow_two_independent_registrations_to_coexist() {
        // Given
        let mut meta = setup();
        let tls_key_a = make_key(1);
        let tls_key_b = make_key(2);

        // When
        meta.register(tls_key_a.clone(), empty_config());
        meta.register(tls_key_b.clone(), empty_config());

        // Then — both entries exist
        assert!(meta.foreign_chains_configs.contains_key(&tls_key_a));
        assert!(meta.foreign_chains_configs.contains_key(&tls_key_b));
    }

    #[test]
    #[expect(non_snake_case)]
    fn remove_stale_configs__should_remove_entries_not_in_active_set() {
        // Given
        let mut meta = setup();
        let tls_key_a = make_key(1);
        let tls_key_b = make_key(2);
        meta.register(tls_key_a.clone(), empty_config());
        meta.register(tls_key_b.clone(), empty_config());

        // When — only tls_key_a is active
        let active = BTreeSet::from([tls_key_a.clone()]);
        meta.remove_stale_configs(&active);

        // Then
        assert!(meta.foreign_chains_configs.contains_key(&tls_key_a));
        assert!(!meta.foreign_chains_configs.contains_key(&tls_key_b));
    }
}
