use near_mpc_contract_interface::types as dtos;
use near_sdk::near;
use near_sdk::store::IterableMap;

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

    /// Map of node's tls key to signer account public key. Same node operator can have multiple nodes, therefore multiple tls key.
    tls_key_by_signer_pk: IterableMap<dtos::Ed25519PublicKey, dtos::Ed25519PublicKey>,
}

impl Default for ForeignChainsMetadata {
    fn default() -> Self {
        Self {
            rpc_whitelist: Default::default(),
            available_foreign_chains: Default::default(),
            foreign_chains_configs: IterableMap::new(StorageKey::ForeignChainsConfigs),
            tls_key_by_signer_pk: IterableMap::new(StorageKey::TlsKeyBySignerPk),
        }
    }
}

impl ForeignChainsMetadata {
    /// Registers `foreign_chains_config` for the node.
    /// This means same node operator can register config per node.
    /// If the same `signer_pk` previously registered with a different TLS key, the stale entry is
    /// removed first.
    pub(crate) fn register(
        &mut self,
        signer_pk: dtos::Ed25519PublicKey,
        tls_key: dtos::Ed25519PublicKey,
        foreign_chains_config: dtos::ForeignChainsConfig,
    ) {
        if let Some(old_key) = self.tls_key_by_signer_pk.get(&signer_pk)
            && *old_key != tls_key
        {
            let old_key = old_key.clone();
            self.foreign_chains_configs.remove(&old_key);
        }
        // Two different signer keys must never share a TLS key. TLS key uniquely identifies a node.
        assert!(
            !self.foreign_chains_configs.contains_key(&tls_key)
                || self
                    .tls_key_by_signer_pk
                    .get(&signer_pk)
                    .is_some_and(|k| *k == tls_key),
            "TLS key already registered by a different signer"
        );
        self.tls_key_by_signer_pk.insert(signer_pk, tls_key.clone());
        self.foreign_chains_configs
            .insert(tls_key, foreign_chains_config);
    }

    /// Removes all entries from `tls_key_by_signer_pk` and `foreign_chains_configs` whose TLS key
    /// is not in `active_tls_keys`. Called during participant set cleanup.
    pub(crate) fn remove_stale_configs(
        &mut self,
        active_tls_keys: &std::collections::BTreeSet<dtos::Ed25519PublicKey>,
    ) {
        let stale_signer_pks: Vec<dtos::Ed25519PublicKey> = self
            .tls_key_by_signer_pk
            .iter()
            .filter(|(_, tls_key)| !active_tls_keys.contains(*tls_key))
            .map(|(signer_pk, _)| signer_pk.clone())
            .collect();
        for signer_pk in &stale_signer_pks {
            if let Some(tls_key) = self.tls_key_by_signer_pk.remove(signer_pk) {
                self.foreign_chains_configs.remove(&tls_key);
            }
        }
    }

    /// Returns clone of foreign chains as a map of <node tls key, foreign chain config>
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
    fn register__should_panic_when_different_signer_uses_same_tls_key() {
        // Given
        let mut meta = setup();
        let tls_key = make_key(1);
        meta.register(make_key(10), tls_key.clone(), empty_config());

        // When / Then
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            meta.register(make_key(20), tls_key, empty_config());
        }));
        assert!(result.is_err(), "expected panic for duplicate TLS key");
    }

    #[test]
    #[expect(non_snake_case)]
    fn register__should_allow_same_signer_to_re_register_with_same_tls_key() {
        // Given
        let mut meta = setup();
        let signer_pk = make_key(10);
        let tls_key = make_key(1);
        meta.register(signer_pk.clone(), tls_key.clone(), empty_config());

        // When / Then — no panic
        meta.register(signer_pk, tls_key, empty_config());
    }

    #[test]
    #[expect(non_snake_case)]
    fn register__should_allow_two_independent_registrations_to_coexist() {
        // Given
        let mut meta = setup();
        let tls_key_a = make_key(1);
        let tls_key_b = make_key(2);
        let signer_pk_a = make_key(10);
        let signer_pk_b = make_key(20);

        // When
        meta.register(signer_pk_a, tls_key_a.clone(), empty_config());
        meta.register(signer_pk_b, tls_key_b.clone(), empty_config());

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
        meta.register(make_key(10), tls_key_a.clone(), empty_config());
        meta.register(make_key(20), tls_key_b.clone(), empty_config());

        // When — only tls_key_a is active
        let active = BTreeSet::from([tls_key_a.clone()]);
        meta.remove_stale_configs(&active);

        // Then
        assert!(meta.foreign_chains_configs.contains_key(&tls_key_a));
        assert!(!meta.foreign_chains_configs.contains_key(&tls_key_b));
    }
}
