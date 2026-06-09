use near_mpc_contract_interface::types as dtos;
use near_sdk::near;
use near_sdk::store::{IterableMap, LookupMap};

use crate::foreign_chain_rpc::ForeignChainRpcWhitelist;
use crate::storage_keys::StorageKey;

/// All foreign-chain state: the RPC provider whitelist, the per-node config reports, and the
/// cached available-chain set derived from them. Stored behind `Lazy<>` in `MpcContract` so it
/// is only deserialized when foreign-chain methods are called.
#[near(serializers=[borsh])]
#[derive(Debug)]
pub(crate) struct ForeignChainsMetadata {
    pub(crate) rpc_whitelist: ForeignChainRpcWhitelist,
    pub(crate) available_foreign_chains: dtos::AvailableForeignChains,
    pub(crate) foreign_chains_configs:
        IterableMap<dtos::Ed25519PublicKey, dtos::ForeignChainsConfig>,
    /// Reverse map from account ID to its most-recently registered TLS key, used to remove
    /// stale `foreign_chains_configs` entries when a node rotates its TLS key.
    tls_key_by_account: LookupMap<dtos::AccountId, dtos::Ed25519PublicKey>,
}

impl Default for ForeignChainsMetadata {
    fn default() -> Self {
        Self {
            rpc_whitelist: Default::default(),
            available_foreign_chains: Default::default(),
            foreign_chains_configs: IterableMap::new(StorageKey::ForeignChainsConfigs),
            tls_key_by_account: LookupMap::new(StorageKey::TlsKeyByAccount),
        }
    }
}

impl ForeignChainsMetadata {
    /// Creates a new instance carrying over an existing `rpc_whitelist`; all other fields default.
    pub(crate) fn with_rpc_whitelist(rpc_whitelist: ForeignChainRpcWhitelist) -> Self {
        Self {
            rpc_whitelist,
            ..Default::default()
        }
    }

    /// Registers `foreign_chains_config` for the given account, keyed by `tls_key`. If the
    /// account previously registered with a different TLS key, the stale entry is removed first.
    pub(crate) fn register(
        &mut self,
        account_id: dtos::AccountId,
        tls_key: dtos::Ed25519PublicKey,
        foreign_chains_config: dtos::ForeignChainsConfig,
    ) {
        if let Some(old_key) = self.tls_key_by_account.get(&account_id)
            && *old_key != tls_key
        {
            let old_key = old_key.clone();
            self.foreign_chains_configs.remove(&old_key);
        }
        // Two different accounts must never share a TLS key — the key uniquely identifies a node.
        assert!(
            !self.foreign_chains_configs.contains_key(&tls_key)
                || self
                    .tls_key_by_account
                    .get(&account_id)
                    .is_some_and(|k| *k == tls_key),
            "TLS key already registered by a different account"
        );
        self.tls_key_by_account.insert(account_id, tls_key.clone());
        self.foreign_chains_configs
            .insert(tls_key, foreign_chains_config);
    }

    pub(crate) fn snapshot_by_node(&self) -> dtos::ForeignChainsConfigs {
        self.foreign_chains_configs
            .iter()
            .map(|(id, chains)| (id.clone(), chains.clone()))
            .collect::<std::collections::BTreeMap<_, _>>()
            .into()
    }
}
