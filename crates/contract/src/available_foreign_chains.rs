use std::collections::BTreeMap;

use near_mpc_contract_interface::types as dtos;
use near_sdk::near;
use near_sdk::store::{IterableMap, LookupMap};

use crate::storage_keys::StorageKey;

/// Cached available foreign-chain set and the per-node coverage map that feeds it.
#[near(serializers=[borsh])]
#[derive(Debug)]
pub(crate) struct ForeignChainAvailability {
    pub(crate) available_foreign_chains: dtos::AvailableForeignChains,
    pub(crate) available_foreign_chains_by_node:
        IterableMap<dtos::Ed25519PublicKey, dtos::AvailableForeignChains>,
    /// Reverse map from account ID to its most-recently registered TLS key, used to remove
    /// stale `available_foreign_chains_by_node` entries when a node rotates its TLS key.
    tls_key_by_account: LookupMap<dtos::AccountId, dtos::Ed25519PublicKey>,
}

impl Default for ForeignChainAvailability {
    fn default() -> Self {
        Self {
            available_foreign_chains: Default::default(),
            available_foreign_chains_by_node: IterableMap::new(
                StorageKey::AvailableForeignChainsByNode,
            ),
            tls_key_by_account: LookupMap::new(StorageKey::TlsKeyByAccount),
        }
    }
}

impl ForeignChainAvailability {
    /// Registers `chains` for the given account, keyed by `tls_key`. If the account previously
    /// registered with a different TLS key, the stale entry is removed first.
    pub(crate) fn register(
        &mut self,
        account_id: dtos::AccountId,
        tls_key: dtos::Ed25519PublicKey,
        chains: dtos::AvailableForeignChains,
    ) {
        if let Some(old_key) = self.tls_key_by_account.get(&account_id) {
            if *old_key != tls_key {
                let old_key = old_key.clone();
                self.available_foreign_chains_by_node.remove(&old_key);
            }
        }
        self.tls_key_by_account.insert(account_id, tls_key.clone());
        self.available_foreign_chains_by_node
            .insert(tls_key, chains);
    }

    pub(crate) fn snapshot_by_node(
        &self,
    ) -> BTreeMap<dtos::Ed25519PublicKey, dtos::AvailableForeignChains> {
        self.available_foreign_chains_by_node
            .iter()
            .map(|(id, chains)| (id.clone(), chains.clone()))
            .collect()
    }
}
