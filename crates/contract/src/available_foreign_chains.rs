use std::collections::BTreeMap;

use near_mpc_contract_interface::types as dtos;
use near_sdk::near;
use near_sdk::store::IterableMap;

use crate::storage_keys::StorageKey;

/// Combined lazy state for foreign-chain availability: the cached available set and the
/// per-node coverage map that feeds it. Stored behind a `Lazy` in `MpcContract` so it is
/// only deserialized when methods that touch foreign-chain data are called.
#[near(serializers=[borsh])]
#[derive(Debug)]
pub(crate) struct ForeignChainAvailability {
    pub(crate) available_foreign_chains: dtos::AvailableForeignChains,
    pub(crate) available_foreign_chains_by_node:
        IterableMap<dtos::AccountId, dtos::AvailableForeignChains>,
}

impl Default for ForeignChainAvailability {
    fn default() -> Self {
        Self {
            available_foreign_chains: Default::default(),
            available_foreign_chains_by_node: IterableMap::new(
                StorageKey::AvailableForeignChainsByNode,
            ),
        }
    }
}

impl ForeignChainAvailability {
    pub(crate) fn snapshot_by_node(
        &self,
    ) -> BTreeMap<dtos::AccountId, dtos::AvailableForeignChains> {
        self.available_foreign_chains_by_node
            .iter()
            .map(|(id, chains)| (id.clone(), chains.clone()))
            .collect()
    }
}
