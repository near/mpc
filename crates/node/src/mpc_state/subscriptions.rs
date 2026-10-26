use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use chain_gateway::errors::NearViewClientError;
use mpc_primitives::hash::LauncherDockerComposeHash;
use near_contract_transport::{HasPollInterval, Subscription, ViewContract};
use near_mpc_contract_interface::client::MpcContractHandle;
use near_mpc_contract_interface::types::{
    AllowedMpcDockerImageHash, AvailableForeignChains, ChainEntry, Ed25519PublicKey, ForeignChain,
    ForeignChainsConfigs, GetAttestationResponse, ProtocolContractState,
};

use crate::indexer::migrations::ContractMigrationInfo;

/// The contract views the node follows, one subscription each. Clones share the poller, so a
/// clone feeds a second consumer without a second stream of view calls.
#[derive(Clone)]
pub struct ChainSubscriptions<E> {
    pub protocol_state: Subscription<ProtocolContractState, E>,
    pub allowed_docker_images: Subscription<Vec<AllowedMpcDockerImageHash>, E>,
    pub allowed_launcher_compose_hashes: Subscription<Vec<LauncherDockerComposeHash>, E>,
    pub allowed_foreign_chain_providers: Subscription<BTreeMap<ForeignChain, ChainEntry>, E>,
    pub migration_info: Subscription<ContractMigrationInfo, E>,
    pub available_foreign_chains: Subscription<AvailableForeignChains, E>,
    pub foreign_chains_configs: Subscription<ForeignChainsConfigs, E>,
    pub my_attestation: Subscription<Option<GetAttestationResponse>, E>,
}

impl<E> ChainSubscriptions<E> {
    pub async fn subscribe<V>(
        contract: &MpcContractHandle<V>,
        my_tls_public_key: Ed25519PublicKey,
    ) -> Self
    where
        V: ViewContract<Error = E> + HasPollInterval + Clone + Send + Sync + 'static,
    {
        Self {
            protocol_state: contract.state().subscribe().await,
            allowed_docker_images: contract.allowed_docker_image_hashes().subscribe().await,
            allowed_launcher_compose_hashes: contract
                .allowed_launcher_compose_hashes()
                .subscribe()
                .await,
            allowed_foreign_chain_providers: contract
                .allowed_foreign_chain_providers()
                .subscribe()
                .await,
            migration_info: contract.migration_info().subscribe().await,
            available_foreign_chains: contract.get_available_foreign_chains().subscribe().await,
            foreign_chains_configs: contract.get_foreign_chains_configs().subscribe().await,
            my_attestation: contract
                .get_attestation(&my_tls_public_key)
                .subscribe()
                .await,
        }
    }
}

/// The node's subscriptions, set by the indexer once it has subscribed and read by the debug
/// pages. One cursor is shared, so the cached value is deserialized once per change.
pub type ChainSubscriptionsSlot = Arc<OnceLock<Mutex<ChainSubscriptions<NearViewClientError>>>>;
