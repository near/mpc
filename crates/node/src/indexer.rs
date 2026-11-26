use crate::migration_service::types::MigrationInfo;

use self::stats::IndexerStats;
use anyhow::Context;
use chain_gateway::ChainGateway;
use handler::ChainBlockUpdate;
use mpc_primitives::hash::LauncherDockerComposeHash;
use near_account_id::AccountId;
use near_indexer::near_primitives::hash::CryptoHash;
use near_mpc_contract_interface::client::MpcContractHandle;
use near_mpc_contract_interface::types as dtos;
use participants::ContractState;
use std::sync::Arc;
use tokio::sync::{
    Mutex, {mpsc, watch},
};
use types::ChainSendTransactionRequest;

pub mod chain_binding;
pub mod configs;
pub mod foreign_chain;
pub mod handler;
pub mod migrations;
pub mod near_data_wipe;
pub mod participants;
pub mod real;
pub mod stats;
pub mod tee;
pub mod tx_sender;
pub mod types;

#[cfg(test)]
pub mod fake;

pub(crate) struct IndexerState {
    contract: MpcContractHandle<ChainGateway>,
    gateway: ChainGateway,
    /// AccountId for the mpc contract.
    mpc_contract_id: AccountId,
    /// Stores runtime indexing statistics.
    stats: Arc<Mutex<IndexerStats>>,
}

impl IndexerState {
    pub fn new(gateway: ChainGateway, mpc_contract_id: AccountId) -> Self {
        Self {
            contract: MpcContractHandle::new(gateway.clone(), mpc_contract_id.clone()),
            gateway,
            mpc_contract_id,
            stats: Arc::new(Mutex::new(IndexerStats::new())),
        }
    }

    async fn ensure_chain_matches_contract(
        &self,
        expected_genesis_hash: Option<CryptoHash>,
    ) -> anyhow::Result<()> {
        let genesis_hash = self
            .gateway
            .genesis_hash()
            .await
            .context("querying the genesis hash")?;
        chain_binding::ensure_chain_matches_contract(expected_genesis_hash, genesis_hash)
    }
}

/// API to interact with the indexer. Can be replaced by a dummy implementation.
/// The MPC node implementation needs this and only this to be able to interact
/// with the indexer.
/// TODO(#592): abstract away having an indexer running in a separate process
pub struct IndexerAPI<TransactionSender> {
    /// Provides the current contract state as well as updates to it.
    pub contract_state_receiver: watch::Receiver<ContractState>,
    /// Provides block updates (signature requests and other relevant receipts).
    /// It is in a mutex, because the logical "owner" of this receiver can
    /// change over time (specifically, when we transition from the Running
    /// state to a Resharing state to the Running state again, two different
    /// tasks would successively "own" the receiver).
    /// We do not want to re-create the channel, because while resharing is
    /// happening we want to buffer the signature requests.
    pub block_update_receiver: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<ChainBlockUpdate>>>,
    /// Handle to transaction processor.
    pub txn_sender: TransactionSender,
    /// Watcher that keeps track of [`dtos::AllowedMpcDockerImageHash`]es on the contract
    pub allowed_docker_images_receiver: watch::Receiver<Vec<dtos::AllowedMpcDockerImageHash>>,
    /// Watcher that keeps track of allowed [`LauncherDockerComposeHash`]es on the contract.
    pub allowed_launcher_compose_receiver: watch::Receiver<Vec<LauncherDockerComposeHash>>,
    /// Watcher that keeps track of the allowed OS [`dtos::ExpectedMeasurements`] on the contract.
    pub allowed_os_measurements_receiver: watch::Receiver<Vec<dtos::ExpectedMeasurements>>,

    pub my_migration_info_receiver: watch::Receiver<MigrationInfo>,

    pub my_attestation_receiver: watch::Receiver<Option<dtos::StoredAttestation>>,

    /// Watcher that tracks the contract's available foreign chains and their
    /// registered supporters (by TLS key). Seeded with the first successful read
    /// before the indexer hands it back, so it always holds a real value.
    pub foreign_chain_supporters_receiver: watch::Receiver<foreign_chain::ForeignChainSupporters>,
    /// The contract's RPC provider whitelist, seeded with the first successful read.
    pub foreign_chain_whitelist_receiver: watch::Receiver<foreign_chain::ForeignChainWhitelist>,
    /// The foreign chains each node registered, keyed by TLS key, seeded with the first successful read.
    pub foreign_chains_configs_receiver: watch::Receiver<dtos::ForeignChainsConfigs>,
}
