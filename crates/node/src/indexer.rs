use crate::migration_service::types::MigrationInfo;
use chain_gateway::chain_gateway::ChainGateway;
use contract_interface::types as dtos;
use contract_state_viewer::MpcContractStateViewer;
use handler::ChainBlockUpdate;
use mpc_contract::tee::{
    proposal::{LauncherDockerComposeHash, MpcDockerImageHash},
    tee_state::NodeId,
};
use near_account_id::AccountId;
use participants::ContractState;
use std::{future::Future, sync::Arc};
use tokio::sync::{mpsc, watch};
use types::ChainSendTransactionRequest;

pub mod configs;
pub(crate) mod contract_state_viewer;
pub mod handler;
pub mod migrations;
pub mod participants;
pub mod real;
pub mod tee;
pub mod tx_sender;
pub mod tx_signer;
pub mod types;

#[cfg(test)]
pub mod fake;

pub(crate) struct IndexerState {
    /// Chain indexer to interact with the NEAR blockchain
    chain_gateway: ChainGateway,
    /// AccountId for the mpc contract.
    mpc_contract_id: AccountId,
}

impl IndexerState {
    pub fn new(chain_gateway: ChainGateway, mpc_contract_id: AccountId) -> Self {
        Self {
            chain_gateway,
            mpc_contract_id,
        }
    }
}

#[cfg_attr(test, mockall::automock)]
pub(crate) trait ReadForeignChainPolicy: Send + Sync {
    fn get_foreign_chain_policy(
        &self,
    ) -> impl Future<Output = anyhow::Result<dtos::ForeignChainPolicy>> + Send;
    fn get_foreign_chain_policy_proposals(
        &self,
    ) -> impl Future<Output = anyhow::Result<dtos::ForeignChainPolicyVotes>> + Send;
}

#[derive(Clone)]
pub(crate) struct RealForeignChainPolicyReader {
    contract_state_viewer: MpcContractStateViewer,
}

impl RealForeignChainPolicyReader {
    pub(crate) fn new(contract_state_viewer: MpcContractStateViewer) -> Self {
        Self {
            contract_state_viewer,
        }
    }
}

impl ReadForeignChainPolicy for RealForeignChainPolicyReader {
    async fn get_foreign_chain_policy(&self) -> anyhow::Result<dtos::ForeignChainPolicy> {
        self.contract_state_viewer.get_foreign_chain_policy().await
    }

    async fn get_foreign_chain_policy_proposals(
        &self,
    ) -> anyhow::Result<dtos::ForeignChainPolicyVotes> {
        self.contract_state_viewer
            .get_foreign_chain_policy_proposals()
            .await
    }
}

/// API to interact with the indexer. Can be replaced by a dummy implementation.
/// The MPC node implementation needs this and only this to be able to interact
/// with the indexer.
/// TODO(#155): This would be the interface to abstract away having an indexer
/// running in a separate process.
pub struct IndexerAPI<TransactionSender, ForeignChainPolicyReader> {
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
    /// Watcher that keeps track of allowed [`DockerImageHash`]es on the contract.
    pub allowed_docker_images_receiver: watch::Receiver<Vec<MpcDockerImageHash>>,
    /// Watcher that keeps track of allowed [`LauncherDockerComposeHash`]es on the contract.
    pub allowed_launcher_compose_receiver: watch::Receiver<Vec<LauncherDockerComposeHash>>,
    /// Watcher that tracks node IDs that have TEE attestations in the contract.
    pub attested_nodes_receiver: watch::Receiver<Vec<NodeId>>,

    pub my_migration_info_receiver: watch::Receiver<MigrationInfo>,

    pub foreign_chain_policy_reader: ForeignChainPolicyReader,
}
