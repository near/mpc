use crate::migration_service::types::MigrationInfo;

use self::stats::IndexerStats;
use handler::ChainBlockUpdate;
use mpc_contract::tee::{proposal::MpcDockerImageHash, tee_state::NodeId};
use near_indexer_primitives::types::AccountId;
use participants::ContractState;
use std::sync::Arc;
use tokio::sync::{
    Mutex, {mpsc, watch},
};
use types::ChainSendTransactionRequest;

pub mod balances;
pub mod configs;
pub mod handler;
pub mod lib;
pub mod migrations;
pub mod participants;
pub mod real;
pub mod stats;
pub mod tee;
pub mod tx_sender;
pub mod tx_signer;
pub mod types;

#[cfg(test)]
pub mod fake;

#[derive(Debug)]
pub(crate) struct IndexerState {
    /// For querying blockchain state.
    view_client: actix::Addr<near_client::ViewClientActor>,
    /// For querying blockchain sync status.
    client: actix::Addr<near_client::ClientActor>,
    /// For sending txs to the chain.
    tx_processor: actix::Addr<near_client::RpcHandlerActor>,
    /// AccountId for the mpc contract.
    mpc_contract_id: AccountId,
    /// Stores runtime indexing statistics.
    stats: Arc<Mutex<IndexerStats>>,
}

impl IndexerState {
    pub fn new(
        view_client: actix::Addr<near_client::ViewClientActor>,
        client: actix::Addr<near_client::ClientActor>,
        tx_processor: actix::Addr<near_client::RpcHandlerActor>,
        mpc_contract_id: AccountId,
    ) -> Self {
        Self {
            view_client,
            client,
            tx_processor,
            mpc_contract_id,
            stats: Arc::new(Mutex::new(IndexerStats::new())),
        }
    }
}

/// API to interact with the indexer. Can be replaced by a dummy implementation.
/// The MPC node implementation needs this and only this to be able to interact
/// with the indexer.
/// TODO(#155): This would be the interface to abstract away having an indexer
/// running in a separate process.
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
    /// Watcher that keeps track of allowed [`AllowedDockerImageHash`]es on the contract.
    pub allowed_docker_images_receiver: watch::Receiver<Vec<MpcDockerImageHash>>,
    /// Watcher that tracks node IDs that have TEE attestations in the contract.
    pub attested_nodes_receiver: watch::Receiver<Vec<NodeId>>,

    #[allow(dead_code)] // todo: [#1249](https://github.com/near/mpc/issues/1249): remove `allow`
    pub my_migration_info_receiver: watch::Receiver<MigrationInfo>,
}
