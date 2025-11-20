use crate::{indexer::migrations::ContractMigrationInfo, migration_service::types::MigrationInfo};

use self::stats::IndexerStats;
use handler::ChainBlockUpdate;
use mpc_contract::{
    state::ProtocolContractState,
    tee::{
        proposal::{LauncherDockerComposeHash, MpcDockerImageHash},
        tee_state::NodeId,
    },
};
use near_account_id::AccountId;
use near_async::{
    messaging::CanSendAsync, multithread::MultithreadRuntimeHandle, tokio::TokioRuntimeHandle,
};
use near_client::{client_actor::ClientActorInner, RpcHandler, Status, ViewClientActorInner};
use near_indexer_primitives::{
    types::{BlockReference, Finality},
    views::{QueryRequest, QueryResponseKind},
};
use near_o11y::span_wrapped_msg::SpanWrappedMessageExt;
use participants::ContractState;
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use tokio::sync::{
    Mutex, {mpsc, watch},
};
use types::ChainSendTransactionRequest;
use utilities::AccountIdExtV1;

pub mod configs;
pub mod handler;
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

//TODO: The new types don't implement Debug
// #[derive(Debug)]
pub(crate) struct IndexerState {
    /// For querying blockchain state.
    view_client: IndexerViewClient,
    /// For querying blockchain sync status.
    client: IndexerClient,
    /// For sending txs to the chain.
    tx_processor: IndexerTxProcessor,
    /// AccountId for the mpc contract.
    mpc_contract_id: AccountId,
    /// Stores runtime indexing statistics.
    stats: Arc<Mutex<IndexerStats>>,
}

impl IndexerState {
    pub fn new(
        view_client: IndexerViewClient,
        client: IndexerClient,
        tx_processor: IndexerTxProcessor,
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

#[derive(Clone)]
struct IndexerViewClient {
    view_client: MultithreadRuntimeHandle<ViewClientActorInner>,
}

// TODO: during refactor I noticed the account id is always taken from the indexer state as well.
// We should remove this account_id parameter...
//
// example:
// indexer_state.view_client.get_mpc_tee_accounts(indexer_state.mpc_contract_id.clone()).await
// =>
// indexer_state.view_client.get_mpc_tee_accounts().await
// This pattern repeats for all the methods.
impl IndexerViewClient {
    pub(crate) async fn get_mpc_contract_state(
        &self,
        mpc_contract_id: AccountId,
    ) -> anyhow::Result<(u64, ProtocolContractState)> {
        self.get_mpc_state(mpc_contract_id, CONTRACT_STATE_ENDPOINT)
            .await
    }

    pub(crate) async fn get_mpc_allowed_image_hashes(
        &self,
        mpc_contract_id: AccountId,
    ) -> anyhow::Result<(u64, Vec<MpcDockerImageHash>)> {
        self.get_mpc_state(mpc_contract_id, ALLOWED_IMAGE_HASHES_ENDPOINT)
            .await
    }
    pub(crate) async fn get_mpc_allowed_launcher_compose_hashes(
        &self,
        mpc_contract_id: AccountId,
    ) -> anyhow::Result<(u64, Vec<LauncherDockerComposeHash>)> {
        self.get_mpc_state(mpc_contract_id, ALLOWED_LAUNCHER_COMPOSE_HASHES_ENDPOINT)
            .await
    }

    pub(crate) async fn get_mpc_tee_accounts(
        &self,
        mpc_contract_id: AccountId,
    ) -> anyhow::Result<(u64, Vec<NodeId>)> {
        self.get_mpc_state(mpc_contract_id, TEE_ACCOUNTS_ENDPOINT)
            .await
    }

    pub(crate) async fn get_mpc_migration_info(
        &self,
        mpc_contract_id: AccountId,
    ) -> anyhow::Result<(u64, ContractMigrationInfo)> {
        self.get_mpc_state(mpc_contract_id, MIGRATION_INFO_ENDPOINT)
            .await
    }

    async fn get_mpc_state<State>(
        &self,
        mpc_contract_id: AccountId,
        endpoint: &str,
    ) -> anyhow::Result<(u64, State)>
    where
        State: for<'de> Deserialize<'de>,
    {
        let request = QueryRequest::CallFunction {
            account_id: mpc_contract_id.as_v2_account_id(),
            method_name: endpoint.to_string(),
            args: vec![].into(),
        };

        let query = near_client::Query {
            block_reference: BlockReference::Finality(Finality::Final),
            request,
        };

        let response = self.view_client.send_async(query).await??;

        match response.kind {
            QueryResponseKind::CallResult(result) => Ok((
                response.block_height,
                serde_json::from_slice(&result.result)?,
            )),
            _ => {
                anyhow::bail!("got unexpected response querying mpc contract state")
            }
        }
    }
}

#[derive(Clone)]
struct IndexerClient {
    client: TokioRuntimeHandle<ClientActorInner>,
}

const INTERVAL: Duration = Duration::from_millis(500);
const ALLOWED_IMAGE_HASHES_ENDPOINT: &str = "allowed_docker_image_hashes";
const ALLOWED_LAUNCHER_COMPOSE_HASHES_ENDPOINT: &str = "allowed_launcher_compose_hashes";
const TEE_ACCOUNTS_ENDPOINT: &str = "get_tee_accounts";
pub const MIGRATION_INFO_ENDPOINT: &str = "migration_info";
const CONTRACT_STATE_ENDPOINT: &str = "state";

impl IndexerClient {
    async fn wait_for_full_sync(&self) {
        loop {
            tokio::time::sleep(INTERVAL).await;

            let status_request = Status {
                is_health_check: false,
                detailed: false,
            };

            let status_response = self.client.send_async(status_request.span_wrap()).await;

            let Ok(Ok(status)) = status_response else {
                continue;
            };

            if !status.sync_info.syncing {
                return;
            }
        }
    }
}

// #[derive(Debug)]
struct IndexerTxProcessor {
    rpc_handler: MultithreadRuntimeHandle<RpcHandler>,
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
    /// Watcher that keeps track of allowed [`DockerImageHash`]es on the contract.
    pub allowed_docker_images_receiver: watch::Receiver<Vec<MpcDockerImageHash>>,
    /// Watcher that keeps track of allowed [`LauncherDockerComposeHash`]es on the contract.
    pub allowed_launcher_compose_receiver: watch::Receiver<Vec<LauncherDockerComposeHash>>,
    /// Watcher that tracks node IDs that have TEE attestations in the contract.
    pub attested_nodes_receiver: watch::Receiver<Vec<NodeId>>,

    pub my_migration_info_receiver: watch::Receiver<MigrationInfo>,
}
