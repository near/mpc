use crate::{
    indexer::{
        migrations::ContractMigrationInfo,
        types::{
            ChainCKDRequest, ChainGetPendingCKDRequestArgs, ChainGetPendingSignatureRequestArgs,
            ChainGetPendingVerifyForeignTxRequestArgs, ChainSignatureRequest,
            ChainVerifyForeignTransactionRequest, GetAttestationArgs,
        },
    },
    migration_service::types::MigrationInfo,
};

use self::stats::IndexerStats;
use anyhow::Context;
use handler::ChainBlockUpdate;
use mpc_primitives::hash::{LauncherDockerComposeHash, NodeImageHash};
use near_account_id::AccountId;
use near_async::{
    messaging::CanSendAsync, multithread::MultithreadRuntimeHandle, tokio::TokioRuntimeHandle,
};
use near_client::{RpcHandlerActor, Status, ViewClientActor, client_actor::ClientActor};
use near_indexer::near_primitives::transaction::SignedTransaction;
use near_indexer_primitives::{
    types::{BlockHeight, BlockReference, Finality},
    views::{BlockView, QueryRequest, QueryResponseKind},
};
use near_mpc_contract_interface::method_names::{
    ALLOWED_DOCKER_IMAGE_HASHES, ALLOWED_FOREIGN_CHAIN_PROVIDERS, ALLOWED_LAUNCHER_COMPOSE_HASHES,
    GET_ATTESTATION, GET_PENDING_CKD_REQUEST, GET_PENDING_REQUEST,
    GET_PENDING_VERIFY_FOREIGN_TX_REQUEST, GET_SUPPORTED_FOREIGN_CHAINS, GET_TEE_ACCOUNTS,
    MIGRATION_INFO, STATE,
};
use near_mpc_contract_interface::types::{self as dtos, YieldIndex};
use participants::ContractState;
use serde::Deserialize;
use std::{future::Future, sync::Arc, time::Duration};
use tokio::sync::{
    Mutex, {mpsc, watch},
};
use types::ChainSendTransactionRequest;

pub mod configs;
pub mod handler;
pub mod migrations;
pub mod near_data_wipe;
pub mod participants;
pub mod real;
pub mod stats;
pub mod tee;
pub mod tx_sender;
pub mod tx_signer;
pub mod types;

#[cfg(test)]
pub mod fake;

pub(crate) struct IndexerState {
    /// For querying blockchain state.
    view_client: IndexerViewClient,
    /// For querying blockchain sync status.
    client: IndexerClient,
    /// For sending txs to the chain.
    rpc_handler: IndexerRpcHandler,
    /// AccountId for the mpc contract.
    mpc_contract_id: AccountId,
    /// Stores runtime indexing statistics.
    stats: Arc<Mutex<IndexerStats>>,
}

impl IndexerState {
    pub fn new(
        view_client: MultithreadRuntimeHandle<ViewClientActor>,
        client: TokioRuntimeHandle<ClientActor>,
        rpc_handler: MultithreadRuntimeHandle<RpcHandlerActor>,
        mpc_contract_id: AccountId,
    ) -> Self {
        Self {
            view_client: IndexerViewClient { view_client },
            client: IndexerClient { client },
            rpc_handler: IndexerRpcHandler { rpc_handler },
            mpc_contract_id,
            stats: Arc::new(Mutex::new(IndexerStats::new())),
        }
    }
}

#[derive(Clone)]
pub(crate) struct IndexerViewClient {
    view_client: MultithreadRuntimeHandle<ViewClientActor>,
}

// TODO(#1514): during refactor I noticed the account id is always taken from the indexer state as well.
// We should remove this account_id parameter...
//
// example:
// indexer_state.view_client.get_mpc_tee_accounts(indexer_state.mpc_contract_id.clone()).await
// =>
// indexer_state.view_client.get_mpc_tee_accounts().await
// This pattern repeats for all the methods.
// TODO(#1956): There is a lot of duplicate code here that could be simplified
impl IndexerViewClient {
    pub(crate) async fn get_pending_request(
        &self,
        mpc_contract_id: &AccountId,
        chain_signature_request: &ChainSignatureRequest,
    ) -> anyhow::Result<Option<YieldIndex>> {
        let get_pending_request_args: Vec<u8> =
            serde_json::to_string(&ChainGetPendingSignatureRequestArgs {
                request: chain_signature_request.clone(),
            })
            .unwrap()
            .into_bytes();

        let request = QueryRequest::CallFunction {
            account_id: mpc_contract_id.clone(),
            method_name: GET_PENDING_REQUEST.to_string(),
            args: get_pending_request_args.into(),
        };
        let block_reference = BlockReference::Finality(Finality::Final);

        let query = near_client::Query {
            block_reference,
            request,
        };

        let query_response = self
            .view_client
            .send_async(query)
            .await
            .context("failed to query for pending request")??;

        match query_response.kind {
            QueryResponseKind::CallResult(call_result) => {
                serde_json::from_slice::<Option<YieldIndex>>(&call_result.result)
                    .context("failed to deserialize pending request response")
            }
            _ => {
                anyhow::bail!("Unexpected result from a view client function call");
            }
        }
    }

    pub(crate) async fn get_pending_ckd_request(
        &self,
        mpc_contract_id: &AccountId,
        chain_ckd_request: &ChainCKDRequest,
    ) -> anyhow::Result<Option<YieldIndex>> {
        let get_pending_request_args: Vec<u8> =
            serde_json::to_string(&ChainGetPendingCKDRequestArgs {
                request: chain_ckd_request.clone(),
            })
            .unwrap()
            .into_bytes();

        let request = QueryRequest::CallFunction {
            account_id: mpc_contract_id.clone(),
            method_name: GET_PENDING_CKD_REQUEST.to_string(),
            args: get_pending_request_args.into(),
        };
        let block_reference = BlockReference::Finality(Finality::Final);

        let query = near_client::Query {
            block_reference,
            request,
        };

        let query_response = self
            .view_client
            .send_async(query)
            .await
            .context("failed to query for pending CKD request")??;

        match query_response.kind {
            QueryResponseKind::CallResult(call_result) => {
                serde_json::from_slice::<Option<YieldIndex>>(&call_result.result)
                    .context("failed to deserialize pending CKD request response")
            }
            _ => {
                anyhow::bail!("Unexpected result from a view client function call");
            }
        }
    }

    pub(crate) async fn get_pending_verify_foreign_tx_request(
        &self,
        mpc_contract_id: &AccountId,
        chain_verify_foreign_tx_request: &ChainVerifyForeignTransactionRequest,
    ) -> anyhow::Result<Option<YieldIndex>> {
        let get_pending_request_args: Vec<u8> =
            serde_json::to_string(&ChainGetPendingVerifyForeignTxRequestArgs {
                request: chain_verify_foreign_tx_request.clone(),
            })
            .unwrap()
            .into_bytes();

        let request = QueryRequest::CallFunction {
            account_id: mpc_contract_id.clone(),
            method_name: GET_PENDING_VERIFY_FOREIGN_TX_REQUEST.to_string(),
            args: get_pending_request_args.into(),
        };
        let block_reference = BlockReference::Finality(Finality::Final);

        let query = near_client::Query {
            block_reference,
            request,
        };

        let query_response = self
            .view_client
            .send_async(query)
            .await
            .context("failed to query for pending verify foreign tx request")??;

        match query_response.kind {
            QueryResponseKind::CallResult(call_result) => {
                serde_json::from_slice::<Option<YieldIndex>>(&call_result.result)
                    .context("failed to deserialize pending verify foreign tx request response")
            }
            _ => {
                anyhow::bail!("Unexpected result from a view client function call");
            }
        }
    }

    pub(crate) async fn get_participant_attestation(
        &self,
        mpc_contract_id: &AccountId,
        participant_tls_public_key: &near_mpc_contract_interface::types::Ed25519PublicKey,
    ) -> anyhow::Result<Option<near_mpc_contract_interface::types::VerifiedAttestation>> {
        let get_attestation_args: Vec<u8> = serde_json::to_string(&GetAttestationArgs {
            tls_public_key: participant_tls_public_key,
        })
        .unwrap()
        .into_bytes();

        let request = QueryRequest::CallFunction {
            account_id: mpc_contract_id.clone(),
            method_name: GET_ATTESTATION.to_string(),
            args: get_attestation_args.into(),
        };
        let block_reference = BlockReference::Finality(Finality::Final);

        let query = near_client::Query {
            block_reference,
            request,
        };

        let query_response = self
            .view_client
            .send_async(query)
            .await
            .context("failed to query for pending request")??;

        match query_response.kind {
            QueryResponseKind::CallResult(call_result) => serde_json::from_slice::<
                Option<near_mpc_contract_interface::types::VerifiedAttestation>,
            >(&call_result.result)
            .context("failed to deserialize pending request response"),
            _ => {
                anyhow::bail!("Unexpected result from a view client function call");
            }
        }
    }

    pub(crate) async fn get_supported_chains(
        &self,
        mpc_contract_id: &AccountId,
    ) -> anyhow::Result<dtos::SupportedForeignChains> {
        let (_height, policy) = self
            .get_mpc_state(mpc_contract_id.clone(), GET_SUPPORTED_FOREIGN_CHAINS)
            .await?;
        Ok(policy)
    }

    /// Borsh-decoding view-fn query (`get_mpc_state` is JSON-only).
    pub(crate) async fn get_allowed_foreign_chain_providers(
        &self,
        mpc_contract_id: AccountId,
    ) -> anyhow::Result<std::collections::BTreeMap<dtos::ForeignChain, dtos::ChainEntry>> {
        let request = QueryRequest::CallFunction {
            account_id: mpc_contract_id,
            method_name: ALLOWED_FOREIGN_CHAIN_PROVIDERS.to_string(),
            args: vec![].into(),
        };
        let query = near_client::Query {
            block_reference: BlockReference::Finality(Finality::Final),
            request,
        };

        let response = self.view_client.send_async(query).await??;

        match response.kind {
            QueryResponseKind::CallResult(result) => borsh::from_slice::<
                std::collections::BTreeMap<dtos::ForeignChain, dtos::ChainEntry>,
            >(&result.result)
            .with_context(|| {
                let preview: String = result
                    .result
                    .iter()
                    .take(32)
                    .map(|b| format!("{b:02x}"))
                    .collect();
                format!(
                    "failed to borsh-decode allowed_foreign_chain_providers response (len={}, first {} bytes hex: {preview})",
                    result.result.len(),
                    result.result.len().min(32),
                )
            }),
            _ => anyhow::bail!("got unexpected response querying allowed_foreign_chain_providers"),
        }
    }

    pub(crate) async fn latest_final_block(&self) -> anyhow::Result<BlockView> {
        let block_query = near_client::GetBlock(BlockReference::Finality(Finality::Final));
        self.view_client
            .send_async(block_query)
            .await?
            .context("failed to get query for final block")
    }

    pub(crate) async fn get_mpc_contract_state_dto(
        &self,
        mpc_contract_id: AccountId,
    ) -> anyhow::Result<(u64, dtos::ProtocolContractState)> {
        self.get_mpc_state(mpc_contract_id, STATE).await
    }

    pub(crate) async fn get_mpc_allowed_image_hashes(
        &self,
        mpc_contract_id: AccountId,
    ) -> anyhow::Result<(u64, Vec<NodeImageHash>)> {
        self.get_mpc_state(mpc_contract_id, ALLOWED_DOCKER_IMAGE_HASHES)
            .await
    }
    pub(crate) async fn get_mpc_allowed_launcher_compose_hashes(
        &self,
        mpc_contract_id: AccountId,
    ) -> anyhow::Result<(u64, Vec<LauncherDockerComposeHash>)> {
        self.get_mpc_state(mpc_contract_id, ALLOWED_LAUNCHER_COMPOSE_HASHES)
            .await
    }

    pub(crate) async fn get_mpc_tee_accounts(
        &self,
        mpc_contract_id: AccountId,
    ) -> anyhow::Result<(u64, Vec<dtos::NodeId>)> {
        self.get_mpc_state(mpc_contract_id, GET_TEE_ACCOUNTS).await
    }

    pub(crate) async fn get_mpc_migration_info(
        &self,
        mpc_contract_id: AccountId,
    ) -> anyhow::Result<(u64, ContractMigrationInfo)> {
        self.get_mpc_state(mpc_contract_id, MIGRATION_INFO).await
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
            account_id: mpc_contract_id,
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

#[cfg_attr(test, mockall::automock)]
pub(crate) trait ReadSupportedForeignChain: Send + Sync {
    fn get_supported_chains(
        &self,
    ) -> impl Future<Output = anyhow::Result<dtos::SupportedForeignChains>> + Send;
}

#[derive(Clone)]
pub(crate) struct RealForeignChainPolicyReader {
    indexer_state: Arc<IndexerState>,
}

impl RealForeignChainPolicyReader {
    pub(crate) fn new(indexer_state: Arc<IndexerState>) -> Self {
        Self { indexer_state }
    }
}

impl ReadSupportedForeignChain for RealForeignChainPolicyReader {
    async fn get_supported_chains(&self) -> anyhow::Result<dtos::SupportedForeignChains> {
        self.indexer_state
            .view_client
            .get_supported_chains(&self.indexer_state.mpc_contract_id)
            .await
    }
}

#[derive(Clone)]
struct IndexerClient {
    client: TokioRuntimeHandle<ClientActor>,
}

const INTERVAL: Duration = Duration::from_millis(500);

/// Max blocks the local head may trail the highest peer and still count as caught up.
const SYNC_HEIGHT_TOLERANCE: BlockHeight = 5;

impl IndexerClient {
    async fn wait_for_full_sync(&self) {
        loop {
            tokio::time::sleep(INTERVAL).await;

            // `detailed: true` so the response carries connected-peer heights,
            // which we use to confirm the head has actually caught up.
            let status_request = Status {
                is_health_check: false,
                detailed: true,
            };
            let status_response = self
                .client
                .send_async(
                    near_o11y::span_wrapped_msg::SpanWrappedMessageExt::span_wrap(status_request),
                )
                .await;

            let Ok(Ok(status)) = status_response else {
                continue;
            };

            let max_peer_height = status.detailed_debug_status.as_ref().and_then(|detailed| {
                detailed
                    .network_info
                    .connected_peers
                    .iter()
                    .filter_map(|peer| peer.height)
                    .max()
            });

            if head_caught_up_to_peers(
                status.sync_info.syncing,
                status.sync_info.latest_block_height,
                max_peer_height,
            ) {
                return;
            }
        }
    }
}

/// Whether the node has caught up to the network head.
///
/// `syncing` alone is insufficient: a freshly state-syncing node reports it
/// `false` at boot before learning it is behind, which would pin the streamer's
/// `LatestSynced` cursor at a stale head. So we also require the head within
/// [`SYNC_HEIGHT_TOLERANCE`] of the highest peer, and wait while no peer height
/// is known.
fn head_caught_up_to_peers(
    syncing: bool,
    head_height: BlockHeight,
    max_peer_height: Option<BlockHeight>,
) -> bool {
    if syncing {
        return false;
    }
    match max_peer_height {
        None => false,
        Some(peer_height) => peer_height.saturating_sub(head_height) <= SYNC_HEIGHT_TOLERANCE,
    }
}

// #[derive(Debug)]
struct IndexerRpcHandler {
    rpc_handler: MultithreadRuntimeHandle<RpcHandlerActor>,
}

impl IndexerRpcHandler {
    /// Creates, signs, and submits a function call with the given method and serialized arguments.
    async fn submit_tx(&self, transaction: SignedTransaction) -> anyhow::Result<()> {
        let response = self
            .rpc_handler
            .send_async(near_client::ProcessTxRequest {
                transaction,
                is_forwarded: false,
                check_only: false,
            })
            .await?;

        match response {
            // We're not a validator, so we should always be routing the transaction.
            near_client::ProcessTxResponse::RequestRouted => Ok(()),
            _ => {
                anyhow::bail!("unexpected ProcessTxResponse: {:?}", response);
            }
        }
    }
}

/// API to interact with the indexer. Can be replaced by a dummy implementation.
/// The MPC node implementation needs this and only this to be able to interact
/// with the indexer.
/// TODO(#592): abstract away having an indexer running in a separate process
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
    pub allowed_docker_images_receiver: watch::Receiver<Vec<NodeImageHash>>,
    /// Watcher that keeps track of allowed [`LauncherDockerComposeHash`]es on the contract.
    pub allowed_launcher_compose_receiver: watch::Receiver<Vec<LauncherDockerComposeHash>>,
    /// Watcher that tracks node IDs that have TEE attestations in the contract.
    pub attested_nodes_receiver: watch::Receiver<Vec<dtos::NodeId>>,

    pub my_migration_info_receiver: watch::Receiver<MigrationInfo>,

    pub foreign_chain_policy_reader: ForeignChainPolicyReader,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{SYNC_HEIGHT_TOLERANCE, head_caught_up_to_peers};

    #[test]
    fn head_caught_up_to_peers__should_be_false_while_node_reports_syncing() {
        // Given
        let syncing = true;

        // When
        let caught_up = head_caught_up_to_peers(syncing, 257_000_000, Some(257_000_000));

        // Then
        assert!(!caught_up);
    }

    #[test]
    fn head_caught_up_to_peers__should_be_false_at_genesis_before_sync_starts() {
        // Given
        let syncing = false;
        let genesis_head = 42_376_888;
        let peer_head = 257_409_058;

        // When
        let caught_up = head_caught_up_to_peers(syncing, genesis_head, Some(peer_head));

        // Then
        assert!(!caught_up);
    }

    #[test]
    fn head_caught_up_to_peers__should_be_false_with_stale_head_far_above_genesis() {
        // Given
        let syncing = false;
        let stale_head = 200_000_000;
        let peer_head = 257_409_058;

        // When
        let caught_up = head_caught_up_to_peers(syncing, stale_head, Some(peer_head));

        // Then
        assert!(!caught_up);
    }

    #[test]
    fn head_caught_up_to_peers__should_be_false_when_no_peer_height_known() {
        // Given
        let syncing = false;

        // When
        let caught_up = head_caught_up_to_peers(syncing, 257_409_058, None);

        // Then
        assert!(!caught_up);
    }

    #[test]
    fn head_caught_up_to_peers__should_be_true_when_head_reaches_peer_height() {
        // Given
        let syncing = false;
        let peer_head = 257_409_058;

        // When
        let caught_up = head_caught_up_to_peers(syncing, peer_head, Some(peer_head));

        // Then
        assert!(caught_up);
    }

    #[test]
    fn head_caught_up_to_peers__should_be_true_within_tolerance_of_peer_height() {
        // Given
        let syncing = false;
        let peer_head = 257_409_058;
        let head = peer_head - SYNC_HEIGHT_TOLERANCE;

        // When
        let caught_up = head_caught_up_to_peers(syncing, head, Some(peer_head));

        // Then
        assert!(caught_up);
    }

    #[test]
    fn head_caught_up_to_peers__should_be_true_when_head_above_peer_height() {
        // Given
        let syncing = false;
        let peer_head = 257_409_058;

        // When
        let caught_up = head_caught_up_to_peers(syncing, peer_head + 10, Some(peer_head));

        // Then
        assert!(caught_up);
    }
}
