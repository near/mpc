use near_mpc_contract_interface::call_args as contract_args;

use crate::{indexer::migrations::ContractMigrationInfo, migration_service::types::MigrationInfo};

use self::stats::IndexerStats;
use anyhow::Context;
use base64::{Engine, engine::general_purpose::STANDARD};
use mpc_primitives::hash::LauncherDockerComposeHash;
use near_account_id::AccountId;
#[cfg(feature = "embedded-node")]
use near_async::{
    messaging::CanSendAsync, multithread::MultithreadRuntimeHandle, tokio::TokioRuntimeHandle,
};
#[cfg(feature = "embedded-node")]
use near_client::{RpcHandlerActor, Status, ViewClientActor, client_actor::ClientActor};
use near_indexer_primitives::near_primitives::transaction::SignedTransaction;
use near_indexer_primitives::{
    types::{BlockHeight, BlockReference, Finality},
    views::{BlockView, QueryRequest, QueryResponse, QueryResponseKind},
};
use near_jsonrpc_node::types::query::RpcQueryRequest;
use near_kit::rpc::RpcClient;
use near_mpc_contract_interface::method_names::{
    ALLOWED_DOCKER_IMAGE_HASHES, ALLOWED_FOREIGN_CHAIN_PROVIDERS, ALLOWED_LAUNCHER_COMPOSE_HASHES,
    GET_ATTESTATION, GET_AVAILABLE_FOREIGN_CHAINS, GET_FOREIGN_CHAINS_CONFIGS,
    GET_PENDING_CKD_REQUEST, GET_PENDING_REQUEST, GET_PENDING_VERIFY_FOREIGN_TX_REQUEST,
    MIGRATION_INFO, STATE,
};
use near_mpc_contract_interface::types::{self as dtos, YieldIndex};
use participants::ContractState;
use serde::Deserialize;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::sync::{Mutex, watch};
use types::ChainSendTransactionRequest;
use updates::BlockUpdateReceiver;

#[cfg(feature = "embedded-node")]
pub mod configs;
pub mod foreign_chain;
pub mod handler;
pub mod http;
pub mod migrations;
#[cfg(feature = "embedded-node")]
pub mod near_data_wipe;
pub mod participants;
pub mod real;
pub mod stats;
pub mod tee;
pub mod tx_sender;
pub mod tx_signer;
pub mod types;
pub mod updates;

#[cfg(test)]
pub mod fake;

type AllowedDockerImageHashesResponse = Vec<dtos::AllowedMpcDockerImageHash>;

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
    #[cfg(feature = "embedded-node")]
    pub fn new(
        view_client: MultithreadRuntimeHandle<ViewClientActor>,
        client: TokioRuntimeHandle<ClientActor>,
        rpc_handler: MultithreadRuntimeHandle<RpcHandlerActor>,
        mpc_contract_id: AccountId,
    ) -> Self {
        Self {
            view_client: IndexerViewClient::Embedded(view_client),
            client: IndexerClient::Embedded(client),
            rpc_handler: IndexerRpcHandler::Embedded(rpc_handler),
            mpc_contract_id,
            stats: Arc::new(Mutex::new(IndexerStats::new())),
        }
    }

    fn from_http(url: &str, mpc_contract_id: AccountId) -> Self {
        let rpc = Arc::new(RpcClient::new(url));
        Self {
            view_client: IndexerViewClient::Http(Arc::clone(&rpc)),
            client: IndexerClient::Http(Arc::clone(&rpc)),
            rpc_handler: IndexerRpcHandler::Http(rpc),
            mpc_contract_id,
            stats: Arc::new(Mutex::new(IndexerStats::new())),
        }
    }
}

#[derive(Clone)]
pub(crate) enum IndexerViewClient {
    #[cfg(feature = "embedded-node")]
    Embedded(MultithreadRuntimeHandle<ViewClientActor>),
    Http(Arc<RpcClient>),
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
    async fn query(&self, query: RpcQueryRequest) -> anyhow::Result<QueryResponse> {
        match self {
            #[cfg(feature = "embedded-node")]
            Self::Embedded(view_client) => Ok(view_client
                .send_async(near_client::Query {
                    block_reference: query.block_reference,
                    request: query.request,
                })
                .await??),
            Self::Http(rpc) => http::query(rpc, query).await,
        }
    }

    pub(crate) async fn get_pending_request(
        &self,
        mpc_contract_id: &AccountId,
        chain_signature_request: &dtos::SignatureRequest,
    ) -> anyhow::Result<Option<YieldIndex>> {
        let get_pending_request_args: Vec<u8> = serde_json::to_string(
            &contract_args::GetPendingSignatureRequestArgs::new(chain_signature_request.clone()),
        )
        .unwrap()
        .into_bytes();

        let request = QueryRequest::CallFunction {
            account_id: mpc_contract_id.clone(),
            method_name: GET_PENDING_REQUEST.to_string(),
            args: get_pending_request_args.into(),
        };
        let block_reference = BlockReference::Finality(Finality::Final);

        let query = RpcQueryRequest {
            block_reference,
            request,
        };

        let query_response = self
            .query(query)
            .await
            .context("failed to query for pending request")?;

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
        chain_ckd_request: &dtos::CKDRequest,
    ) -> anyhow::Result<Option<YieldIndex>> {
        let get_pending_request_args: Vec<u8> = serde_json::to_string(
            &contract_args::GetPendingCKDRequestArgs::new(chain_ckd_request.clone()),
        )
        .unwrap()
        .into_bytes();

        let request = QueryRequest::CallFunction {
            account_id: mpc_contract_id.clone(),
            method_name: GET_PENDING_CKD_REQUEST.to_string(),
            args: get_pending_request_args.into(),
        };
        let block_reference = BlockReference::Finality(Finality::Final);

        let query = RpcQueryRequest {
            block_reference,
            request,
        };

        let query_response = self
            .query(query)
            .await
            .context("failed to query for pending CKD request")?;

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
        chain_verify_foreign_tx_request: &dtos::VerifyForeignTransactionRequest,
    ) -> anyhow::Result<Option<YieldIndex>> {
        let get_pending_request_args: Vec<u8> =
            serde_json::to_string(&contract_args::GetPendingVerifyForeignTxRequestArgs::new(
                chain_verify_foreign_tx_request.clone(),
            ))
            .unwrap()
            .into_bytes();

        let request = QueryRequest::CallFunction {
            account_id: mpc_contract_id.clone(),
            method_name: GET_PENDING_VERIFY_FOREIGN_TX_REQUEST.to_string(),
            args: get_pending_request_args.into(),
        };
        let block_reference = BlockReference::Finality(Finality::Final);

        let query = RpcQueryRequest {
            block_reference,
            request,
        };

        let query_response = self
            .query(query)
            .await
            .context("failed to query for pending verify foreign tx request")?;

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
        let get_attestation_args: Vec<u8> = serde_json::to_string(
            &contract_args::GetAttestationArgs::new(participant_tls_public_key),
        )
        .unwrap()
        .into_bytes();

        let request = QueryRequest::CallFunction {
            account_id: mpc_contract_id.clone(),
            method_name: GET_ATTESTATION.to_string(),
            args: get_attestation_args.into(),
        };
        let block_reference = BlockReference::Finality(Finality::Final);

        let query = RpcQueryRequest {
            block_reference,
            request,
        };

        let query_response = self
            .query(query)
            .await
            .context("failed to query for pending request")?;

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

    pub(crate) async fn get_foreign_chains_configs(
        &self,
        mpc_contract_id: &AccountId,
    ) -> anyhow::Result<(u64, dtos::ForeignChainsConfigs)> {
        self.get_mpc_state(mpc_contract_id.clone(), GET_FOREIGN_CHAINS_CONFIGS)
            .await
    }

    pub(crate) async fn get_available_chains(
        &self,
        mpc_contract_id: &AccountId,
    ) -> anyhow::Result<(u64, dtos::AvailableForeignChains)> {
        self.get_mpc_state(mpc_contract_id.clone(), GET_AVAILABLE_FOREIGN_CHAINS)
            .await
    }

    pub(crate) async fn get_allowed_foreign_chain_providers(
        &self,
        mpc_contract_id: AccountId,
    ) -> anyhow::Result<BTreeMap<dtos::ForeignChain, dtos::ChainEntry>> {
        let request = QueryRequest::CallFunction {
            account_id: mpc_contract_id,
            method_name: ALLOWED_FOREIGN_CHAIN_PROVIDERS.to_string(),
            args: vec![].into(),
        };
        let query = RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request,
        };

        let response = self.query(query).await?;

        match response.kind {
            QueryResponseKind::CallResult(result) => {
                decode_allowed_foreign_chain_providers(&result.result)
            }
            _ => anyhow::bail!("got unexpected response querying allowed_foreign_chain_providers"),
        }
    }

    pub(crate) async fn latest_final_block(&self) -> anyhow::Result<BlockView> {
        match self {
            #[cfg(feature = "embedded-node")]
            Self::Embedded(view_client) => {
                let block_query = near_client::GetBlock(BlockReference::Finality(Finality::Final));
                view_client
                    .send_async(block_query)
                    .await?
                    .context("failed to get query for final block")
            }
            Self::Http(rpc) => Ok(rpc
                .call("block", serde_json::json!({"finality": "final"}))
                .await?),
        }
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
    ) -> anyhow::Result<(u64, Vec<dtos::AllowedMpcDockerImageHash>)> {
        let (block_height, entries): (u64, AllowedDockerImageHashesResponse) = self
            .get_mpc_state(mpc_contract_id, ALLOWED_DOCKER_IMAGE_HASHES)
            .await?;

        Ok((block_height, entries))
    }
    pub(crate) async fn get_mpc_allowed_launcher_compose_hashes(
        &self,
        mpc_contract_id: AccountId,
    ) -> anyhow::Result<(u64, Vec<LauncherDockerComposeHash>)> {
        self.get_mpc_state(mpc_contract_id, ALLOWED_LAUNCHER_COMPOSE_HASHES)
            .await
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

        let query = RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request,
        };

        let response = self.query(query).await?;

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

/// TODO(#4353): drop the borsh fallback once mainnet and testnet both return JSON.
fn decode_allowed_foreign_chain_providers(
    bytes: &[u8],
) -> anyhow::Result<BTreeMap<dtos::ForeignChain, dtos::ChainEntry>> {
    let json_error = match serde_json::from_slice(bytes) {
        Ok(whitelist) => return Ok(whitelist),
        Err(error) => error,
    };
    borsh::from_slice(bytes).with_context(|| {
        let preview: String = bytes.iter().take(32).map(|b| format!("{b:02x}")).collect();
        format!(
            "failed to decode allowed_foreign_chain_providers as JSON ({json_error}) or \
             borsh (len={}, first {} bytes hex: {preview})",
            bytes.len(),
            bytes.len().min(32),
        )
    })
}

pub(crate) trait ReadAttestationExpiry: Send + Sync {
    /// The attestation expiry currently stored for `tls_public_key`, or `None` if none is stored or
    /// the stored attestation carries no expiry (an unstamped mock — e.g. from an older contract or
    /// a genesis sentinel).
    fn read_stored_attestation_expiry<'a>(
        &'a self,
        tls_public_key: &'a dtos::Ed25519PublicKey,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Option<u64>>> + Send + 'a>>;
}

pub(crate) struct RealAttestationExpiryReader {
    indexer_state: Arc<IndexerState>,
}

impl RealAttestationExpiryReader {
    pub(crate) fn new(indexer_state: Arc<IndexerState>) -> Self {
        Self { indexer_state }
    }
}

impl ReadAttestationExpiry for RealAttestationExpiryReader {
    fn read_stored_attestation_expiry<'a>(
        &'a self,
        tls_public_key: &'a dtos::Ed25519PublicKey,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Option<u64>>> + Send + 'a>>
    {
        Box::pin(async move {
            let stored = self
                .indexer_state
                .view_client
                .get_participant_attestation(&self.indexer_state.mpc_contract_id, tls_public_key)
                .await?;
            Ok(stored.and_then(|attestation| attestation.expiry_timestamp_seconds()))
        })
    }
}

#[derive(Clone)]
enum IndexerClient {
    #[cfg(feature = "embedded-node")]
    Embedded(TokioRuntimeHandle<ClientActor>),
    Http(Arc<RpcClient>),
}

const INTERVAL: Duration = Duration::from_millis(500);

/// Consecutive non-syncing polls with head progress before the node counts as caught up.
const REQUIRED_STABLE_POLLS: u32 = 4;

impl IndexerClient {
    /// Polls sync status, yielding `(syncing, head_height)`, or `None` on a
    /// failed request.
    async fn sync_info(&self) -> Option<(bool, BlockHeight)> {
        match self {
            #[cfg(feature = "embedded-node")]
            Self::Embedded(client) => {
                let status_request = Status {
                    is_health_check: false,
                    detailed: false,
                };
                let Ok(Ok(status)) = client
                    .send_async(
                        near_o11y::span_wrapped_msg::SpanWrappedMessageExt::span_wrap(
                            status_request,
                        ),
                    )
                    .await
                else {
                    return None;
                };
                Some((
                    status.sync_info.syncing,
                    status.sync_info.latest_block_height,
                ))
            }
            Self::Http(rpc) => http::sync_info(rpc).await.ok(),
        }
    }

    /// Returns once neard clears its `syncing` flag.
    async fn wait_for_full_sync(&self) {
        loop {
            tokio::time::sleep(INTERVAL).await;
            if matches!(self.sync_info().await, Some((false, _))) {
                return;
            }
        }
    }

    async fn ensure_head_follows_tip(&self) {
        let mut progress = SyncProgress::default();
        loop {
            tokio::time::sleep(INTERVAL).await;
            if let Some((syncing, head_height)) = self.sync_info().await
                && progress.observe(syncing, head_height)
            {
                return;
            }
        }
    }
}

/// Reports caught-up only after [`REQUIRED_STABLE_POLLS`] consecutive
/// non-syncing polls over which the head advances.
#[derive(Default)]
struct SyncProgress {
    run_start_head: Option<BlockHeight>,
    run_polls: u32,
}

impl SyncProgress {
    fn observe(&mut self, syncing: bool, head_height: BlockHeight) -> bool {
        if syncing {
            self.run_start_head = None;
            self.run_polls = 0;
            return false;
        }
        match self.run_start_head {
            None => {
                self.run_start_head = Some(head_height);
                self.run_polls = 1;
                false
            }
            Some(start_head) => {
                self.run_polls += 1;
                self.run_polls >= REQUIRED_STABLE_POLLS && head_height > start_head
            }
        }
    }
}

// #[derive(Debug)]
enum IndexerRpcHandler {
    #[cfg(feature = "embedded-node")]
    Embedded(MultithreadRuntimeHandle<RpcHandlerActor>),
    Http(Arc<RpcClient>),
}

/// What submission established; HTTP queueing is weaker than actor routing.
#[derive(Clone, Copy, Debug)]
enum SubmissionAck {
    #[cfg(any(feature = "embedded-node", test))]
    Routed,
    Queued,
    Unknown,
}

impl SubmissionAck {
    fn is_http(self) -> bool {
        matches!(self, Self::Queued | Self::Unknown)
    }
}

#[derive(Deserialize)]
struct HttpSubmissionResponse {
    // Require a valid status field rather than accepting a malformed success body.
    #[serde(rename = "final_execution_status")]
    _status: near_kit::rpc::TxExecutionStatus,
}

impl IndexerRpcHandler {
    /// Submits an already signed transaction without changing its bytes.
    async fn submit_tx(&self, transaction: SignedTransaction) -> anyhow::Result<SubmissionAck> {
        match self {
            Self::Http(rpc) => {
                let encoded = STANDARD.encode(borsh::to_vec(&transaction)?);
                let response = rpc
                    .call::<_, HttpSubmissionResponse>(
                        "send_tx",
                        serde_json::json!({"signed_tx_base64": encoded, "wait_until": "NONE"}),
                    )
                    .await;
                Ok(match response {
                    Ok(_) => SubmissionAck::Queued,
                    Err(error) => {
                        tracing::warn!(%error, tx_hash = %transaction.get_hash(), "HTTP submission acknowledgement unknown");
                        SubmissionAck::Unknown
                    }
                })
            }
            #[cfg(feature = "embedded-node")]
            Self::Embedded(rpc_handler) => {
                let response = rpc_handler
                    .send_async(near_client::ProcessTxRequest {
                        transaction,
                        is_forwarded: false,
                        check_only: false,
                    })
                    .await?;
                match response {
                    near_client::ProcessTxResponse::RequestRouted => Ok(SubmissionAck::Routed),
                    other => anyhow::bail!("unexpected ProcessTxResponse: {other:?}"),
                }
            }
        }
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
    /// HTTP consumers rebuild their queues from retained chain history when
    /// ownership changes; embedded consumers retain the buffered channel.
    pub block_update_receiver: Arc<tokio::sync::Mutex<BlockUpdateReceiver>>,
    /// Handle to transaction processor.
    pub txn_sender: TransactionSender,
    /// Watcher that keeps track of [`dtos::AllowedMpcDockerImageHash`]es on the contract
    pub allowed_docker_images_receiver: watch::Receiver<Vec<dtos::AllowedMpcDockerImageHash>>,
    /// Watcher that keeps track of allowed [`LauncherDockerComposeHash`]es on the contract.
    pub allowed_launcher_compose_receiver: watch::Receiver<Vec<LauncherDockerComposeHash>>,

    pub my_migration_info_receiver: watch::Receiver<MigrationInfo>,

    /// Watcher that tracks the contract's available foreign chains and their
    /// registered supporters (by TLS key). Seeded with the first successful read
    /// before the indexer hands it back, so it always holds a real value.
    pub foreign_chain_supporters_receiver: watch::Receiver<foreign_chain::ForeignChainSupporters>,

    pub(crate) attestation_reader: std::sync::Arc<dyn ReadAttestationExpiry>,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{
        BlockHeight, REQUIRED_STABLE_POLLS, SyncProgress, decode_allowed_foreign_chain_providers,
        dtos,
    };
    use assert_matches::assert_matches;
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use std::collections::BTreeMap;

    fn first_caught_up_poll(samples: &[(bool, BlockHeight)]) -> Option<usize> {
        let mut progress = SyncProgress::default();
        samples
            .iter()
            .position(|&(syncing, head)| progress.observe(syncing, head))
    }

    #[test]
    fn observe__should_never_report_caught_up_while_syncing() {
        // Given
        let samples: Vec<_> = (0..10).map(|i| (true, 42_000_000 + i)).collect();

        // When
        let caught_up_at = first_caught_up_poll(&samples);

        // Then
        assert_eq!(caught_up_at, None);
    }

    #[test]
    fn observe__should_never_report_caught_up_with_static_head_at_genesis() {
        // Given
        let genesis = 42_376_888;
        let samples: Vec<_> = (0..10).map(|_| (false, genesis)).collect();

        // When
        let caught_up_at = first_caught_up_poll(&samples);

        // Then
        assert_eq!(caught_up_at, None);
    }

    #[test]
    fn observe__should_not_report_caught_up_before_required_polls() {
        // Given
        let samples: Vec<_> = (0..REQUIRED_STABLE_POLLS - 1)
            .map(|i| (false, 257_000_000 + u64::from(i)))
            .collect();

        // When
        let caught_up_at = first_caught_up_poll(&samples);

        // Then
        assert_eq!(caught_up_at, None);
    }

    #[test]
    fn observe__should_report_caught_up_after_sustained_progress() {
        // Given
        let samples: Vec<_> = (0..REQUIRED_STABLE_POLLS)
            .map(|i| (false, 257_000_000 + u64::from(i)))
            .collect();

        // When
        let caught_up_at = first_caught_up_poll(&samples);

        // Then
        let expected = usize::try_from(REQUIRED_STABLE_POLLS).unwrap() - 1;
        assert_eq!(caught_up_at, Some(expected));
    }

    #[test]
    fn observe__should_wait_for_head_to_advance_past_run_start() {
        // Given
        let head = 257_000_000;
        let mut samples: Vec<_> = (0..REQUIRED_STABLE_POLLS + 2)
            .map(|_| (false, head))
            .collect();
        samples.push((false, head + 1));

        // When
        let caught_up_at = first_caught_up_poll(&samples);

        // Then
        assert_eq!(caught_up_at, Some(samples.len() - 1));
    }

    #[test]
    fn observe__should_reset_run_when_syncing_resumes() {
        // Given
        let pre = [
            (false, 42_000_000),
            (false, 42_000_001),
            (false, 42_000_002),
        ];
        let resync = [(true, 100_000_000)];
        let post: Vec<_> = (0..REQUIRED_STABLE_POLLS)
            .map(|i| (false, 257_000_000 + u64::from(i)))
            .collect();
        let samples: Vec<_> = pre.iter().chain(&resync).chain(&post).copied().collect();

        // When
        let caught_up_at = first_caught_up_poll(&samples);

        // Then
        let expected =
            pre.len() + resync.len() + usize::try_from(REQUIRED_STABLE_POLLS).unwrap() - 1;
        assert_eq!(caught_up_at, Some(expected));
    }

    fn whitelist_fixture() -> BTreeMap<dtos::ForeignChain, dtos::ChainEntry> {
        BTreeMap::from([(
            dtos::ForeignChain::Bitcoin,
            dtos::ChainEntry {
                providers: NonEmptyBTreeMap::new(
                    dtos::ProviderId("alchemy".to_string()),
                    dtos::ProviderConfig {
                        base_url: "http://localhost:7".to_string(),
                        auth_scheme: dtos::AuthScheme::None,
                        chain_routing: dtos::ChainRouting::Embedded,
                    },
                ),
                quorum: 1,
            },
        )])
    }

    #[test]
    fn decode_allowed_foreign_chain_providers__should_decode_a_json_result() {
        // Given
        let bytes = serde_json::to_vec(&whitelist_fixture()).unwrap();

        // When
        let decoded = decode_allowed_foreign_chain_providers(&bytes).unwrap();

        // Then
        assert_eq!(decoded, whitelist_fixture());
    }

    #[test]
    fn decode_allowed_foreign_chain_providers__should_decode_a_borsh_result() {
        // Given
        let bytes = borsh::to_vec(&whitelist_fixture()).unwrap();

        // When
        let decoded = decode_allowed_foreign_chain_providers(&bytes).unwrap();

        // Then
        assert_eq!(decoded, whitelist_fixture());
    }

    #[test]
    fn decode_allowed_foreign_chain_providers__should_decode_an_empty_borsh_result() {
        // Given
        let bytes =
            borsh::to_vec(&BTreeMap::<dtos::ForeignChain, dtos::ChainEntry>::new()).unwrap();

        // When
        let decoded = decode_allowed_foreign_chain_providers(&bytes).unwrap();

        // Then
        assert!(decoded.is_empty());
    }

    #[test]
    fn decode_allowed_foreign_chain_providers__should_return_err_on_bytes_of_neither_encoding() {
        // When
        let result = decode_allowed_foreign_chain_providers(b"not a whitelist");

        // Then
        assert_matches!(result, Err(_));
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod http_transaction_tests {
    use super::{IndexerRpcHandler, STANDARD, SubmissionAck};
    use crate::indexer::tx_signer::TransactionSigner;
    use assert_matches::assert_matches;
    use base64::Engine;
    use ed25519_dalek::SigningKey;
    use near_indexer_primitives::types::Gas;
    use near_kit::rpc::{
        BoxFuture, RetryConfig, RpcClient, RpcError, RpcTransport, TransportResponse,
    };
    use serde_json::{Value, json};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    struct RecordingTransport {
        requests: Mutex<Vec<Value>>,
        responses: Mutex<VecDeque<Result<TransportResponse, RpcError>>>,
    }

    impl RpcTransport for RecordingTransport {
        fn post_json(
            &self,
            _url: &str,
            body: Vec<u8>,
        ) -> BoxFuture<'_, Result<TransportResponse, RpcError>> {
            Box::pin(async move {
                self.requests
                    .lock()
                    .unwrap()
                    .push(serde_json::from_slice(&body).unwrap());
                self.responses.lock().unwrap().pop_front().unwrap()
            })
        }
    }

    fn response(body: Value) -> TransportResponse {
        TransportResponse {
            status: 200,
            body: serde_json::to_vec(&body).unwrap(),
        }
    }

    async fn submit_with_responses(
        responses: Vec<Result<TransportResponse, RpcError>>,
    ) -> (SubmissionAck, Vec<Value>, String) {
        let signer = TransactionSigner::from_key(
            "sender.bench".parse().unwrap(),
            SigningKey::from_bytes(&[7; 32]),
        );
        let transaction = signer.create_and_sign_function_call_tx(
            "mpc.bench".parse().unwrap(),
            "respond".into(),
            b"{}".to_vec(),
            Gas::from_gas(30_000_000_000_000),
            Default::default(),
            100,
        );
        let expected = STANDARD.encode(borsh::to_vec(&transaction).unwrap());
        let transport = Arc::new(RecordingTransport {
            requests: Mutex::new(vec![]),
            responses: Mutex::new(responses.into()),
        });
        let rpc = RpcClient::with_transport_and_retry_config(
            "http://fixture.invalid",
            transport.clone(),
            RetryConfig {
                max_retries: 1,
                initial_delay_ms: 1,
                max_delay_ms: 1,
            },
        );
        let ack = IndexerRpcHandler::Http(Arc::new(rpc))
            .submit_tx(transaction)
            .await
            .unwrap();
        let requests = transport.requests.lock().unwrap().clone();
        (ack, requests, expected)
    }

    #[tokio::test]
    async fn http_submit__should_retry_identical_signed_bytes_and_report_only_queued() {
        // Given: a response is lost after dispatch, then the identical request is acknowledged.
        let responses = vec![
            Err(RpcError::network("response lost", None, true)),
            Ok(response(
                json!({"jsonrpc":"2.0", "id":1, "result":{"final_execution_status":"NONE"}}),
            )),
        ];

        // When
        let (ack, requests, expected) = submit_with_responses(responses).await;

        // Then
        assert_matches!(ack, SubmissionAck::Queued);
        assert_eq!(requests.len(), 2);
        for request in requests {
            assert_eq!(request["method"], "send_tx");
            assert_eq!(
                request["params"],
                json!({"signed_tx_base64":expected, "wait_until":"NONE"})
            );
        }
    }

    #[tokio::test]
    async fn http_submit__should_keep_malformed_success_unknown() {
        // Given
        let responses = vec![Ok(response(json!({"jsonrpc":"2.0", "id":1, "result":{}})))];

        // When
        let (ack, requests, expected) = submit_with_responses(responses).await;

        // Then
        assert_matches!(ack, SubmissionAck::Unknown);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["params"]["signed_tx_base64"], expected);
    }

    #[tokio::test]
    async fn http_submit__should_keep_final_rejection_after_lost_response_unknown() {
        // Given: a first attempt may have landed; a rejection of the retry cannot disprove that.
        let responses = vec![
            Err(RpcError::network("response lost", None, true)),
            Ok(response(json!({"jsonrpc":"2.0", "id":1, "error": {
                "name":"HANDLER_ERROR", "cause":{"name":"INVALID_TRANSACTION", "info":{}},
                "code":-32000, "message":"server error", "data":{"TxExecutionError":{"InvalidTxError":{"InvalidNonce":{"tx_nonce":6,"ak_nonce":20}}}}
            }}))),
        ];

        // When
        let (ack, requests, expected) = submit_with_responses(responses).await;

        // Then
        assert_matches!(ack, SubmissionAck::Unknown);
        assert_eq!(requests.len(), 2);
        assert!(
            requests
                .iter()
                .all(|request| request["params"]["signed_tx_base64"] == expected)
        );
    }
}
