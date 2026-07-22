use near_mpc_contract_interface::call_args as contract_args;

use crate::{indexer::migrations::ContractMigrationInfo, migration_service::types::MigrationInfo};

use self::stats::IndexerStats;
use anyhow::Context;
use chain_gateway::ChainGateway;
use chain_gateway::state_viewer::ViewMethod;
use handler::ChainBlockUpdate;
use mpc_primitives::hash::{LauncherDockerComposeHash, NodeImageHash};
use near_account_id::AccountId;
use near_async::{
    messaging::CanSendAsync, multithread::MultithreadRuntimeHandle, tokio::TokioRuntimeHandle,
};
use near_client::{RpcHandlerActor, Status, ViewClientActor, client_actor::ClientActor};
use near_contract_transport::{ViewArgs, ViewContract};
use near_indexer::near_primitives::transaction::SignedTransaction;
use near_indexer_primitives::{
    types::{BlockHeight, BlockReference, Finality},
    views::BlockView,
};
use near_mpc_contract_interface::method_names::{
    ALLOWED_DOCKER_IMAGE_HASHES, ALLOWED_FOREIGN_CHAIN_PROVIDERS, ALLOWED_LAUNCHER_COMPOSE_HASHES,
    GET_ATTESTATION, GET_AVAILABLE_FOREIGN_CHAINS, GET_FOREIGN_CHAINS_CONFIGS,
    GET_PENDING_CKD_REQUEST, GET_PENDING_REQUEST, GET_PENDING_VERIFY_FOREIGN_TX_REQUEST,
    GET_SUPPORTED_FOREIGN_CHAINS, GET_TEE_ACCOUNTS, MIGRATION_INFO, STATE,
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
pub mod foreign_chain;
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

// TODO(#3751): drop this struct after upgrading the contract.
#[derive(Debug, PartialEq, Deserialize)]
#[serde(untagged)]
enum AllowedDockerImageHashesResponse {
    WithExpiry(Vec<dtos::AllowedMpcDockerImageHash>),
    Legacy(Vec<NodeImageHash>),
}

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
        let chain_gateway = ChainGateway::from_actor_handles(
            view_client.clone(),
            client.clone(),
            rpc_handler.clone(),
        );
        Self {
            view_client: IndexerViewClient {
                chain_gateway,
                view_client,
            },
            client: IndexerClient { client },
            rpc_handler: IndexerRpcHandler { rpc_handler },
            mpc_contract_id,
            stats: Arc::new(Mutex::new(IndexerStats::new())),
        }
    }
}

/// Contract views over the chain-gateway view ladder ([`ViewMethod`]),
/// assembled from the indexer's own actor handles.
#[derive(Clone)]
pub(crate) struct IndexerViewClient {
    chain_gateway: ChainGateway,
    /// Raw handle for block queries ([`Self::latest_final_block`]), which are
    /// not contract views.
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
        chain_signature_request: &dtos::SignatureRequest,
    ) -> anyhow::Result<Option<YieldIndex>> {
        let args = serde_json::to_vec(&contract_args::GetPendingSignatureRequestArgs::new(
            chain_signature_request.clone(),
        ))?;
        let observed = self
            .chain_gateway
            .view_method::<Option<YieldIndex>>(
                mpc_contract_id.clone(),
                ViewArgs::new(GET_PENDING_REQUEST, args),
            )
            .await
            .context("failed to query for pending request")?;
        Ok(observed.value)
    }

    pub(crate) async fn get_pending_ckd_request(
        &self,
        mpc_contract_id: &AccountId,
        chain_ckd_request: &dtos::CKDRequest,
    ) -> anyhow::Result<Option<YieldIndex>> {
        let args = serde_json::to_vec(&contract_args::GetPendingCKDRequestArgs::new(
            chain_ckd_request.clone(),
        ))?;
        let observed = self
            .chain_gateway
            .view_method::<Option<YieldIndex>>(
                mpc_contract_id.clone(),
                ViewArgs::new(GET_PENDING_CKD_REQUEST, args),
            )
            .await
            .context("failed to query for pending CKD request")?;
        Ok(observed.value)
    }

    pub(crate) async fn get_pending_verify_foreign_tx_request(
        &self,
        mpc_contract_id: &AccountId,
        chain_verify_foreign_tx_request: &dtos::VerifyForeignTransactionRequest,
    ) -> anyhow::Result<Option<YieldIndex>> {
        let args = serde_json::to_vec(&contract_args::GetPendingVerifyForeignTxRequestArgs::new(
            chain_verify_foreign_tx_request.clone(),
        ))?;
        let observed = self
            .chain_gateway
            .view_method::<Option<YieldIndex>>(
                mpc_contract_id.clone(),
                ViewArgs::new(GET_PENDING_VERIFY_FOREIGN_TX_REQUEST, args),
            )
            .await
            .context("failed to query for pending verify foreign tx request")?;
        Ok(observed.value)
    }

    pub(crate) async fn get_participant_attestation(
        &self,
        mpc_contract_id: &AccountId,
        participant_tls_public_key: &dtos::Ed25519PublicKey,
    ) -> anyhow::Result<Option<dtos::VerifiedAttestation>> {
        let args = serde_json::to_vec(&contract_args::GetAttestationArgs::new(
            participant_tls_public_key,
        ))?;
        let observed = self
            .chain_gateway
            .view_method::<Option<dtos::VerifiedAttestation>>(
                mpc_contract_id.clone(),
                ViewArgs::new(GET_ATTESTATION, args),
            )
            .await
            .context("failed to query stored attestation")?;
        Ok(observed.value)
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

    /// Borsh-decoding view-fn query, over the raw [`ViewContract`] seam (the
    /// [`ViewMethod`] ladder is JSON-only).
    pub(crate) async fn get_allowed_foreign_chain_providers(
        &self,
        mpc_contract_id: AccountId,
    ) -> anyhow::Result<std::collections::BTreeMap<dtos::ForeignChain, dtos::ChainEntry>> {
        let observed = self
            .chain_gateway
            .view_contract(
                &mpc_contract_id,
                ViewArgs::new(ALLOWED_FOREIGN_CHAIN_PROVIDERS, vec![]),
            )
            .await?;

        borsh::from_slice::<std::collections::BTreeMap<dtos::ForeignChain, dtos::ChainEntry>>(
            &observed.value,
        )
        .with_context(|| {
            let preview: String = observed
                .value
                .iter()
                .take(32)
                .map(|b| format!("{b:02x}"))
                .collect();
            format!(
                "failed to borsh-decode allowed_foreign_chain_providers response (len={}, first {} bytes hex: {preview})",
                observed.value.len(),
                observed.value.len().min(32),
            )
        })
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
    ) -> anyhow::Result<(u64, Vec<dtos::AllowedMpcDockerImageHash>)> {
        let (block_height, response): (u64, AllowedDockerImageHashesResponse) = self
            .get_mpc_state(mpc_contract_id, ALLOWED_DOCKER_IMAGE_HASHES)
            .await?;

        // TODO(#3751): drop this logic after upgrading the contract.
        let entries = match response {
            AllowedDockerImageHashesResponse::WithExpiry(entries) => entries,
            AllowedDockerImageHashesResponse::Legacy(hashes) => hashes
                .into_iter()
                .map(|image_hash| dtos::AllowedMpcDockerImageHash {
                    image_hash,
                    expiry_timestamp_seconds: None,
                })
                .collect(),
        };
        Ok((block_height, entries))
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
        State: for<'de> Deserialize<'de> + Send,
    {
        let observed = self
            .chain_gateway
            .view_method::<State>(mpc_contract_id, ViewArgs::no_args(endpoint))
            .await?;
        Ok((observed.observed_at.into(), observed.value))
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

pub(crate) trait ReadAttestationExpiry: Send + Sync {
    /// The Dstack attestation expiry currently stored for `tls_public_key`, or `None` if none is
    /// stored.
    fn read_stored_dstack_expiry<'a>(
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
    fn read_stored_dstack_expiry<'a>(
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
            Ok(match stored {
                Some(dtos::VerifiedAttestation::Dstack(a)) => Some(a.expiry_timestamp_seconds),
                _ => None,
            })
        })
    }
}

#[derive(Clone)]
struct IndexerClient {
    client: TokioRuntimeHandle<ClientActor>,
}

const INTERVAL: Duration = Duration::from_millis(500);

/// Consecutive non-syncing polls with head progress before the node counts as caught up.
const REQUIRED_STABLE_POLLS: u32 = 4;

impl IndexerClient {
    /// Polls sync status, yielding `(syncing, head_height)`, or `None` on a
    /// failed request.
    async fn sync_info(&self) -> Option<(bool, BlockHeight)> {
        let status_request = Status {
            is_health_check: false,
            detailed: false,
        };
        let Ok(Ok(status)) = self
            .client
            .send_async(
                near_o11y::span_wrapped_msg::SpanWrappedMessageExt::span_wrap(status_request),
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
    /// Watcher that keeps track of [`dtos::AllowedMpcDockerImageHash`]es on the contract
    pub allowed_docker_images_receiver: watch::Receiver<Vec<dtos::AllowedMpcDockerImageHash>>,
    /// Watcher that keeps track of allowed [`LauncherDockerComposeHash`]es on the contract.
    pub allowed_launcher_compose_receiver: watch::Receiver<Vec<LauncherDockerComposeHash>>,
    /// Watcher that tracks node IDs that have TEE attestations in the contract.
    pub attested_nodes_receiver: watch::Receiver<Vec<dtos::NodeId>>,

    pub my_migration_info_receiver: watch::Receiver<MigrationInfo>,

    pub foreign_chain_policy_reader: ForeignChainPolicyReader,

    /// Watcher that tracks the contract's available foreign chains and their
    /// registered supporters (by TLS key).
    #[expect(
        dead_code,
        reason = "consumed once the verify-foreign-tx provider switches to the new API"
    )]
    pub foreign_chain_supporters_receiver: watch::Receiver<foreign_chain::ForeignChainSupporters>,

    pub(crate) attestation_reader: std::sync::Arc<dyn ReadAttestationExpiry>,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{
        AllowedDockerImageHashesResponse, BlockHeight, REQUIRED_STABLE_POLLS, SyncProgress,
    };
    use assert_matches::assert_matches;
    use mpc_primitives::hash::NodeImageHash;

    #[test]
    fn allowed_docker_image_hashes_response__should_deserialize_with_expiry_objects() {
        let json = r#"[
        { "image_hash": "1111111111111111111111111111111111111111111111111111111111111111", "expiry_timestamp_seconds": 42 },
        { "image_hash": "2222222222222222222222222222222222222222222222222222222222222222", "expiry_timestamp_seconds": null }
    ]"#;
        let response: AllowedDockerImageHashesResponse = serde_json::from_str(json).unwrap();
        assert_matches!(response, AllowedDockerImageHashesResponse::WithExpiry(entries) if entries.len() == 2);
    }

    #[test]
    fn allowed_docker_image_hashes_response__should_deserialize_legacy_bare_hashes() {
        // Given: the shape returned by contracts predating expiry reporting.
        let json = r#"[
            "1111111111111111111111111111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222222222222222222222222222"
        ]"#;

        // When
        let response: AllowedDockerImageHashesResponse = serde_json::from_str(json).unwrap();

        // Then
        assert_eq!(
            response,
            AllowedDockerImageHashesResponse::Legacy(vec![
                NodeImageHash::from([0x11; 32]),
                NodeImageHash::from([0x22; 32]),
            ])
        );
    }

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
}
