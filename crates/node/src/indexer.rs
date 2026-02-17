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
use contract_interface::method_names::{
    ALLOWED_DOCKER_IMAGE_HASHES, ALLOWED_LAUNCHER_COMPOSE_HASHES, GET_ATTESTATION,
    GET_FOREIGN_CHAIN_POLICY, GET_FOREIGN_CHAIN_POLICY_PROPOSALS, GET_PENDING_CKD_REQUEST,
    GET_PENDING_REQUEST, GET_PENDING_VERIFY_FOREIGN_TX_REQUEST, GET_TEE_ACCOUNTS, MIGRATION_INFO,
    STATE,
};
use contract_interface::types as dtos;
use handler::ChainBlockUpdate;
use mpc_contract::{
    primitives::signature::YieldIndex,
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
use near_indexer::near_primitives::transaction::SignedTransaction;
use near_indexer_primitives::{
    types::{BlockReference, Finality},
    views::{BlockView, QueryRequest, QueryResponseKind},
};
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
        view_client: MultithreadRuntimeHandle<ViewClientActorInner>,
        client: TokioRuntimeHandle<ClientActorInner>,
        rpc_handler: MultithreadRuntimeHandle<RpcHandler>,
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
struct IndexerViewClient {
    view_client: MultithreadRuntimeHandle<ViewClientActorInner>,
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
            // TODO(#1959): add this function in the contract
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
        participant_tls_public_key: &contract_interface::types::Ed25519PublicKey,
    ) -> anyhow::Result<Option<contract_interface::types::VerifiedAttestation>> {
        let get_attestation_args: Vec<u8> = serde_json::to_string(&GetAttestationArgs {
            tls_public_key: participant_tls_public_key,
        })
        .unwrap()
        .into_bytes();

        let request = QueryRequest::CallFunction {
            account_id: mpc_contract_id.clone(),
            method_name: GET_TEE_ATTESTATION_ENDPOINT.to_string(),
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
                Option<contract_interface::types::VerifiedAttestation>,
            >(&call_result.result)
            .context("failed to deserialize pending request response"),
            _ => {
                anyhow::bail!("Unexpected result from a view client function call");
            }
        }
    }

    pub(crate) async fn get_foreign_chain_policy(
        &self,
        mpc_contract_id: &AccountId,
    ) -> anyhow::Result<dtos::ForeignChainPolicy> {
        let (_height, policy) = self
            .get_mpc_state(mpc_contract_id.clone(), FOREIGN_CHAIN_POLICY_ENDPOINT)
            .await?;
        Ok(policy)
    }

    pub(crate) async fn get_foreign_chain_policy_proposals(
        &self,
        mpc_contract_id: &AccountId,
    ) -> anyhow::Result<dtos::ForeignChainPolicyVotes> {
        let (_height, proposals) = self
            .get_mpc_state(
                mpc_contract_id.clone(),
                FOREIGN_CHAIN_POLICY_PROPOSALS_ENDPOINT,
            )
            .await?;
        Ok(proposals)
    }

    pub(crate) async fn latest_final_block(&self) -> anyhow::Result<BlockView> {
        let block_query = near_client::GetBlock(BlockReference::Finality(Finality::Final));
        self.view_client
            .send_async(block_query)
            .await?
            .context("failed to get query for final block")
    }

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
    indexer_state: Arc<IndexerState>,
}

impl RealForeignChainPolicyReader {
    pub(crate) fn new(indexer_state: Arc<IndexerState>) -> Self {
        Self { indexer_state }
    }
}

impl ReadForeignChainPolicy for RealForeignChainPolicyReader {
    async fn get_foreign_chain_policy(&self) -> anyhow::Result<dtos::ForeignChainPolicy> {
        self.indexer_state
            .view_client
            .get_foreign_chain_policy(&self.indexer_state.mpc_contract_id)
            .await
    }

    async fn get_foreign_chain_policy_proposals(
        &self,
    ) -> anyhow::Result<dtos::ForeignChainPolicyVotes> {
        self.indexer_state
            .view_client
            .get_foreign_chain_policy_proposals(&self.indexer_state.mpc_contract_id)
            .await
    }
}

#[derive(Clone)]
struct IndexerClient {
    client: TokioRuntimeHandle<ClientActorInner>,
}

const INTERVAL: Duration = Duration::from_millis(500);
const ALLOWED_IMAGE_HASHES_ENDPOINT: &str = ALLOWED_DOCKER_IMAGE_HASHES;
const ALLOWED_LAUNCHER_COMPOSE_HASHES_ENDPOINT: &str = ALLOWED_LAUNCHER_COMPOSE_HASHES;
const TEE_ACCOUNTS_ENDPOINT: &str = GET_TEE_ACCOUNTS;
pub const MIGRATION_INFO_ENDPOINT: &str = MIGRATION_INFO;
const CONTRACT_STATE_ENDPOINT: &str = STATE;
const GET_TEE_ATTESTATION_ENDPOINT: &str = GET_ATTESTATION;
const FOREIGN_CHAIN_POLICY_ENDPOINT: &str = GET_FOREIGN_CHAIN_POLICY;
const FOREIGN_CHAIN_POLICY_PROPOSALS_ENDPOINT: &str = GET_FOREIGN_CHAIN_POLICY_PROPOSALS;

impl IndexerClient {
    async fn wait_for_full_sync(&self) {
        loop {
            tokio::time::sleep(INTERVAL).await;

            let status_request = Status {
                is_health_check: false,
                detailed: false,
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

            if !status.sync_info.syncing {
                return;
            }
        }
    }
}

// #[derive(Debug)]
struct IndexerRpcHandler {
    rpc_handler: MultithreadRuntimeHandle<RpcHandler>,
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
