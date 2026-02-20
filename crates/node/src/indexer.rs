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

use anyhow::Context;
use chain_gateway::neard::ChainGateway;
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
    /// Chain indexer to interact with the NEAR blockchain
    chain_gateway: ChainGateway,
    /// AccountId for the mpc contract.
    mpc_contract_id: AccountId,
}

impl IndexerState {
    pub fn new(
        chain_gateway: ChainGateway,
        //view_client: MultithreadRuntimeHandle<ViewClientActorInner>,
        //client: TokioRuntimeHandle<ClientActorInner>,
        //rpc_handler: MultithreadRuntimeHandle<RpcHandler>,
        mpc_contract_id: AccountId,
    ) -> Self {
        Self {
            chain_gateway,
            //view_client: IndexerViewClient { view_client },
            //client: IndexerClient { client },
            //rpc_handler: IndexerRpcHandler { rpc_handler },
            mpc_contract_id,
            //stats: Arc::new(Mutex::new(IndexerStats::new())),
        }
    }
}

//#[derive(Clone)]
//struct IndexerViewClient {
//    view_client: MultithreadRuntimeHandle<ViewClientActorInner>,
//}

// TODO(#1514): during refactor I noticed the account id is always taken from the indexer state as well.
// We should remove this account_id parameter...
//
// example:
// indexer_state.view_client.get_mpc_tee_accounts(indexer_state.mpc_contract_id.clone()).await
// =>
// indexer_state.view_client.get_mpc_tee_accounts().await
// This pattern repeats for all the methods.
// TODO(#1956): There is a lot of duplicate code here that could be simplified
impl IndexerState {
    pub(crate) async fn get_pending_request(
        &self,
        chain_signature_request: &ChainSignatureRequest,
    ) -> anyhow::Result<Option<YieldIndex>> {
        let args: Vec<u8> = serde_json::to_string(&ChainGetPendingSignatureRequestArgs {
            request: chain_signature_request.clone(),
        })
        .unwrap()
        .into_bytes();

        let (_, call_result) = self
            .chain_gateway
            .function_query(&self.mpc_contract_id, GET_PENDING_REQUEST, args.into())
            .await
            .context("failed to query for pending request")?;
        serde_json::from_slice::<Option<YieldIndex>>(&call_result)
            .context("failed to deserialize pending request response")
    }

    pub(crate) async fn get_pending_ckd_request(
        &self,
        chain_ckd_request: &ChainCKDRequest,
    ) -> anyhow::Result<Option<YieldIndex>> {
        let args: Vec<u8> = serde_json::to_string(&ChainGetPendingCKDRequestArgs {
            request: chain_ckd_request.clone(),
        })
        .unwrap()
        .into_bytes();

        let (_, call_result) = self
            .chain_gateway
            .function_query(&self.mpc_contract_id, GET_PENDING_CKD_REQUEST, args)
            .await
            .context("failed to query for pending CKD request")?;

        serde_json::from_slice::<Option<YieldIndex>>(&call_result)
            .context("failed to deserialize pending CKD request response")
    }

    pub(crate) async fn get_pending_verify_foreign_tx_request(
        &self,
        chain_verify_foreign_tx_request: &ChainVerifyForeignTransactionRequest,
    ) -> anyhow::Result<Option<YieldIndex>> {
        let args: Vec<u8> = serde_json::to_string(&ChainGetPendingVerifyForeignTxRequestArgs {
            request: chain_verify_foreign_tx_request.clone(),
        })
        .unwrap()
        .into_bytes();

        let (_, call_result) = self
            .chain_gateway
            .function_query(
                &self.mpc_contract_id,
                GET_PENDING_VERIFY_FOREIGN_TX_REQUEST,
                args,
            )
            .await
            .context("failed to query for pending verify foreign tx request")?;

        serde_json::from_slice::<Option<YieldIndex>>(&call_result)
            .context("failed to deserialize pending verify foreign tx request response")
    }

    pub(crate) async fn get_participant_attestation(
        &self,
        participant_tls_public_key: &contract_interface::types::Ed25519PublicKey,
    ) -> anyhow::Result<Option<contract_interface::types::VerifiedAttestation>> {
        let args: Vec<u8> = serde_json::to_string(&GetAttestationArgs {
            tls_public_key: participant_tls_public_key,
        })
        .unwrap()
        .into_bytes();

        let (_, call_result) = self
            .chain_gateway
            .function_query(&self.mpc_contract_id, GET_ATTESTATION, args)
            .await
            .context("failed to query for pending request")?;

        serde_json::from_slice::<Option<contract_interface::types::VerifiedAttestation>>(
            &call_result,
        )
        .context("failed to deserialize pending request response")
    }

    pub(crate) async fn get_foreign_chain_policy(
        &self,
    ) -> anyhow::Result<dtos::ForeignChainPolicy> {
        let (_height, policy) = self.get_mpc_state(GET_FOREIGN_CHAIN_POLICY).await?;
        Ok(policy)
    }

    pub(crate) async fn get_foreign_chain_policy_proposals(
        &self,
    ) -> anyhow::Result<dtos::ForeignChainPolicyVotes> {
        let (_height, proposals) = self
            .get_mpc_state(GET_FOREIGN_CHAIN_POLICY_PROPOSALS)
            .await?;
        Ok(proposals)
    }

    pub(crate) async fn latest_final_block(&self) -> anyhow::Result<BlockView> {
        Ok(self
            .chain_gateway
            .latest_final_block()
            .await
            .context("failed to get query for final block")?)
    }

    pub(crate) async fn get_mpc_contract_state(
        &self,
    ) -> anyhow::Result<(u64, ProtocolContractState)> {
        self.get_mpc_state(STATE).await
    }

    pub(crate) async fn get_mpc_allowed_image_hashes(
        &self,
    ) -> anyhow::Result<(u64, Vec<MpcDockerImageHash>)> {
        self.get_mpc_state(ALLOWED_DOCKER_IMAGE_HASHES).await
    }
    pub(crate) async fn get_mpc_allowed_launcher_compose_hashes(
        &self,
    ) -> anyhow::Result<(u64, Vec<LauncherDockerComposeHash>)> {
        self.get_mpc_state(ALLOWED_LAUNCHER_COMPOSE_HASHES).await
    }

    pub(crate) async fn get_mpc_tee_accounts(&self) -> anyhow::Result<(u64, Vec<NodeId>)> {
        self.get_mpc_state(GET_TEE_ACCOUNTS).await
    }

    pub(crate) async fn get_mpc_migration_info(
        &self,
    ) -> anyhow::Result<(u64, ContractMigrationInfo)> {
        self.get_mpc_state(MIGRATION_INFO).await
    }

    async fn get_mpc_state<State>(&self, endpoint: &str) -> anyhow::Result<(u64, State)>
    where
        State: for<'de> Deserialize<'de>,
    {
        let (block_height, call_result) = self
            .chain_gateway
            .function_query(&self.mpc_contract_id, endpoint, vec![].into())
            .await
            .context("failed to query contract")?;
        Ok((block_height, serde_json::from_slice(&call_result)?))
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
        self.indexer_state.get_foreign_chain_policy().await
    }

    async fn get_foreign_chain_policy_proposals(
        &self,
    ) -> anyhow::Result<dtos::ForeignChainPolicyVotes> {
        self.indexer_state
            .get_foreign_chain_policy_proposals()
            .await
    }
}

//#[derive(Clone)]
//struct IndexerClient {
//    client: TokioRuntimeHandle<ClientActorInner>,
//}
//
//const INTERVAL: Duration = Duration::from_millis(500);
//
//impl IndexerClient {
//    async fn wait_for_full_sync(&self) {
//        loop {
//            tokio::time::sleep(INTERVAL).await;
//
//            let status_request = Status {
//                is_health_check: false,
//                detailed: false,
//            };
//            let status_response = self
//                .client
//                .send_async(
//                    near_o11y::span_wrapped_msg::SpanWrappedMessageExt::span_wrap(status_request),
//                )
//                .await;
//
//            let Ok(Ok(status)) = status_response else {
//                continue;
//            };
//
//            if !status.sync_info.syncing {
//                return;
//            }
//        }
//    }
//}
//
//// #[derive(Debug)]
//struct IndexerRpcHandler {
//    rpc_handler: MultithreadRuntimeHandle<RpcHandler>,
//}
//
//impl IndexerRpcHandler {
//    /// Creates, signs, and submits a function call with the given method and serialized arguments.
//    async fn submit_tx(&self, transaction: SignedTransaction) -> anyhow::Result<()> {
//        let response = self
//            .rpc_handler
//            .send_async(near_client::ProcessTxRequest {
//                transaction,
//                is_forwarded: false,
//                check_only: false,
//            })
//            .await?;
//
//        match response {
//            // We're not a validator, so we should always be routing the transaction.
//            near_client::ProcessTxResponse::RequestRouted => Ok(()),
//            _ => {
//                anyhow::bail!("unexpected ProcessTxResponse: {:?}", response);
//            }
//        }
//    }
//}

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
