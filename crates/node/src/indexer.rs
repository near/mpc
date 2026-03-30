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
use chain_gateway::{state_viewer::ViewMethod, types::ObservedState, ChainGateway};
use handler::ChainBlockUpdate;
use mpc_contract::{
    primitives::signature::YieldIndex,
    state::ProtocolContractState,
    tee::{
        proposal::{LauncherDockerComposeHash, NodeImageHash},
        tee_state::NodeId,
    },
};
use near_account_id::AccountId;
use near_async::{
    messaging::CanSendAsync, multithread::MultithreadRuntimeHandle, tokio::TokioRuntimeHandle,
};
use near_client::{client_actor::ClientActor, RpcHandlerActor, Status, ViewClientActor};
use near_indexer::near_primitives::transaction::SignedTransaction;
use near_indexer_primitives::{
    types::{BlockReference, Finality},
    views::{BlockView, QueryRequest, QueryResponseKind},
};
use near_mpc_contract_interface::method_names::{
    ALLOWED_DOCKER_IMAGE_HASHES, ALLOWED_LAUNCHER_COMPOSE_HASHES, GET_ATTESTATION,
    GET_FOREIGN_CHAIN_POLICY, GET_FOREIGN_CHAIN_POLICY_PROPOSALS, GET_PENDING_CKD_REQUEST,
    GET_PENDING_REQUEST, GET_PENDING_VERIFY_FOREIGN_TX_REQUEST, GET_TEE_ACCOUNTS, MIGRATION_INFO,
    STATE,
};
use near_mpc_contract_interface::types as dtos;
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
pub mod mpc_contract_viewer;
pub mod participants;
pub mod real;
pub mod tee;
pub mod tx_sender;
pub mod tx_signer;
pub mod types;

#[cfg(test)]
pub mod fake;

#[derive(Clone)]
struct MpcContractViewer<V: ViewMethod> {
    mpc_contract_id: AccountId,
    viewer: V,
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
impl<V> MpcContractViewer<V>
where
    V: ViewMethod,
{
    pub(crate) async fn get_pending_request(
        &self,
        chain_signature_request: &ChainSignatureRequest,
    ) -> anyhow::Result<Option<YieldIndex>> {
        let args = ChainGetPendingSignatureRequestArgs {
            request: chain_signature_request.clone(),
        };
        let response: ObservedState<Option<YieldIndex>> = self
            .viewer
            .view_method(&self.mpc_contract_id, GET_PENDING_REQUEST, &args)
            .await?;
        Ok(response.value)
    }

    pub(crate) async fn get_pending_ckd_request(
        &self,
        chain_ckd_request: &ChainCKDRequest,
    ) -> anyhow::Result<Option<YieldIndex>> {
        let args = ChainGetPendingCKDRequestArgs {
            request: chain_ckd_request.clone(),
        };
        let response: ObservedState<Option<YieldIndex>> = self
            .viewer
            .view_method(&self.mpc_contract_id, GET_PENDING_CKD_REQUEST, &args)
            .await?;
        Ok(response.value)
    }

    pub(crate) async fn get_pending_verify_foreign_tx_request(
        &self,
        chain_verify_foreign_tx_request: &ChainVerifyForeignTransactionRequest,
    ) -> anyhow::Result<Option<YieldIndex>> {
        let args = ChainGetPendingVerifyForeignTxRequestArgs {
            request: chain_verify_foreign_tx_request.clone(),
        };
        let response: ObservedState<Option<YieldIndex>> = self
            .viewer
            .view_method(
                &self.mpc_contract_id,
                GET_PENDING_VERIFY_FOREIGN_TX_REQUEST,
                &args,
            )
            .await?;
        Ok(response.value)
    }

    pub(crate) async fn get_participant_attestation(
        &self,
        participant_tls_public_key: &near_mpc_contract_interface::types::Ed25519PublicKey,
    ) -> anyhow::Result<Option<near_mpc_contract_interface::types::VerifiedAttestation>> {
        let args = GetAttestationArgs {
            tls_public_key: participant_tls_public_key,
        };
        let response: ObservedState<
            Option<near_mpc_contract_interface::types::VerifiedAttestation>,
        > = self
            .viewer
            .view_method(&self.mpc_contract_id, GET_ATTESTATION, &args)
            .await?;
        Ok(response.value)
    }

    pub(crate) async fn get_foreign_chain_policy(
        &self,
    ) -> anyhow::Result<dtos::ForeignChainPolicy> {
        let res = self
            .viewer
            .view_method(
                &self.mpc_contract_id,
                GET_FOREIGN_CHAIN_POLICY,
                &chain_gateway::types::NoArgs {},
            )
            .await?;
        Ok(res.value)
    }

    pub(crate) async fn get_foreign_chain_policy_proposals(
        &self,
    ) -> anyhow::Result<dtos::ForeignChainPolicyVotes> {
        let res = self
            .viewer
            .view_method(
                &self.mpc_contract_id,
                GET_FOREIGN_CHAIN_POLICY_PROPOSALS,
                &chain_gateway::types::NoArgs {},
            )
            .await?;
        Ok(res.value)
    }
    //
    //    pub(crate) async fn latest_final_block(&self) -> anyhow::Result<BlockView> {
    //        let block_query = near_client::GetBlock(BlockReference::Finality(Finality::Final));
    //        self.view_client
    //            .send_async(block_query)
    //            .await?
    //            .context("failed to get query for final block")
    //    }
    //
    //    pub(crate) async fn get_mpc_contract_state(
    //        &self,
    //        mpc_contract_id: AccountId,
    //    ) -> anyhow::Result<(u64, ProtocolContractState)> {
    //        self.get_mpc_state(mpc_contract_id, STATE).await
    //    }
    //
    //    pub(crate) async fn get_mpc_allowed_image_hashes(
    //        &self,
    //        mpc_contract_id: AccountId,
    //    ) -> anyhow::Result<(u64, Vec<NodeImageHash>)> {
    //        self.get_mpc_state(mpc_contract_id, ALLOWED_DOCKER_IMAGE_HASHES)
    //            .await
    //    }
    //    pub(crate) async fn get_mpc_allowed_launcher_compose_hashes(
    //        &self,
    //        mpc_contract_id: AccountId,
    //    ) -> anyhow::Result<(u64, Vec<LauncherDockerComposeHash>)> {
    //        self.get_mpc_state(mpc_contract_id, ALLOWED_LAUNCHER_COMPOSE_HASHES)
    //            .await
    //    }
    //
    //    pub(crate) async fn get_mpc_tee_accounts(
    //        &self,
    //        mpc_contract_id: AccountId,
    //    ) -> anyhow::Result<(u64, Vec<NodeId>)> {
    //        self.get_mpc_state(mpc_contract_id, GET_TEE_ACCOUNTS).await
    //    }
    //
    //    pub(crate) async fn get_mpc_migration_info(
    //        &self,
    //        mpc_contract_id: AccountId,
    //    ) -> anyhow::Result<(u64, ContractMigrationInfo)> {
    //        self.get_mpc_state(mpc_contract_id, MIGRATION_INFO).await
    //    }
    //
    //    async fn get_mpc_state<State>(
    //        &self,
    //        mpc_contract_id: AccountId,
    //        endpoint: &str,
    //    ) -> anyhow::Result<(u64, State)>
    //    where
    //        State: for<'de> Deserialize<'de>,
    //    {
    //        let request = QueryRequest::CallFunction {
    //            account_id: mpc_contract_id,
    //            method_name: endpoint.to_string(),
    //            args: vec![].into(),
    //        };
    //
    //        let query = near_client::Query {
    //            block_reference: BlockReference::Finality(Finality::Final),
    //            request,
    //        };
    //
    //        let response = self.view_client.send_async(query).await??;
    //
    //        match response.kind {
    //            QueryResponseKind::CallResult(result) => Ok((
    //                response.block_height,
    //                serde_json::from_slice(&result.result)?,
    //            )),
    //            _ => {
    //                anyhow::bail!("got unexpected response querying mpc contract state")
    //            }
    //        }
    //    }
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
    contract_viewer: MpcContractViewer<ChainGateway>,
}

impl RealForeignChainPolicyReader {
    pub(crate) fn new(contract_viewer: MpcContractViewer<ChainGateway>) -> Self {
        Self { contract_viewer }
    }
}

impl ReadForeignChainPolicy for RealForeignChainPolicyReader {
    async fn get_foreign_chain_policy(&self) -> anyhow::Result<dtos::ForeignChainPolicy> {
        self.contract_viewer.get_foreign_chain_policy().await
    }

    async fn get_foreign_chain_policy_proposals(
        &self,
    ) -> anyhow::Result<dtos::ForeignChainPolicyVotes> {
        self.contract_viewer
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
    pub allowed_docker_images_receiver: watch::Receiver<Vec<NodeImageHash>>,
    /// Watcher that keeps track of allowed [`LauncherDockerComposeHash`]es on the contract.
    pub allowed_launcher_compose_receiver: watch::Receiver<Vec<LauncherDockerComposeHash>>,
    /// Watcher that tracks node IDs that have TEE attestations in the contract.
    pub attested_nodes_receiver: watch::Receiver<Vec<NodeId>>,

    pub my_migration_info_receiver: watch::Receiver<MigrationInfo>,

    pub foreign_chain_policy_reader: ForeignChainPolicyReader,
}
