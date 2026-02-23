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
use async_trait::async_trait;
use chain_gateway::chain_gateway::{ChainGateway, FinalizedStateView};
use contract_interface::method_names::{
    ALLOWED_DOCKER_IMAGE_HASHES, ALLOWED_LAUNCHER_COMPOSE_HASHES, GET_ATTESTATION,
    GET_FOREIGN_CHAIN_POLICY, GET_FOREIGN_CHAIN_POLICY_PROPOSALS, GET_PENDING_CKD_REQUEST,
    GET_PENDING_REQUEST, GET_PENDING_VERIFY_FOREIGN_TX_REQUEST, GET_TEE_ACCOUNTS, MIGRATION_INFO,
    STATE,
};
use contract_interface::types as dtos;
use contract_state_viewer::MpcContractStateViewer;
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
use participants::ContractState;
use serde::Deserialize;
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
    //    contract_state_viewer: SharedContractViewer,
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

//#[async_trait]
//pub(crate) trait MpcContractStateViewer {
//    async fn get_pending_request(
//        &self,
//        chain_signature_request: &ChainSignatureRequest,
//    ) -> anyhow::Result<Option<YieldIndex>>;
//    async fn get_pending_ckd_request(
//        &self,
//        chain_ckd_request: &ChainCKDRequest,
//    ) -> anyhow::Result<Option<YieldIndex>>;
//
//    async fn get_pending_verify_foreign_tx_request(
//        &self,
//        chain_verify_foreign_tx_request: &ChainVerifyForeignTransactionRequest,
//    ) -> anyhow::Result<Option<YieldIndex>>;
//
//    async fn get_participant_attestation(
//        &self,
//        participant_tls_public_key: &contract_interface::types::Ed25519PublicKey,
//    ) -> anyhow::Result<Option<contract_interface::types::VerifiedAttestation>>;
//
//    async fn get_mpc_contract_state(&self) -> anyhow::Result<(u64, ProtocolContractState)>;
//
//    async fn get_mpc_allowed_image_hashes(&self) -> anyhow::Result<(u64, Vec<MpcDockerImageHash>)>;
//    async fn get_mpc_allowed_launcher_compose_hashes(
//        &self,
//    ) -> anyhow::Result<(u64, Vec<LauncherDockerComposeHash>)>;
//
//    async fn get_mpc_tee_accounts(&self) -> anyhow::Result<(u64, Vec<NodeId>)>;
//    async fn get_mpc_migration_info(&self) -> anyhow::Result<(u64, ContractMigrationInfo)>;
//
//    async fn get_foreign_chain_policy(&self) -> anyhow::Result<dtos::ForeignChainPolicy>;
//    async fn get_foreign_chain_policy_proposals(
//        &self,
//    ) -> anyhow::Result<dtos::ForeignChainPolicyVotes>;
//}

//// TODO(#1514): during refactor I noticed the account id is always taken from the indexer state as well.
//// TODO(#1956): There is a lot of duplicate code here that could be simplified
//#[async_trait]
//impl MpcContractStateViewer for IndexerState {
//    async fn get_pending_request(
//        &self,
//        chain_signature_request: &ChainSignatureRequest,
//    ) -> anyhow::Result<Option<YieldIndex>> {
//        let args: Vec<u8> = serde_json::to_string(&ChainGetPendingSignatureRequestArgs {
//            request: chain_signature_request.clone(),
//        })
//        .unwrap()
//        .into_bytes();
//
//        let (_, call_result) = self
//            .call_view_method(GET_PENDING_REQUEST, args)
//            .await
//            .context("failed to query for pending request")?;
//        Ok(call_result)
//    }
//
//    async fn get_pending_ckd_request(
//        &self,
//        chain_ckd_request: &ChainCKDRequest,
//    ) -> anyhow::Result<Option<YieldIndex>> {
//        let args: Vec<u8> = serde_json::to_string(&ChainGetPendingCKDRequestArgs {
//            request: chain_ckd_request.clone(),
//        })
//        .unwrap()
//        .into_bytes();
//
//        let (_, call_result) = self
//            .call_view_method(GET_PENDING_CKD_REQUEST, args)
//            .await
//            .context("failed to query for pending CKD request")?;
//
//        Ok(call_result)
//    }
//
//    async fn get_pending_verify_foreign_tx_request(
//        &self,
//        chain_verify_foreign_tx_request: &ChainVerifyForeignTransactionRequest,
//    ) -> anyhow::Result<Option<YieldIndex>> {
//        let args: Vec<u8> = serde_json::to_string(&ChainGetPendingVerifyForeignTxRequestArgs {
//            request: chain_verify_foreign_tx_request.clone(),
//        })
//        .unwrap()
//        .into_bytes();
//
//        let (_, call_result) = self
//            .call_view_method(GET_PENDING_VERIFY_FOREIGN_TX_REQUEST, args)
//            .await
//            .context("failed to query for pending verify foreign tx request")?;
//
//        Ok(call_result)
//    }
//
//    async fn get_participant_attestation(
//        &self,
//        participant_tls_public_key: &contract_interface::types::Ed25519PublicKey,
//    ) -> anyhow::Result<Option<contract_interface::types::VerifiedAttestation>> {
//        let args: Vec<u8> = serde_json::to_string(&GetAttestationArgs {
//            tls_public_key: participant_tls_public_key,
//        })
//        .unwrap()
//        .into_bytes();
//
//        let (_, call_result) = self
//            .call_view_method(GET_ATTESTATION, args)
//            .await
//            .context("failed to query for pending request")?;
//        Ok(call_result)
//    }
//
//    async fn get_foreign_chain_policy(&self) -> anyhow::Result<dtos::ForeignChainPolicy> {
//        let (_height, policy) = self
//            .call_view_method(GET_FOREIGN_CHAIN_POLICY, vec![])
//            .await?;
//        Ok(policy)
//    }
//
//    async fn get_foreign_chain_policy_proposals(
//        &self,
//    ) -> anyhow::Result<dtos::ForeignChainPolicyVotes> {
//        let (_height, proposals) = self
//            .call_view_method(GET_FOREIGN_CHAIN_POLICY_PROPOSALS, vec![])
//            .await?;
//        Ok(proposals)
//    }
//
//    async fn get_mpc_contract_state(&self) -> anyhow::Result<(u64, ProtocolContractState)> {
//        self.call_view_method(STATE, vec![]).await
//    }
//
//    async fn get_mpc_allowed_image_hashes(&self) -> anyhow::Result<(u64, Vec<MpcDockerImageHash>)> {
//        self.call_view_method(ALLOWED_DOCKER_IMAGE_HASHES, vec![])
//            .await
//    }
//    async fn get_mpc_allowed_launcher_compose_hashes(
//        &self,
//    ) -> anyhow::Result<(u64, Vec<LauncherDockerComposeHash>)> {
//        self.call_view_method(ALLOWED_LAUNCHER_COMPOSE_HASHES, vec![])
//            .await
//    }
//
//    async fn get_mpc_tee_accounts(&self) -> anyhow::Result<(u64, Vec<NodeId>)> {
//        self.call_view_method(GET_TEE_ACCOUNTS, vec![]).await
//    }
//
//    async fn get_mpc_migration_info(&self) -> anyhow::Result<(u64, ContractMigrationInfo)> {
//        self.call_view_method(MIGRATION_INFO, vec![]).await
//    }
//}

impl IndexerState {
    async fn call_view_method<State>(
        &self,
        method: &str,
        args: Vec<u8>,
    ) -> anyhow::Result<(u64, State)>
    where
        State: for<'de> Deserialize<'de>,
    {
        let (block_height, call_result) = self
            .chain_gateway
            .view_call(&self.mpc_contract_id, method, args)
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
