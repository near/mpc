
use crate::indexer::{
    migrations::ContractMigrationInfo,
    types::{ChainCKDRequest, ChainSignatureRequest, ChainVerifyForeignTransactionRequest},
};
use anyhow::Context;
use chain_gateway::contract_state::SharedContractViewer;
// todo: do not directly import and move ShardeContractViewer to a different module
//use chain_gateway::chain_gateway::SharedContractViewer;
use mpc_contract::{
    primitives::signature::YieldIndex,
    state::ProtocolContractState,
    tee::{
        proposal::{LauncherDockerComposeHash, MpcDockerImageHash},
        tee_state::NodeId,
    },
};

use super::types::{
    ChainGetPendingCKDRequestArgs, ChainGetPendingSignatureRequestArgs,
    ChainGetPendingVerifyForeignTxRequestArgs, GetAttestationArgs,
};

/// this is just a wrapper around a shared contract viewer
#[derive(Clone)]
pub(crate) struct MpcContractStateViewer {
    mpc_contract_viewer: SharedContractViewer,
}

impl MpcContractStateViewer {
    pub fn new(mpc_contract_viewer: SharedContractViewer) -> Self {
        Self {
            mpc_contract_viewer,
        }
    }
}

// todo: resovles the below:
// TODO(#1514): during refactor I noticed the account id is always taken from the indexer state as well.
// TODO(#1956): There is a lot of duplicate code here that could be simplified
impl MpcContractStateViewer {
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
            .mpc_contract_viewer
            .view(contract_interface::method_names::GET_PENDING_REQUEST, args)
            .await
            .context("failed to query for pending request")?;
        Ok(serde_json::from_slice(&call_result)?)
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
            .mpc_contract_viewer
            .view(
                contract_interface::method_names::GET_PENDING_CKD_REQUEST,
                args,
            )
            .await
            .context("failed to query for pending CKD request")?;

        Ok(serde_json::from_slice(&call_result)?)
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
            .mpc_contract_viewer
            .view(
                contract_interface::method_names::GET_PENDING_VERIFY_FOREIGN_TX_REQUEST,
                args,
            )
            .await
            .context("failed to query for pending verify foreign tx request")?;

        Ok(serde_json::from_slice(&call_result)?)
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
            .mpc_contract_viewer
            .view(contract_interface::method_names::GET_ATTESTATION, args)
            .await
            .context("failed to query for pending request")?;
        Ok(serde_json::from_slice(&call_result)?)
    }

    pub(crate) async fn get_foreign_chain_policy(
        &self,
    ) -> anyhow::Result<contract_interface::types::ForeignChainPolicy> {
        let (_height, call_result) = self
            .mpc_contract_viewer
            .view(
                contract_interface::method_names::GET_FOREIGN_CHAIN_POLICY,
                vec![],
            )
            .await?;
        Ok(serde_json::from_slice(&call_result)?)
    }

    pub(crate) async fn get_foreign_chain_policy_proposals(
        &self,
    ) -> anyhow::Result<contract_interface::types::ForeignChainPolicyVotes> {
        let (_height, call_result) = self
            .mpc_contract_viewer
            .view(
                contract_interface::method_names::GET_FOREIGN_CHAIN_POLICY_PROPOSALS,
                vec![],
            )
            .await?;
        Ok(serde_json::from_slice(&call_result)?)
    }

    pub(crate) async fn get_mpc_contract_state(
        &self,
    ) -> anyhow::Result<(u64, ProtocolContractState)> {
        let (height, call_result) = self
            .mpc_contract_viewer
            .view(contract_interface::method_names::STATE, vec![])
            .await?;
        Ok((height, serde_json::from_slice(&call_result)?))
    }

    pub(crate) async fn get_mpc_allowed_image_hashes(
        &self,
    ) -> anyhow::Result<(u64, Vec<MpcDockerImageHash>)> {
        let (height, call_result) = self
            .mpc_contract_viewer
            .view(
                contract_interface::method_names::ALLOWED_DOCKER_IMAGE_HASHES,
                vec![],
            )
            .await?;
        Ok((height, serde_json::from_slice(&call_result)?))
    }
    pub(crate) async fn get_mpc_allowed_launcher_compose_hashes(
        &self,
    ) -> anyhow::Result<(u64, Vec<LauncherDockerComposeHash>)> {
        let (height, call_result) = self
            .mpc_contract_viewer
            .view(
                contract_interface::method_names::ALLOWED_LAUNCHER_COMPOSE_HASHES,
                vec![],
            )
            .await?;
        Ok((height, serde_json::from_slice(&call_result)?))
    }

    pub(crate) async fn get_mpc_tee_accounts(&self) -> anyhow::Result<(u64, Vec<NodeId>)> {
        let (height, call_result) = self
            .mpc_contract_viewer
            .view(contract_interface::method_names::GET_TEE_ACCOUNTS, vec![])
            .await?;
        Ok((height, serde_json::from_slice(&call_result)?))
    }

    pub(crate) async fn get_mpc_migration_info(
        &self,
    ) -> anyhow::Result<(u64, ContractMigrationInfo)> {
        let (height, call_result) = self
            .mpc_contract_viewer
            .view(contract_interface::method_names::MIGRATION_INFO, vec![])
            .await?;
        Ok((height, serde_json::from_slice(&call_result)?))
    }
}
