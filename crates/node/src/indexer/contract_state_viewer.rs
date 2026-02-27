use crate::indexer::{
    migrations::ContractMigrationInfo,
    types::{ChainCKDRequest, ChainSignatureRequest, ChainVerifyForeignTransactionRequest},
};
use anyhow::Context;
use chain_gateway::{contract_state_stream::ContractStateStream, state_viewer::StateViewer};
use mpc_contract::{primitives::signature::YieldIndex, state::ProtocolContractState};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::{
    types::{
        ChainGetPendingCKDRequestArgs, ChainGetPendingSignatureRequestArgs,
        ChainGetPendingVerifyForeignTxRequestArgs, GetAttestationArgs,
    },
    IndexerState,
};

/// this is just a wrapper around a shared contract viewer
#[derive(Clone)]
pub(crate) struct MpcContractStateViewer {
    mpc_contract_id: near_account_id::AccountId,
    mpc_contract_viewer: StateViewer,
}

pub fn spawn_subscriber<Arg, T>(
    sender: watch::Sender<T>,
    // todo: remove Arc
    indexer: Arc<IndexerState>,
    method_name: impl Into<String>,
    args: Arg,
) -> JoinHandle<anyhow::Result<()>>
where
    Arg: Serialize + Send + Sync + 'static,
    T: DeserializeOwned + Send + Clone + Sync + 'static,
{
    let method_name = method_name.into();

    tokio::spawn(async move { monitor_contract_value(sender, indexer, method_name, args).await })
}

async fn monitor_contract_value<Arg, T>(
    sender: watch::Sender<T>,
    // todo: remove Arc
    indexer: Arc<IndexerState>,
    method_name: String,
    args: Arg,
) -> anyhow::Result<()>
where
    Arg: Serialize + Send,
    T: DeserializeOwned + Send + Clone + 'static,
{
    let mut subscription = indexer
        .chain_gateway
        .subscribe::<Arg, T>(indexer.mpc_contract_id.clone(), &method_name, &args)
        .await
        .context("invalid arguments")?;

    loop {
        match subscription.latest() {
            Ok((_, value)) => {
                if sender.send(value).is_err() {
                    return Ok(()); // no receivers left
                }
            }
            Err(err) => {
                tracing::warn!(
                    method_name,
                    %err,
                    "error reading contract state, waiting for next update"
                );
            }
        }
        subscription.changed().await?; // channel closed = fatal
    }
}

impl MpcContractStateViewer {
    pub fn new(
        mpc_contract_id: near_account_id::AccountId,
        mpc_contract_viewer: StateViewer,
    ) -> Self {
        Self {
            mpc_contract_id,
            mpc_contract_viewer,
        }
    }
}

#[derive(serde::Serialize)]
struct NoArgs {}

// todo: resovles the below:
// TODO(#1514): during refactor I noticed the account id is always taken from the indexer state as well.
// TODO(#1956): There is a lot of duplicate code here that could be simplified
impl MpcContractStateViewer {
    pub(crate) async fn get_pending_request(
        &self,
        chain_signature_request: &ChainSignatureRequest,
    ) -> anyhow::Result<Option<YieldIndex>> {
        let args = ChainGetPendingSignatureRequestArgs {
            request: chain_signature_request.clone(),
        };
        let (_, call_result) = self
            .mpc_contract_viewer
            .view(
                self.mpc_contract_id.clone(),
                contract_interface::method_names::GET_PENDING_REQUEST,
                &args,
            )
            .await
            .context("failed to query for pending request")?;
        Ok(call_result)
    }
    pub(crate) async fn get_pending_ckd_request(
        &self,
        chain_ckd_request: &ChainCKDRequest,
    ) -> anyhow::Result<Option<YieldIndex>> {
        let args = ChainGetPendingCKDRequestArgs {
            request: chain_ckd_request.clone(),
        };

        let (_, call_result) = self
            .mpc_contract_viewer
            .view(
                self.mpc_contract_id.clone(),
                contract_interface::method_names::GET_PENDING_CKD_REQUEST,
                &args,
            )
            .await
            .context("failed to query for pending CKD request")?;

        Ok(call_result)
    }

    pub(crate) async fn get_pending_verify_foreign_tx_request(
        &self,
        chain_verify_foreign_tx_request: &ChainVerifyForeignTransactionRequest,
    ) -> anyhow::Result<Option<YieldIndex>> {
        let args = ChainGetPendingVerifyForeignTxRequestArgs {
            request: chain_verify_foreign_tx_request.clone(),
        };

        let (_, call_result) = self
            .mpc_contract_viewer
            .view(
                self.mpc_contract_id.clone(),
                contract_interface::method_names::GET_PENDING_VERIFY_FOREIGN_TX_REQUEST,
                &args,
            )
            .await
            .context("failed to query for pending verify foreign tx request")?;

        Ok(call_result)
    }

    pub(crate) async fn get_participant_attestation(
        &self,
        participant_tls_public_key: &contract_interface::types::Ed25519PublicKey,
    ) -> anyhow::Result<Option<contract_interface::types::VerifiedAttestation>> {
        let args = GetAttestationArgs {
            tls_public_key: participant_tls_public_key,
        };

        let (_, call_result) = self
            .mpc_contract_viewer
            .view(
                self.mpc_contract_id.clone(),
                contract_interface::method_names::GET_ATTESTATION,
                &args,
            )
            .await
            .context("failed to query for participant attestation")?;

        Ok(call_result)
    }

    pub(crate) async fn get_foreign_chain_policy(
        &self,
    ) -> anyhow::Result<contract_interface::types::ForeignChainPolicy> {
        let (_height, call_result) = self
            .mpc_contract_viewer
            .view(
                self.mpc_contract_id.clone(),
                contract_interface::method_names::GET_FOREIGN_CHAIN_POLICY,
                &NoArgs {},
            )
            .await?;

        Ok(call_result)
    }

    pub(crate) async fn get_foreign_chain_policy_proposals(
        &self,
    ) -> anyhow::Result<contract_interface::types::ForeignChainPolicyVotes> {
        let (_height, call_result) = self
            .mpc_contract_viewer
            .view(
                self.mpc_contract_id.clone(),
                contract_interface::method_names::GET_FOREIGN_CHAIN_POLICY_PROPOSALS,
                &NoArgs {},
            )
            .await?;

        Ok(call_result)
    }

    pub(crate) async fn get_mpc_contract_state(
        &self,
    ) -> anyhow::Result<(u64, ProtocolContractState)> {
        let (height, call_result) = self
            .mpc_contract_viewer
            .view(
                self.mpc_contract_id.clone(),
                contract_interface::method_names::STATE,
                &NoArgs {},
            )
            .await?;

        Ok((height.into(), call_result))
    }

    // pub(crate) async fn get_mpc_allowed_image_hashes(
    //     &self,
    // ) -> anyhow::Result<(u64, Vec<MpcDockerImageHash>)> {
    //     let (height, call_result) = self
    //         .mpc_contract_viewer
    //         .view(
    //             self.mpc_contract_id.clone(),
    //             contract_interface::method_names::ALLOWED_DOCKER_IMAGE_HASHES,
    //             &NoArgs {},
    //         )
    //         .await?;

    //     Ok((height.into(), call_result))
    // }

    // pub(crate) async fn get_mpc_allowed_launcher_compose_hashes(
    //     &self,
    // ) -> anyhow::Result<(u64, Vec<LauncherDockerComposeHash>)> {
    //     let (height, call_result) = self
    //         .mpc_contract_viewer
    //         .view(
    //             self.mpc_contract_id.clone(),
    //             contract_interface::method_names::ALLOWED_LAUNCHER_COMPOSE_HASHES,
    //             &NoArgs {},
    //         )
    //         .await?;

    //     Ok((height.into(), call_result))
    // }

    // pub(crate) async fn get_mpc_tee_accounts(&self) -> anyhow::Result<(u64, Vec<NodeId>)> {
    //     let (height, call_result) = self
    //         .mpc_contract_viewer
    //         .view(
    //             self.mpc_contract_id.clone(),
    //             contract_interface::method_names::GET_TEE_ACCOUNTS,
    //             &NoArgs {},
    //         )
    //         .await?;

    //     Ok((height.into(), call_result))
    // }

    pub(crate) async fn get_mpc_migration_info(
        &self,
    ) -> anyhow::Result<(u64, ContractMigrationInfo)> {
        let (height, call_result) = self
            .mpc_contract_viewer
            .view(
                self.mpc_contract_id.clone(),
                contract_interface::method_names::MIGRATION_INFO,
                &NoArgs {},
            )
            .await?;

        Ok((height.into(), call_result))
    }
}
