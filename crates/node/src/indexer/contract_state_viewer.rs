use crate::indexer::types::{
    ChainCKDRequest, ChainSignatureRequest, ChainVerifyForeignTransactionRequest,
};
use anyhow::Context;
use chain_gateway::ChainGateway;
use chain_gateway::state_viewer::{
    ContractStateStream, ContractStateSubscriber, MethodViewer,
};
use chain_gateway::types::NoArgs;
use mpc_contract::primitives::signature::YieldIndex;
use serde::de::DeserializeOwned;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::types::{
    ChainGetPendingCKDRequestArgs, ChainGetPendingSignatureRequestArgs,
    ChainGetPendingVerifyForeignTxRequestArgs, GetAttestationArgs,
};

/// this is just a wrapper around a shared contract viewer
#[derive(Clone)]
pub(crate) struct MpcContractStateViewer {
    pub(crate) mpc_contract_id: near_account_id::AccountId,
    pub(crate) mpc_contract_viewer: ChainGateway,
}

impl MpcContractStateViewer {
    pub fn spawn_subscriber<T>(
        &self,
        sender: watch::Sender<T>,
        method_name: impl Into<String>,
    ) -> JoinHandle<anyhow::Result<()>>
    where
        T: DeserializeOwned + Send + Clone + Sync + 'static,
    {
        let method_name = method_name.into();

        let this = self.clone();
        tokio::spawn(async move { this.monitor_contract_value(sender, method_name).await })
    }
    async fn monitor_contract_value<T>(
        &self,
        sender: watch::Sender<T>,
        method_name: String,
    ) -> anyhow::Result<()>
    where
        T: DeserializeOwned + Send + Clone + 'static,
    {
        let mut subscription = self
            .mpc_contract_viewer
            .subscribe::<T>(self.mpc_contract_id.clone(), &method_name)
            .await;

        loop {
            match subscription.latest() {
                Ok(latest) => {
                    if sender.send(latest.value).is_err() {
                        return Ok(()); // no receivers left
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        method_name,
                        err=?err,
                        "error reading contract state, waiting for next update"
                    );
                }
            }
            subscription.changed().await?; // channel closed = fatal
        }
    }
}

impl MpcContractStateViewer {
    pub fn new(
        mpc_contract_id: near_account_id::AccountId,
        mpc_contract_viewer: ChainGateway,
    ) -> Self {
        Self {
            mpc_contract_id,
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
        let args = ChainGetPendingSignatureRequestArgs {
            request: chain_signature_request.clone(),
        };
        let call_result = self
            .mpc_contract_viewer
            .view(
                self.mpc_contract_id.clone(),
                contract_interface::method_names::GET_PENDING_REQUEST,
                &args,
            )
            .await
            .context("failed to query for pending request")?;
        Ok(call_result.value)
    }
    pub(crate) async fn get_pending_ckd_request(
        &self,
        chain_ckd_request: &ChainCKDRequest,
    ) -> anyhow::Result<Option<YieldIndex>> {
        let args = ChainGetPendingCKDRequestArgs {
            request: chain_ckd_request.clone(),
        };

        let call_result = self
            .mpc_contract_viewer
            .view(
                self.mpc_contract_id.clone(),
                contract_interface::method_names::GET_PENDING_CKD_REQUEST,
                &args,
            )
            .await
            .context("failed to query for pending CKD request")?;

        Ok(call_result.value)
    }

    pub(crate) async fn get_pending_verify_foreign_tx_request(
        &self,
        chain_verify_foreign_tx_request: &ChainVerifyForeignTransactionRequest,
    ) -> anyhow::Result<Option<YieldIndex>> {
        let args = ChainGetPendingVerifyForeignTxRequestArgs {
            request: chain_verify_foreign_tx_request.clone(),
        };

        let call_result = self
            .mpc_contract_viewer
            .view(
                self.mpc_contract_id.clone(),
                contract_interface::method_names::GET_PENDING_VERIFY_FOREIGN_TX_REQUEST,
                &args,
            )
            .await
            .context("failed to query for pending verify foreign tx request")?;

        Ok(call_result.value)
    }

    pub(crate) async fn get_participant_attestation(
        &self,
        participant_tls_public_key: &contract_interface::types::Ed25519PublicKey,
    ) -> anyhow::Result<Option<contract_interface::types::VerifiedAttestation>> {
        let args = GetAttestationArgs {
            tls_public_key: participant_tls_public_key,
        };

        let call_result = self
            .mpc_contract_viewer
            .view(
                self.mpc_contract_id.clone(),
                contract_interface::method_names::GET_ATTESTATION,
                &args,
            )
            .await
            .context("failed to query for participant attestation")?;

        Ok(call_result.value)
    }

    pub(crate) async fn get_foreign_chain_policy(
        &self,
    ) -> anyhow::Result<contract_interface::types::ForeignChainPolicy> {
        let call_result = self
            .mpc_contract_viewer
            .view(
                self.mpc_contract_id.clone(),
                contract_interface::method_names::GET_FOREIGN_CHAIN_POLICY,
                &NoArgs {},
            )
            .await?;

        Ok(call_result.value)
    }

    pub(crate) async fn get_foreign_chain_policy_proposals(
        &self,
    ) -> anyhow::Result<contract_interface::types::ForeignChainPolicyVotes> {
        let call_result = self
            .mpc_contract_viewer
            .view(
                self.mpc_contract_id.clone(),
                contract_interface::method_names::GET_FOREIGN_CHAIN_POLICY_PROPOSALS,
                &NoArgs {},
            )
            .await?;

        Ok(call_result.value)
    }
}
