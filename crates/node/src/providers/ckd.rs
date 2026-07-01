mod key_generation;
mod key_resharing;
mod sign;

use std::{collections::HashMap, sync::Arc};

use borsh::{BorshDeserialize, BorshSerialize};
use mpc_primitives::ReconstructionThreshold;
use mpc_primitives::domain::DomainId;
use near_mpc_contract_interface::types::KeyEventId;
use threshold_signatures::confidential_key_derivation::{
    ElementG1, KeygenOutput, SigningShare, VerifyingKey,
};

use threshold_signatures::ReconstructionThreshold as TSReconstructionThreshold;

use mpc_node_config::ConfigFile;

use crate::{
    config::{MpcConfig, ParticipantsConfig},
    network::{MeshNetworkClient, NetworkTaskChannel},
    primitives::MpcTaskId,
    providers::SignatureProvider,
    storage::CKDRequestStorage,
    types::{CKDId, SignatureId},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum CKDTaskId {
    KeyGeneration { key_event: KeyEventId },
    KeyResharing { key_event: KeyEventId },
    Ckd { id: CKDId },
}

impl From<CKDTaskId> for MpcTaskId {
    fn from(value: CKDTaskId) -> Self {
        MpcTaskId::CKDTaskId(value)
    }
}

#[derive(Clone)]
pub struct CKDProvider {
    config: Arc<ConfigFile>,
    mpc_config: Arc<MpcConfig>,
    client: Arc<MeshNetworkClient>,
    ckd_request_store: Arc<CKDRequestStorage>,
    per_domain_data: HashMap<DomainId, PerDomainData>,
}

#[derive(Clone)]
pub(super) struct PerDomainData {
    pub keyshare: KeygenOutput,
    /// Per-domain reconstruction threshold `t`, used as the CKD threshold.
    pub reconstruction_threshold: ReconstructionThreshold,
}

impl CKDProvider {
    pub fn new(
        config: Arc<ConfigFile>,
        mpc_config: Arc<MpcConfig>,
        client: Arc<MeshNetworkClient>,
        ckd_request_store: Arc<CKDRequestStorage>,
        keyshares: HashMap<DomainId, (KeygenOutput, ReconstructionThreshold)>,
    ) -> Self {
        let per_domain_data = keyshares
            .into_iter()
            .map(|(domain_id, (keyshare, reconstruction_threshold))| {
                (
                    domain_id,
                    PerDomainData {
                        keyshare,
                        reconstruction_threshold,
                    },
                )
            })
            .collect();
        Self {
            config,
            mpc_config,
            client,
            ckd_request_store,
            per_domain_data,
        }
    }

    pub(super) fn domain_data(&self, domain_id: DomainId) -> anyhow::Result<PerDomainData> {
        self.per_domain_data
            .get(&domain_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No keyshare for domain {:?}", domain_id))
    }
}

impl SignatureProvider for CKDProvider {
    type PublicKey = VerifyingKey;
    type SecretShare = SigningShare;
    type KeygenOutput = KeygenOutput;
    type Signature = (ElementG1, ElementG1);
    type TaskId = CKDTaskId;

    async fn make_signature(
        &self,
        id: SignatureId,
    ) -> anyhow::Result<(Self::Signature, Self::PublicKey)> {
        self.make_ckd_leader(id).await
    }

    async fn run_key_generation_client(
        threshold: TSReconstructionThreshold,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        Self::run_key_generation_client_internal(threshold, channel).await
    }

    async fn run_key_resharing_client(
        new_threshold: TSReconstructionThreshold,
        old_threshold: TSReconstructionThreshold,
        key_share: Option<SigningShare>,
        public_key: VerifyingKey,
        old_participants: &ParticipantsConfig,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        Self::run_key_resharing_client_internal(
            new_threshold,
            old_threshold,
            key_share,
            public_key,
            old_participants,
            channel,
        )
        .await
    }

    async fn process_channel(&self, channel: NetworkTaskChannel) -> anyhow::Result<()> {
        match channel.task_id() {
            MpcTaskId::CKDTaskId(task) => match task {
                CKDTaskId::KeyGeneration { .. } => {
                    anyhow::bail!("Key generation rejected in normal node operation");
                }
                CKDTaskId::KeyResharing { .. } => {
                    anyhow::bail!("Key resharing rejected in normal node operation");
                }
                CKDTaskId::Ckd { id } => {
                    self.make_ckd_follower(channel, id).await?;
                }
            },
            _ => anyhow::bail!(
                "ckd task handler: received unexpected task id: {:?}",
                channel.task_id()
            ),
        }

        Ok(())
    }

    async fn spawn_background_tasks(self: Arc<Self>) -> anyhow::Result<()> {
        Ok(())
    }
}
