//! SchnorrCheetah (Nockchain) signature provider — FROST threshold Schnorr over
//! the Cheetah curve. Mirrors `providers/eddsa.rs` but over the generic
//! `threshold_signatures::frost::cheetah` ciphersuite (no off-the-shelf curve crate).

mod key_generation;
mod key_resharing;
mod sign;

use crate::config::{MpcConfig, ParticipantsConfig};
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::MpcTaskId;
use crate::providers::SignatureProvider;
use crate::storage::SignRequestStorage;
use crate::types::SignatureId;
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_node_config::ConfigFile;
use mpc_primitives::domain::DomainId;
use near_mpc_contract_interface::types::KeyEventId;
use std::collections::HashMap;
use std::sync::Arc;
use threshold_signatures::ReconstructionThreshold;
use threshold_signatures::frost::cheetah::{CheetahTip5, KeygenOutput};
use threshold_signatures::frost_core::keys::SigningShare;
use threshold_signatures::frost_core::{Signature, VerifyingKey};

#[derive(Clone)]
pub struct CheetahSignatureProvider {
    config: Arc<ConfigFile>,
    mpc_config: Arc<MpcConfig>,
    client: Arc<MeshNetworkClient>,
    sign_request_store: Arc<SignRequestStorage>,
    keyshares: HashMap<DomainId, KeygenOutput>,
}

impl CheetahSignatureProvider {
    pub fn new(
        config: Arc<ConfigFile>,
        mpc_config: Arc<MpcConfig>,
        client: Arc<MeshNetworkClient>,
        sign_request_store: Arc<SignRequestStorage>,
        keyshares: HashMap<DomainId, KeygenOutput>,
    ) -> Self {
        Self {
            config,
            mpc_config,
            client,
            sign_request_store,
            keyshares,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum CheetahTaskId {
    KeyGeneration { key_event: KeyEventId },
    KeyResharing { key_event: KeyEventId },
    Signature { id: SignatureId },
}

impl From<CheetahTaskId> for MpcTaskId {
    fn from(value: CheetahTaskId) -> Self {
        MpcTaskId::CheetahTaskId(value)
    }
}

impl SignatureProvider for CheetahSignatureProvider {
    type PublicKey = VerifyingKey<CheetahTip5>;
    type SecretShare = SigningShare<CheetahTip5>;
    type KeygenOutput = KeygenOutput;
    type Signature = Signature<CheetahTip5>;
    type TaskId = CheetahTaskId;

    async fn make_signature(
        &self,
        id: SignatureId,
    ) -> anyhow::Result<(Self::Signature, Self::PublicKey)> {
        self.make_signature_leader(id).await
    }

    async fn run_key_generation_client(
        threshold: ReconstructionThreshold,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        Self::run_key_generation_client_internal(threshold, channel).await
    }

    async fn run_key_resharing_client(
        new_threshold: ReconstructionThreshold,
        key_share: Option<Self::SecretShare>,
        public_key: Self::PublicKey,
        old_participants: &ParticipantsConfig,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        Self::run_key_resharing_client_internal(
            new_threshold,
            key_share,
            public_key,
            old_participants,
            channel,
        )
        .await
    }

    async fn process_channel(&self, channel: NetworkTaskChannel) -> anyhow::Result<()> {
        match channel.task_id() {
            MpcTaskId::CheetahTaskId(task) => match task {
                CheetahTaskId::KeyGeneration { .. } => {
                    anyhow::bail!("Key generation rejected in normal node operation");
                }
                CheetahTaskId::KeyResharing { .. } => {
                    anyhow::bail!("Key resharing rejected in normal node operation");
                }
                CheetahTaskId::Signature { id } => {
                    self.make_signature_follower(channel, id).await?;
                }
            },
            _ => anyhow::bail!(
                "cheetah task handler: received unexpected task id: {:?}",
                channel.task_id()
            ),
        }

        Ok(())
    }

    async fn spawn_background_tasks(self: Arc<Self>) -> anyhow::Result<()> {
        Ok(())
    }
}
