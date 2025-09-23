mod kdf;
mod key_generation;
mod key_resharing;
mod sign;

use crate::config::{ConfigFile, MpcConfig, ParticipantsConfig};
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::MpcTaskId;
use crate::providers::SignatureProvider;
use crate::storage::SignRequestStorage;
use crate::types::SignatureId;
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_contract::primitives::domain::DomainId;
use mpc_contract::primitives::key_state::KeyEventId;
use std::collections::HashMap;
use std::sync::Arc;
use threshold_signatures::eddsa::KeygenOutput;
use threshold_signatures::frost_ed25519::keys::SigningShare;
use threshold_signatures::frost_ed25519::{Signature, VerifyingKey};

#[derive(Clone)]
pub struct EddsaSignatureProvider {
    config: Arc<ConfigFile>,
    mpc_config: Arc<MpcConfig>,
    client: Arc<MeshNetworkClient>,
    sign_request_store: Arc<SignRequestStorage>,
    keyshares: HashMap<DomainId, KeygenOutput>,
}

impl EddsaSignatureProvider {
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
pub enum EddsaTaskId {
    KeyGeneration { key_event: KeyEventId },
    KeyResharing { key_event: KeyEventId },
    Signature { id: SignatureId },
}

impl From<EddsaTaskId> for MpcTaskId {
    fn from(value: EddsaTaskId) -> Self {
        MpcTaskId::EddsaTaskId(value)
    }
}

impl SignatureProvider for EddsaSignatureProvider {
    type PublicKey = VerifyingKey;
    type SecretShare = SigningShare;
    type KeygenOutput = KeygenOutput;
    type Signature = Signature;
    type TaskId = EddsaTaskId;

    async fn make_signature(
        self: Arc<Self>,
        id: SignatureId,
    ) -> anyhow::Result<(Self::Signature, Self::PublicKey)> {
        self.make_signature_leader(id).await
    }

    async fn run_key_generation_client(
        threshold: usize,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        Self::run_key_generation_client_internal(threshold, channel).await
    }

    async fn run_key_resharing_client(
        new_threshold: usize,
        key_share: Option<SigningShare>,
        public_key: VerifyingKey,
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

    async fn process_channel(self: Arc<Self>, channel: NetworkTaskChannel) -> anyhow::Result<()> {
        match channel.task_id() {
            MpcTaskId::EddsaTaskId(task) => match task {
                EddsaTaskId::KeyGeneration { .. } => {
                    anyhow::bail!("Key generation rejected in normal node operation");
                }
                EddsaTaskId::KeyResharing { .. } => {
                    anyhow::bail!("Key resharing rejected in normal node operation");
                }
                EddsaTaskId::Signature { id } => {
                    self.make_signature_follower(channel, id).await?;
                }
            },
            _ => anyhow::bail!(
                "eddsa task handler: received unexpected task id: {:?}",
                channel.task_id()
            ),
        }

        Ok(())
    }

    async fn spawn_background_tasks(self: Arc<Self>) -> anyhow::Result<()> {
        Ok(())
    }
}
