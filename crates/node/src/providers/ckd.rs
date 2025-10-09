mod key_generation;
mod key_resharing;
mod sign;

use std::{collections::HashMap, sync::Arc};

use anyhow::Context;
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_contract::primitives::{domain::DomainId, key_state::KeyEventId};
use threshold_signatures::confidential_key_derivation::{
    ElementG1, KeygenOutput, SigningShare, VerifyingKey,
};

use crate::{
    config::{ConfigFile, MpcConfig, ParticipantsConfig},
    network::{MeshNetworkClient, NetworkTaskChannel},
    primitives::MpcTaskId,
    providers::{PublicKeyConversion, SignatureProvider},
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
    keyshares: HashMap<DomainId, KeygenOutput>,
}

impl CKDProvider {
    pub fn new(
        config: Arc<ConfigFile>,
        mpc_config: Arc<MpcConfig>,
        client: Arc<MeshNetworkClient>,
        ckd_request_store: Arc<CKDRequestStorage>,
        keyshares: HashMap<DomainId, KeygenOutput>,
    ) -> Self {
        Self {
            config,
            mpc_config,
            client,
            ckd_request_store,
            keyshares,
        }
    }
}

impl SignatureProvider for CKDProvider {
    type PublicKey = VerifyingKey;
    type SecretShare = SigningShare;
    type KeygenOutput = KeygenOutput;
    type Signature = (ElementG1, ElementG1);
    type TaskId = CKDTaskId;

    async fn make_signature(
        self: Arc<Self>,
        id: SignatureId,
    ) -> anyhow::Result<(Self::Signature, Self::PublicKey)> {
        self.make_ckd_leader(id).await
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

impl PublicKeyConversion for VerifyingKey {
    #[cfg(test)]
    fn to_near_sdk_public_key(&self) -> anyhow::Result<near_sdk::PublicKey> {
        let data = self.serialize()?;
        let data: [u8; 32] = data
            .try_into()
            .or_else(|_| anyhow::bail!("Serialized public key is not 32 bytes."))?;

        near_sdk::PublicKey::from_parts(near_sdk::CurveType::ED25519, data.to_vec())
            .context("Infallible.")
    }

    fn from_near_sdk_public_key(public_key: &near_sdk::PublicKey) -> anyhow::Result<Self> {
        let key_bytes = public_key.as_bytes();

        // Skip first byte as it is reserved as an identifier for the curve type.
        let key_data: [u8; 32] = key_bytes[1..]
            .try_into()
            .context("Invariant broken, public key must 32 bytes.")?;

        VerifyingKey::deserialize(&key_data)
            .context("Failed to convert SDK public key to ed25519_dalek::VerifyingKey")
    }
}
