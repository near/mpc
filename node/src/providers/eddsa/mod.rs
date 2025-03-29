mod key_generation;
mod key_resharing;
mod sign;

use crate::config::{ConfigFile, MpcConfig, ParticipantsConfig};
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::MpcTaskId;
use crate::providers::SignatureProvider;
use crate::sign_request::{SignRequestStorage, SignatureId};
use borsh::{BorshDeserialize, BorshSerialize};
use cait_sith::eddsa::KeygenOutput;
use frost_ed25519::keys::{PublicKeyPackage, SigningShare};
use frost_ed25519::{Signature, VerifyingKey};
use mpc_contract::primitives::domain::DomainId;
use mpc_contract::primitives::key_state::KeyEventId;
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::Arc;

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
    type PublicKey = PublicKeyPackage;
    type SecretShare = SigningShare;
    type KeygenOutput = KeygenOutput;
    type SignatureOutput = (Signature, VerifyingKey);
    type TaskId = EddsaTaskId;

    async fn make_signature(
        self: Arc<Self>,
        id: SignatureId,
    ) -> anyhow::Result<Self::SignatureOutput> {
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
        public_key: PublicKeyPackage,
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

pub fn convert_to_near_pubkey(
    public_key_package: &PublicKeyPackage,
) -> anyhow::Result<near_crypto::PublicKey> {
    let data = public_key_package.verifying_key().serialize()?;
    let data: [u8; 32] = data
        .try_into()
        .or_else(|_| anyhow::bail!("Serialized public key is not 32 bytes."))?;
    Ok(near_crypto::PublicKey::ED25519(
        near_crypto::ED25519PublicKey::from(data),
    ))
}

pub fn convert_from_near_pubkey(key: near_crypto::PublicKey) -> anyhow::Result<PublicKeyPackage> {
    match key {
        near_crypto::PublicKey::ED25519(key) => {
            let verifying_key = VerifyingKey::deserialize(key.0.as_slice())?;
            Ok(PublicKeyPackage::new(BTreeMap::new(), verifying_key))
        }
        _ => anyhow::bail!("Unsupported public key type"),
    }
}

pub fn convert_from_sdk_pubkey(
    public_key: &near_sdk::PublicKey,
) -> anyhow::Result<PublicKeyPackage> {
    let near_crypto = near_crypto::PublicKey::from_str(&String::from(public_key))?;
    convert_from_near_pubkey(near_crypto)
}

#[test]
fn check_pubkey_conversion_to_sdk() -> anyhow::Result<()> {
    use crate::tests::TestGenerators;
    let x = TestGenerators::new(4, 3)
        .make_eddsa_keygens()
        .values()
        .next()
        .unwrap()
        .clone();
    convert_to_near_pubkey(&x.public_key_package)?;
    Ok(())
}

#[test]
fn check_pubkey_conversion_from_sdk() -> anyhow::Result<()> {
    let near_sdk =
        near_sdk::PublicKey::from_str("ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp")?;
    let _ = convert_from_sdk_pubkey(&near_sdk)?;
    Ok(())
}
