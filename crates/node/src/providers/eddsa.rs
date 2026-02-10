mod key_generation;
mod key_resharing;
mod sign;

use crate::config::{ConfigFile, MpcConfig, ParticipantsConfig};
use crate::metrics::tokio_task_metrics::EDDSA_TASK_MONITORS;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::MpcTaskId;
use crate::providers::{PublicKeyConversion, SignatureProvider};
use crate::storage::SignRequestStorage;
use crate::types::SignatureId;
use anyhow::Context;
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_contract::primitives::domain::DomainId;
use mpc_contract::primitives::key_state::KeyEventId;
use std::collections::HashMap;
use std::sync::Arc;
use threshold_signatures::frost::eddsa::KeygenOutput;
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
        &self,
        id: SignatureId,
    ) -> anyhow::Result<(Self::Signature, Self::PublicKey)> {
        EDDSA_TASK_MONITORS
            .make_signature_leader
            .instrument(self.make_signature_leader(id))
            .await
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

    async fn process_channel(&self, channel: NetworkTaskChannel) -> anyhow::Result<()> {
        match channel.task_id() {
            MpcTaskId::EddsaTaskId(task) => match task {
                EddsaTaskId::KeyGeneration { .. } => {
                    anyhow::bail!("Key generation rejected in normal node operation");
                }
                EddsaTaskId::KeyResharing { .. } => {
                    anyhow::bail!("Key resharing rejected in normal node operation");
                }
                EddsaTaskId::Signature { id } => {
                    EDDSA_TASK_MONITORS
                        .make_signature_follower
                        .instrument(self.make_signature_follower(channel, id))
                        .await?;
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
impl PublicKeyConversion for ed25519_dalek::VerifyingKey {
    #[cfg(test)]
    fn to_near_sdk_public_key(&self) -> anyhow::Result<near_sdk::PublicKey> {
        let data: [u8; 32] = self.to_bytes();
        near_sdk::PublicKey::from_parts(near_sdk::CurveType::ED25519, data.to_vec())
            .context("Infallible.")
    }

    fn from_near_sdk_public_key(public_key: &near_sdk::PublicKey) -> anyhow::Result<Self> {
        let key_bytes = public_key.as_bytes();

        // Skip first byte as it is reserved as an identifier for the curve type.
        let key_data: [u8; 32] = key_bytes[1..]
            .try_into()
            .context("Invariant broken, public key must 32 bytes.")?;

        ed25519_dalek::VerifyingKey::from_bytes(&key_data)
            .context("Failed to convert SDK public key to ed25519_dalek::VerifyingKey")
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng as _;
    use threshold_signatures::frost_ed25519::VerifyingKey;

    use crate::{
        providers::PublicKeyConversion,
        trait_extensions::convert_to_contract_dto::IntoContractInterfaceType,
    };
    #[test]
    fn check_pubkey_conversion_to_sdk() -> anyhow::Result<()> {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        use threshold_signatures::test_utils::TestGenerators;
        let x = TestGenerators::new(4, 3.into())
            .make_eddsa_keygens(&mut rng)
            .values()
            .next()
            .unwrap()
            .clone();
        x.public_key.into_contract_interface_type();
        Ok(())
    }

    #[test]
    fn check_pubkey_conversion_from_sdk() -> anyhow::Result<()> {
        use std::str::FromStr;
        let near_sdk =
            near_sdk::PublicKey::from_str("ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp")?;
        let _ = VerifyingKey::from_near_sdk_public_key(&near_sdk)?;
        Ok(())
    }
}
