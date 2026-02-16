mod sign;

use crate::config::{ConfigFile, MpcConfig, ParticipantsConfig};
use crate::network::NetworkTaskChannel;
use crate::primitives::{MpcTaskId, UniqueId};
use crate::providers::{EcdsaSignatureProvider, SignatureProvider};
use crate::storage::VerifyForeignTransactionRequestStorage;
use crate::types::VerifyForeignTxId;
use borsh::{BorshDeserialize, BorshSerialize};
use contract_interface::types as dtos;
use std::sync::Arc;
use threshold_signatures::ecdsa::{KeygenOutput, Signature};
use threshold_signatures::frost_secp256k1::keys::SigningShare;
use threshold_signatures::frost_secp256k1::VerifyingKey;

pub struct VerifyForeignTxProvider<ForeignChainPolicyReader> {
    config: Arc<ConfigFile>,
    #[allow(dead_code)]
    foreign_chain_policy_reader: ForeignChainPolicyReader,
    // TODO(#2076): This field might become useful when domain separation is implemented
    #[allow(dead_code)]
    mpc_config: Arc<MpcConfig>,
    verify_foreign_tx_request_store: Arc<VerifyForeignTransactionRequestStorage>,
    ecdsa_signature_provider: Arc<EcdsaSignatureProvider>,
}

impl<ForeignChainPolicyReader> VerifyForeignTxProvider<ForeignChainPolicyReader> {
    pub fn new(
        config: Arc<ConfigFile>,
        foreign_chain_policy_reader: ForeignChainPolicyReader,
        mpc_config: Arc<MpcConfig>,
        verify_foreign_tx_request_store: Arc<VerifyForeignTransactionRequestStorage>,
        ecdsa_signature_provider: Arc<EcdsaSignatureProvider>,
    ) -> Self {
        Self {
            config,
            foreign_chain_policy_reader,
            mpc_config,
            verify_foreign_tx_request_store,
            ecdsa_signature_provider,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum VerifyForeignTxTaskId {
    VerifyForeignTx {
        id: VerifyForeignTxId,
        presignature_id: UniqueId,
    },
}

impl From<VerifyForeignTxTaskId> for MpcTaskId {
    fn from(val: VerifyForeignTxTaskId) -> Self {
        MpcTaskId::VerifyForeignTxTaskId(val)
    }
}

impl<ForeignChainPolicyReader: Send + Sync> SignatureProvider
    for VerifyForeignTxProvider<ForeignChainPolicyReader>
{
    type PublicKey = VerifyingKey;
    type SecretShare = SigningShare;
    type KeygenOutput = KeygenOutput;
    type Signature = (dtos::ForeignTxSignPayload, Signature);
    type TaskId = VerifyForeignTxTaskId;

    async fn make_signature(
        &self,
        id: VerifyForeignTxId,
    ) -> anyhow::Result<(Self::Signature, Self::PublicKey)> {
        self.make_verify_foreign_tx_leader(id).await
    }

    async fn run_key_generation_client(
        _threshold: usize,
        _channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        anyhow::bail!(
            "this method is never called, as we are re-using the ecdsa signature provider"
        )
    }

    async fn run_key_resharing_client(
        _new_threshold: usize,
        _key_share: Option<SigningShare>,
        _public_key: VerifyingKey,
        _old_participants: &ParticipantsConfig,
        _channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        anyhow::bail!(
            "this method is never called, as we are re-using the ecdsa signature provider"
        )
    }

    async fn process_channel(&self, channel: NetworkTaskChannel) -> anyhow::Result<()> {
        match channel.task_id() {
            MpcTaskId::VerifyForeignTxTaskId(task) => match task {
                VerifyForeignTxTaskId::VerifyForeignTx {
                    id,
                    presignature_id,
                } => {
                    self.make_verify_foreign_tx_follower(channel, id, presignature_id)
                        .await?;
                }
            },
            _ => anyhow::bail!(
                "verify_foreign_tx task handler: received unexpected task id: {:?}",
                channel.task_id()
            ),
        }

        Ok(())
    }

    async fn spawn_background_tasks(self: Arc<Self>) -> anyhow::Result<()> {
        Ok(())
    }
}
