mod sign;

use crate::config::{auth_config_to_rpc_auth, ParticipantsConfig};
use crate::network::NetworkTaskChannel;
use crate::primitives::{MpcTaskId, UniqueId};
use crate::providers::{EcdsaSignatureProvider, SignatureProvider};
use crate::storage::VerifyForeignTransactionRequestStorage;
use crate::types::VerifyForeignTxId;
use borsh::{BorshDeserialize, BorshSerialize};
use foreign_chain_inspector::http_client::HttpClient;
use mpc_node_config::{ConfigFile, ForeignChainsConfig};
use near_mpc_contract_interface::types as dtos;
use std::sync::Arc;
use threshold_signatures::ecdsa::{KeygenOutput, Signature};
use threshold_signatures::frost_secp256k1::keys::SigningShare;
use threshold_signatures::frost_secp256k1::VerifyingKey;
use threshold_signatures::ReconstructionLowerBound;

/// Pre-built HTTP clients for each foreign chain, keyed in provider config order.
///
/// Built once at startup so that request handling only needs to select an index
/// instead of re-parsing config and constructing clients on every call.
pub(crate) struct ForeignChainClients {
    pub bitcoin: Vec<HttpClient>,
    pub abstract_chain: Vec<HttpClient>,
    pub bnb: Vec<HttpClient>,
    pub starknet: Vec<HttpClient>,
}

impl ForeignChainClients {
    fn build(config: &ForeignChainsConfig) -> anyhow::Result<Self> {
        macro_rules! build_clients {
            ($chain_config:expr) => {
                match $chain_config {
                    Some(c) => c
                        .providers
                        .values()
                        .map(|p| {
                            let mut url = p.rpc_url.clone();
                            let rpc_auth = auth_config_to_rpc_auth(p.auth.clone(), &mut url)?;
                            foreign_chain_inspector::build_http_client(url, rpc_auth)
                                .map_err(anyhow::Error::from)
                        })
                        .collect::<anyhow::Result<Vec<_>>>()?,
                    None => vec![],
                }
            };
        }

        Ok(Self {
            bitcoin: build_clients!(&config.bitcoin),
            abstract_chain: build_clients!(&config.abstract_chain),
            bnb: build_clients!(&config.bnb),
            starknet: build_clients!(&config.starknet),
        })
    }
}

pub struct VerifyForeignTxProvider<ForeignChainPolicyReader> {
    config: Arc<ConfigFile>,
    clients: ForeignChainClients,
    foreign_chain_policy_reader: ForeignChainPolicyReader,
    verify_foreign_tx_request_store: Arc<VerifyForeignTransactionRequestStorage>,
    ecdsa_signature_provider: Arc<EcdsaSignatureProvider>,
}

impl<ForeignChainPolicyReader> VerifyForeignTxProvider<ForeignChainPolicyReader> {
    pub fn new(
        config: Arc<ConfigFile>,
        foreign_chain_policy_reader: ForeignChainPolicyReader,
        verify_foreign_tx_request_store: Arc<VerifyForeignTransactionRequestStorage>,
        ecdsa_signature_provider: Arc<EcdsaSignatureProvider>,
    ) -> anyhow::Result<Self> {
        let clients = ForeignChainClients::build(&config.foreign_chains)?;
        Ok(Self {
            config,
            clients,
            foreign_chain_policy_reader,
            verify_foreign_tx_request_store,
            ecdsa_signature_provider,
        })
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

impl<ForeignChainPolicyReader> SignatureProvider
    for VerifyForeignTxProvider<ForeignChainPolicyReader>
where
    ForeignChainPolicyReader: crate::indexer::ReadForeignChainPolicy,
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
        _threshold: ReconstructionLowerBound,
        _channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        anyhow::bail!(
            "this method is never called, as we are re-using the ecdsa signature provider"
        )
    }

    async fn run_key_resharing_client(
        _new_threshold: ReconstructionLowerBound,
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
