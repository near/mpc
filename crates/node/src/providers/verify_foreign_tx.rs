mod sign;

use crate::config::{auth_config_to_rpc_auth, ParticipantsConfig};
use crate::network::NetworkTaskChannel;
use crate::primitives::{MpcTaskId, UniqueId};
use crate::providers::{EcdsaSignatureProvider, SignatureProvider};
use crate::storage::VerifyForeignTransactionRequestStorage;
use crate::types::VerifyForeignTxId;
use borsh::{BorshDeserialize, BorshSerialize};
use foreign_chain_inspector::abstract_chain::inspector::AbstractInspector;
use foreign_chain_inspector::bitcoin::inspector::BitcoinInspector;
use foreign_chain_inspector::bnb::inspector::BnbInspector;
use foreign_chain_inspector::http_client::HttpClient;
use foreign_chain_inspector::starknet::inspector::StarknetInspector;
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
pub(crate) struct ForeignChainInspectors<Client> {
    pub bitcoin: Vec<BitcoinInspector<Client>>,
    pub abstract_chain: Vec<AbstractInspector<Client>>,
    pub bnb: Vec<BnbInspector<Client>>,
    pub starknet: Vec<StarknetInspector<Client>>,
}

impl ForeignChainInspectors<HttpClient> {
    fn build(config: &ForeignChainsConfig) -> anyhow::Result<Self> {
        // using a macro because the chain config and inspector types differ per chain
        macro_rules! build_inspectors {
            ($chain_config:expr, $Inspector:ident) => {
                match $chain_config {
                    Some(c) => c
                        .providers
                        .values()
                        .map(|p| {
                            let mut url = p.rpc_url.clone();
                            let rpc_auth = auth_config_to_rpc_auth(p.auth.clone(), &mut url)?;
                            let client = foreign_chain_inspector::build_http_client(url, rpc_auth)?;
                            Ok($Inspector::new(client))
                        })
                        .collect::<anyhow::Result<Vec<_>>>()?,
                    None => vec![],
                }
            };
        }

        Ok(Self {
            bitcoin: build_inspectors!(&config.bitcoin, BitcoinInspector),
            abstract_chain: build_inspectors!(&config.abstract_chain, AbstractInspector),
            bnb: build_inspectors!(&config.bnb, BnbInspector),
            starknet: build_inspectors!(&config.starknet, StarknetInspector),
        })
    }
}

pub struct VerifyForeignTxProvider<ForeignChainPolicyReader> {
    config: Arc<ConfigFile>,
    inspectors: ForeignChainInspectors<HttpClient>,
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
        let inspectors = ForeignChainInspectors::build(&config.foreign_chains)?;
        Ok(Self {
            config,
            inspectors,
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
