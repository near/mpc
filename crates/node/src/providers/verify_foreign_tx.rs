mod sign;

use crate::config::{auth_config_to_rpc_auth, ParticipantsConfig};
use crate::network::NetworkTaskChannel;
use crate::primitives::{MpcTaskId, UniqueId};
use crate::providers::{EcdsaSignatureProvider, SignatureProvider};
use crate::storage::VerifyForeignTransactionRequestStorage;
use crate::types::VerifyForeignTxId;
use borsh::{BorshDeserialize, BorshSerialize};
use foreign_chain_inspector::abstract_chain::inspector::AbstractInspector;
use foreign_chain_inspector::arbitrum::inspector::ArbitrumInspector;
use foreign_chain_inspector::base::inspector::BaseInspector;
use foreign_chain_inspector::bitcoin::inspector::BitcoinInspector;
use foreign_chain_inspector::bnb::inspector::BnbInspector;
use foreign_chain_inspector::http_client::HttpClient;
use foreign_chain_inspector::hyperevm::inspector::HyperEvmInspector;
use foreign_chain_inspector::polygon::inspector::PolygonInspector;
use foreign_chain_inspector::starknet::inspector::StarknetInspector;
use foreign_chain_inspector::FanOut;
use mpc_node_config::{ConfigFile, ForeignChainConfig, ForeignChainsConfig};
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
    pub bitcoin: Option<FanOut<BitcoinInspector<Client>>>,
    pub abstract_chain: Option<FanOut<AbstractInspector<Client>>>,
    pub bnb: Option<FanOut<BnbInspector<Client>>>,
    pub starknet: Option<FanOut<StarknetInspector<Client>>>,
    pub base: Option<FanOut<BaseInspector<Client>>>,
    pub arbitrum: Option<FanOut<ArbitrumInspector<Client>>>,
    pub hyper_evm: Option<FanOut<HyperEvmInspector<Client>>>,
    pub polygon: Option<FanOut<PolygonInspector<Client>>>,
}

impl ForeignChainInspectors<HttpClient> {
    fn build(config: &ForeignChainsConfig) -> anyhow::Result<Self> {
        fn build_fanout<I>(
            chain_config: Option<&ForeignChainConfig>,
            new_inspector: impl Fn(HttpClient) -> I,
        ) -> anyhow::Result<Option<FanOut<I>>> {
            let Some(c) = chain_config else {
                return Ok(None);
            };
            let inspectors = c.providers.try_map_to_vec(|_, p| {
                let mut url = p.rpc_url.clone();
                let rpc_auth = auth_config_to_rpc_auth(p.auth.clone(), &mut url)?;
                let client = foreign_chain_inspector::build_http_client(url, rpc_auth)?;
                Ok::<_, anyhow::Error>(new_inspector(client))
            })?;
            Ok(Some(FanOut::new(inspectors)))
        }

        Ok(Self {
            bitcoin: build_fanout(config.bitcoin.as_ref(), BitcoinInspector::new)?,
            abstract_chain: build_fanout(config.abstract_chain.as_ref(), AbstractInspector::new)?,
            base: build_fanout(config.base.as_ref(), BaseInspector::new)?,
            bnb: build_fanout(config.bnb.as_ref(), BnbInspector::new)?,
            starknet: build_fanout(config.starknet.as_ref(), StarknetInspector::new)?,
            arbitrum: build_fanout(config.arbitrum.as_ref(), ArbitrumInspector::new)?,
            hyper_evm: build_fanout(config.hyper_evm.as_ref(), HyperEvmInspector::new)?,
            polygon: build_fanout(config.polygon.as_ref(), PolygonInspector::new)?,
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
    ForeignChainPolicyReader: crate::indexer::ReadSupportedForeignChain,
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
