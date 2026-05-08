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
use mpc_node_config::{ConfigFile, ForeignChainsConfig};
use near_mpc_bounded_collections::NonEmptyVec;
use near_mpc_contract_interface::types as dtos;
use std::sync::Arc;
use threshold_signatures::ecdsa::{KeygenOutput, Signature};
use threshold_signatures::frost_secp256k1::keys::SigningShare;
use threshold_signatures::frost_secp256k1::VerifyingKey;
use threshold_signatures::ReconstructionLowerBound;

pub(crate) struct ForeignChainInspectors<Client> {
    pub bitcoin: Option<BitcoinInspector<Client>>,
    pub abstract_chain: Option<AbstractInspector<Client>>,
    pub bnb: Option<BnbInspector<Client>>,
    pub starknet: Option<StarknetInspector<Client>>,
    pub base: Option<BaseInspector<Client>>,
    pub arbitrum: Option<ArbitrumInspector<Client>>,
    pub hyper_evm: Option<HyperEvmInspector<Client>>,
    pub polygon: Option<PolygonInspector<Client>>,
}

impl ForeignChainInspectors<HttpClient> {
    fn build(config: &ForeignChainsConfig) -> anyhow::Result<Self> {
        // using a macro because the chain config and inspector types differ per chain
        macro_rules! build_inspector {
            ($chain_config:expr, $Inspector:ident) => {
                match $chain_config {
                    Some(c) => {
                        let clients = c
                            .providers
                            .values()
                            .map(|p| {
                                let mut url = p.rpc_url.clone();
                                let rpc_auth = auth_config_to_rpc_auth(p.auth.clone(), &mut url)?;
                                Ok(foreign_chain_inspector::build_http_client(url, rpc_auth)?)
                            })
                            .collect::<anyhow::Result<Vec<_>>>()?;
                        // ForeignChainConfig.providers is itself a NonEmptyBTreeMap, so this
                        // conversion can never fail.
                        let clients =
                            NonEmptyVec::from_vec(clients).expect("provider config is non-empty");
                        Some($Inspector::new(clients))
                    }
                    None => None,
                }
            };
        }

        Ok(Self {
            bitcoin: build_inspector!(&config.bitcoin, BitcoinInspector),
            abstract_chain: build_inspector!(&config.abstract_chain, AbstractInspector),
            base: build_inspector!(&config.base, BaseInspector),
            bnb: build_inspector!(&config.bnb, BnbInspector),
            starknet: build_inspector!(&config.starknet, StarknetInspector),
            arbitrum: build_inspector!(&config.arbitrum, ArbitrumInspector),
            hyper_evm: build_inspector!(&config.hyper_evm, HyperEvmInspector),
            polygon: build_inspector!(&config.polygon, PolygonInspector),
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
