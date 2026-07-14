mod sign;

use crate::config::ParticipantsConfig;
use crate::network::NetworkTaskChannel;
use crate::primitives::{MpcTaskId, UniqueId};
use crate::providers::{EcdsaSignatureProvider, SignatureProvider};
use crate::storage::VerifyForeignTransactionRequestStorage;
use crate::types::VerifyForeignTxId;
use borsh::{BorshDeserialize, BorshSerialize};
use foreign_chain_inspector::abstract_chain::inspector::AbstractInspector;
use foreign_chain_inspector::aptos::inspector::AptosInspector;
use foreign_chain_inspector::arbitrum::inspector::ArbitrumInspector;
use foreign_chain_inspector::base::inspector::BaseInspector;
use foreign_chain_inspector::bitcoin::inspector::BitcoinInspector;
use foreign_chain_inspector::bnb::inspector::BnbInspector;
use foreign_chain_inspector::http_client::HttpClient;
use foreign_chain_inspector::hyperevm::inspector::HyperEvmInspector;
use foreign_chain_inspector::polygon::inspector::PolygonInspector;
use foreign_chain_inspector::starknet::inspector::StarknetInspector;
use foreign_chain_inspector::sui::inspector::SuiInspector;
use foreign_chain_inspector::{FanOut, RpcAuthentication};
use foreign_chain_rpc_auth::auth_config_to_rpc_auth;
use foreign_chain_rpc_interfaces::aptos::ReqwestAptosClient;
use foreign_chain_rpc_interfaces::sui::GrpcSuiClient;
use mpc_node_config::{ConfigFile, ForeignChainConfig, ForeignChainsConfig};
use near_mpc_contract_interface::types as dtos;
use std::sync::Arc;
use std::time::Duration;
use threshold_signatures::ReconstructionThreshold;
use threshold_signatures::ecdsa::{KeygenOutput, Signature};
use threshold_signatures::frost_secp256k1::VerifyingKey;
use threshold_signatures::frost_secp256k1::keys::SigningShare;

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
    pub aptos: Option<FanOut<AptosInspector<ReqwestAptosClient>>>,
    pub sui: Option<FanOut<SuiInspector<GrpcSuiClient>>>,
}

impl ForeignChainInspectors<HttpClient> {
    fn build(config: &ForeignChainsConfig) -> anyhow::Result<Self> {
        fn build_fanout<I>(
            chain_config: Option<&ForeignChainConfig>,
            new_inspector: impl Fn(String, RpcAuthentication, Duration) -> anyhow::Result<I>,
        ) -> anyhow::Result<Option<FanOut<I>>> {
            let Some(c) = chain_config else {
                return Ok(None);
            };
            let timeout = Duration::from_secs(c.timeout_sec.get());
            let inspectors = c.providers.try_map_to_vec(|_, p| {
                // `Path`/`Query` auth is substituted into `url`; `Header` auth is returned
                // as `RpcAuthentication::CustomHeader` for the client to install.
                let mut url = p.rpc_url.clone();
                let rpc_auth = auth_config_to_rpc_auth(p.auth.clone(), &mut url)?;
                new_inspector(url, rpc_auth, timeout)
            })?;
            Ok(Some(FanOut::new(inspectors)))
        }

        /// Adapts an inspector constructor over a jsonrpsee [`HttpClient`] to `build_fanout`'s
        /// closure shape. The timeout is unused: the jsonrpsee chains rely on the inspection
        /// deadline in the signing flow, as they did before this adapter existed.
        fn with_http_client<I>(
            new_inspector: impl Fn(HttpClient) -> I,
        ) -> impl Fn(String, RpcAuthentication, Duration) -> anyhow::Result<I> {
            move |url, rpc_auth, _timeout| {
                let client = foreign_chain_inspector::build_http_client(url, rpc_auth)?;
                Ok(new_inspector(client))
            }
        }

        fn new_sui_inspector(
            url: String,
            rpc_auth: RpcAuthentication,
            timeout: Duration,
        ) -> anyhow::Result<SuiInspector<GrpcSuiClient>> {
            let auth_header = match rpc_auth {
                RpcAuthentication::KeyInUrl => None,
                RpcAuthentication::CustomHeader {
                    header_name,
                    header_value,
                } => Some((header_name, header_value)),
            };
            let client = GrpcSuiClient::new(url, auth_header, timeout)
                .map_err(|e| anyhow::anyhow!("failed to build the Sui gRPC client: {e}"))?;
            Ok(SuiInspector::new(client))
        }

        fn new_aptos_inspector(
            url: String,
            rpc_auth: RpcAuthentication,
            timeout: Duration,
        ) -> anyhow::Result<AptosInspector<ReqwestAptosClient>> {
            let auth_header = match rpc_auth {
                RpcAuthentication::KeyInUrl => None,
                RpcAuthentication::CustomHeader {
                    header_name,
                    header_value,
                } => Some((header_name, header_value)),
            };
            Ok(AptosInspector::new(ReqwestAptosClient::new(
                url,
                auth_header,
                timeout,
            )))
        }

        Ok(Self {
            bitcoin: build_fanout(
                config.bitcoin.as_ref(),
                with_http_client(BitcoinInspector::new),
            )?,
            abstract_chain: build_fanout(
                config.abstract_chain.as_ref(),
                with_http_client(AbstractInspector::new),
            )?,
            base: build_fanout(config.base.as_ref(), with_http_client(BaseInspector::new))?,
            bnb: build_fanout(config.bnb.as_ref(), with_http_client(BnbInspector::new))?,
            starknet: build_fanout(
                config.starknet.as_ref(),
                with_http_client(StarknetInspector::new),
            )?,
            arbitrum: build_fanout(
                config.arbitrum.as_ref(),
                with_http_client(ArbitrumInspector::new),
            )?,
            hyper_evm: build_fanout(
                config.hyper_evm.as_ref(),
                with_http_client(HyperEvmInspector::new),
            )?,
            polygon: build_fanout(
                config.polygon.as_ref(),
                with_http_client(PolygonInspector::new),
            )?,
            aptos: build_fanout(config.aptos.as_ref(), new_aptos_inspector)?,
            sui: build_fanout(config.sui.as_ref(), new_sui_inspector)?,
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
        _threshold: ReconstructionThreshold,
        _channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        anyhow::bail!(
            "this method is never called, as we are re-using the ecdsa signature provider"
        )
    }

    async fn run_key_resharing_client(
        _new_threshold: ReconstructionThreshold,
        _old_threshold: ReconstructionThreshold,
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
