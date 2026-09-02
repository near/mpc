mod sign;

use crate::foreign_chain_policy::{ForeignChainLeadersRefiner, SupportersByForeignChain};
use crate::metrics;
use crate::network::NetworkTaskChannel;
use crate::primitives::{MpcTaskId, UniqueId};
use crate::providers::EcdsaSignatureProvider;
use crate::storage::VerifyForeignTransactionRequestStorage;
use crate::types::VerifyForeignTxId;
use borsh::{BorshDeserialize, BorshSerialize};
use foreign_chain_inspector::FanOut;
use foreign_chain_inspector::abstract_chain::inspector::AbstractInspector;
use foreign_chain_inspector::adi::inspector::AdiInspector;
use foreign_chain_inspector::aptos::inspector::AptosInspector;
use foreign_chain_inspector::arbitrum::inspector::ArbitrumInspector;
use foreign_chain_inspector::avalanche::inspector::AvalancheInspector;
use foreign_chain_inspector::base::inspector::BaseInspector;
use foreign_chain_inspector::bitcoin::inspector::BitcoinInspector;
use foreign_chain_inspector::bnb::inspector::BnbInspector;
use foreign_chain_inspector::ethereum::inspector::EthereumInspector;
use foreign_chain_inspector::http_client::HttpClient;
use foreign_chain_inspector::hyperevm::inspector::HyperEvmInspector;
use foreign_chain_inspector::polygon::inspector::PolygonInspector;
use foreign_chain_inspector::starknet::inspector::StarknetInspector;
use foreign_chain_inspector::sui::inspector::SuiInspector;
use foreign_chain_inspector::{ProviderCallOutcome, ProviderFailure, RecordProviderCall};
use foreign_chain_rpc_factory::{build_http_client, resolve_provider_auth};
use foreign_chain_rpc_interfaces::aptos::ReqwestAptosClient;
use foreign_chain_rpc_interfaces::sui::GrpcSuiClient;
use mpc_node_config::{
    ConfigFile, ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig,
};
use mpc_primitives::ReconstructionThreshold;
use near_mpc_contract_interface::types::ProviderId;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// Pre-built HTTP clients for each foreign chain, one per configured provider and named by its
/// [`ProviderId`].
///
/// Built once at startup so that request handling fans out over ready clients instead of re-parsing
/// config and constructing them on every call.
pub(crate) struct ForeignChainInspectors<Client> {
    pub bitcoin: Option<FanOut<BitcoinInspector<Client>>>,
    pub ethereum: Option<FanOut<EthereumInspector<Client>>>,
    pub abstract_chain: Option<FanOut<AbstractInspector<Client>>>,
    pub bnb: Option<FanOut<BnbInspector<Client>>>,
    pub starknet: Option<FanOut<StarknetInspector<Client>>>,
    pub base: Option<FanOut<BaseInspector<Client>>>,
    pub arbitrum: Option<FanOut<ArbitrumInspector<Client>>>,
    pub hyper_evm: Option<FanOut<HyperEvmInspector<Client>>>,
    pub polygon: Option<FanOut<PolygonInspector<Client>>>,
    pub avalanche: Option<FanOut<AvalancheInspector<Client>>>,
    pub adi: Option<FanOut<AdiInspector<Client>>>,
    pub aptos: Option<FanOut<AptosInspector<ReqwestAptosClient>>>,
    pub sui: Option<FanOut<SuiInspector<GrpcSuiClient>>>,
}

/// Reports the verify fan-out's provider calls into [`crate::metrics`].
pub(crate) struct ProviderCallMetrics;

impl ProviderCallMetrics {
    fn declare(chain: &str, provider: &ProviderId) {
        metrics::MPC_FOREIGN_CHAIN_PROVIDER_INSPECTION_SECONDS
            .with_label_values(&[chain, &provider.0]);
        for kind in metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERROR_KINDS {
            metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERRORS_TOTAL.with_label_values(&[
                chain,
                &provider.0,
                kind,
            ]);
        }
    }
}

impl RecordProviderCall for ProviderCallMetrics {
    fn record(
        &self,
        chain: &str,
        provider: &ProviderId,
        elapsed: Duration,
        outcome: ProviderCallOutcome,
    ) {
        // An abandoned call's elapsed time measures whatever cut it off, not the provider.
        if outcome != ProviderCallOutcome::Abandoned {
            metrics::MPC_FOREIGN_CHAIN_PROVIDER_INSPECTION_SECONDS
                .with_label_values(&[chain, &provider.0])
                .observe(elapsed.as_secs_f64());
        }

        if let Some(kind) = error_kind(outcome) {
            metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERRORS_TOTAL
                .with_label_values(&[chain, &provider.0, kind])
                .inc();
        }
    }
}

/// The `kind` label for [`metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERRORS_TOTAL`], or [`None`] when the
/// provider is not at fault.
fn error_kind(outcome: ProviderCallOutcome) -> Option<&'static str> {
    match outcome {
        ProviderCallOutcome::Answered => None,
        ProviderCallOutcome::Failed(ProviderFailure::Unreachable) => {
            Some(metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERROR_TRANSIENT)
        }
        ProviderCallOutcome::Failed(ProviderFailure::Rejected | ProviderFailure::Malformed) => {
            Some(metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERROR_NON_TRANSIENT)
        }
        ProviderCallOutcome::Failed(ProviderFailure::TimedOut) | ProviderCallOutcome::Abandoned => {
            Some(metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERROR_TIMEOUT)
        }
    }
}

impl ForeignChainInspectors<HttpClient> {
    fn build(config: &ForeignChainsConfig) -> anyhow::Result<Self> {
        /// `chain` is the metric label for these providers.
        fn build_fanout<I>(
            chain: &'static str,
            chain_config: Option<&ForeignChainConfig>,
            new_inspector: impl Fn(&ForeignChainProviderConfig, Duration) -> anyhow::Result<I>,
        ) -> anyhow::Result<Option<FanOut<I>>> {
            let Some(c) = chain_config else {
                return Ok(None);
            };
            let timeout = Duration::from_secs(c.timeout_sec.get());
            let inspectors = c.providers.try_map_to_vec(|name, p| {
                let inspector = new_inspector(p, timeout)?;
                anyhow::Ok((ProviderId(name.as_str().to_owned()), inspector))
            })?;
            for (provider, _) in inspectors.iter() {
                ProviderCallMetrics::declare(chain, provider);
            }
            Ok(Some(
                FanOut::new(inspectors).measuring(chain, Arc::new(ProviderCallMetrics)),
            ))
        }

        /// Adapts an inspector constructor over a jsonrpsee [`HttpClient`] to `build_fanout`'s
        /// closure shape. The timeout is unused: the jsonrpsee chains rely on the inspection
        /// deadline in the signing flow, as they did before this adapter existed.
        fn with_http_client<I>(
            new_inspector: impl Fn(HttpClient) -> I,
        ) -> impl Fn(&ForeignChainProviderConfig, Duration) -> anyhow::Result<I> {
            move |provider, _timeout| {
                let client = build_http_client(provider)?;
                Ok(new_inspector(client))
            }
        }

        fn new_sui_inspector(
            provider: &ForeignChainProviderConfig,
            timeout: Duration,
        ) -> anyhow::Result<SuiInspector<GrpcSuiClient>> {
            let (url, auth_header) = resolve_provider_auth(provider)?;
            let client = GrpcSuiClient::new(url, auth_header, timeout)
                .map_err(|e| anyhow::anyhow!("failed to build the Sui gRPC client: {e}"))?;
            Ok(SuiInspector::new(client))
        }

        fn new_aptos_inspector(
            provider: &ForeignChainProviderConfig,
            timeout: Duration,
        ) -> anyhow::Result<AptosInspector<ReqwestAptosClient>> {
            let (url, auth_header) = resolve_provider_auth(provider)?;
            Ok(AptosInspector::new(ReqwestAptosClient::new(
                url,
                auth_header,
                timeout,
            )))
        }

        Ok(Self {
            bitcoin: build_fanout(
                "bitcoin",
                config.bitcoin.as_ref(),
                with_http_client(BitcoinInspector::new),
            )?,
            ethereum: build_fanout(
                "ethereum",
                config.ethereum.as_ref(),
                with_http_client(EthereumInspector::new),
            )?,
            abstract_chain: build_fanout(
                "abstract",
                config.abstract_chain.as_ref(),
                with_http_client(AbstractInspector::new),
            )?,
            base: build_fanout(
                "base",
                config.base.as_ref(),
                with_http_client(BaseInspector::new),
            )?,
            bnb: build_fanout(
                "bnb",
                config.bnb.as_ref(),
                with_http_client(BnbInspector::new),
            )?,
            starknet: build_fanout(
                "starknet",
                config.starknet.as_ref(),
                with_http_client(StarknetInspector::new),
            )?,
            arbitrum: build_fanout(
                "arbitrum",
                config.arbitrum.as_ref(),
                with_http_client(ArbitrumInspector::new),
            )?,
            hyper_evm: build_fanout(
                "hyper_evm",
                config.hyper_evm.as_ref(),
                with_http_client(HyperEvmInspector::new),
            )?,
            polygon: build_fanout(
                "polygon",
                config.polygon.as_ref(),
                with_http_client(PolygonInspector::new),
            )?,
            avalanche: build_fanout(
                "avalanche",
                config.avalanche.as_ref(),
                with_http_client(AvalancheInspector::new),
            )?,
            adi: build_fanout(
                "adi",
                config.adi.as_ref(),
                with_http_client(AdiInspector::new),
            )?,
            aptos: build_fanout("aptos", config.aptos.as_ref(), new_aptos_inspector)?,
            sui: build_fanout("sui", config.sui.as_ref(), new_sui_inspector)?,
        })
    }
}

pub struct VerifyForeignTxProvider {
    config: Arc<ConfigFile>,
    inspectors: ForeignChainInspectors<HttpClient>,
    supporters_by_foreign_chain: watch::Receiver<SupportersByForeignChain>,
    /// [`foreign_tx_reconstruction_threshold`](crate::foreign_chain_policy::foreign_tx_reconstruction_threshold)
    /// of the running domains; `None` when there is no ForeignTx domain.
    foreign_tx_reconstruction_threshold: Option<ReconstructionThreshold>,
    verify_foreign_tx_request_store: Arc<VerifyForeignTransactionRequestStorage>,
    ecdsa_signature_provider: Arc<EcdsaSignatureProvider>,
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

impl VerifyForeignTxProvider {
    pub fn new(
        config: Arc<ConfigFile>,
        supporters_by_foreign_chain: watch::Receiver<SupportersByForeignChain>,
        foreign_tx_reconstruction_threshold: Option<ReconstructionThreshold>,
        verify_foreign_tx_request_store: Arc<VerifyForeignTransactionRequestStorage>,
        ecdsa_signature_provider: Arc<EcdsaSignatureProvider>,
    ) -> anyhow::Result<Self> {
        let inspectors = ForeignChainInspectors::build(&config.foreign_chains)?;
        Ok(Self {
            config,
            inspectors,
            supporters_by_foreign_chain,
            foreign_tx_reconstruction_threshold,
            verify_foreign_tx_request_store,
            ecdsa_signature_provider,
        })
    }

    pub(crate) fn new_eligible_leaders_refiner(&self) -> ForeignChainLeadersRefiner {
        ForeignChainLeadersRefiner::new(
            self.supporters_by_foreign_chain.clone(),
            self.foreign_tx_reconstruction_threshold,
        )
    }

    pub async fn process_channel(&self, channel: NetworkTaskChannel) -> anyhow::Result<()> {
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
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use prometheus::Encoder;
    use rstest::rstest;

    const PROVIDER: &str = "a-provider";

    fn timed(chain: &str) -> u64 {
        metrics::MPC_FOREIGN_CHAIN_PROVIDER_INSPECTION_SECONDS
            .with_label_values(&[chain, PROVIDER])
            .get_sample_count()
    }

    fn counted(chain: &str, kind: &str) -> u64 {
        metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERRORS_TOTAL
            .with_label_values(&[chain, PROVIDER, kind])
            .get()
    }

    /// The registry is process-global, so each case measures under its own `chain`.
    #[rstest]
    #[case::answered("answered", ProviderCallOutcome::Answered, 1, None)]
    #[case::unreachable(
        "unreachable",
        ProviderCallOutcome::Failed(ProviderFailure::Unreachable),
        1,
        Some(metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERROR_TRANSIENT)
    )]
    #[case::rejected(
        "rejected",
        ProviderCallOutcome::Failed(ProviderFailure::Rejected),
        1,
        Some(metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERROR_NON_TRANSIENT)
    )]
    #[case::malformed(
        "malformed",
        ProviderCallOutcome::Failed(ProviderFailure::Malformed),
        1,
        Some(metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERROR_NON_TRANSIENT)
    )]
    #[case::timed_out(
        "timed-out",
        ProviderCallOutcome::Failed(ProviderFailure::TimedOut),
        1,
        Some(metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERROR_TIMEOUT)
    )]
    // Abandoned calls are counted but not timed; see `ProviderCallMetrics::record`.
    #[case::abandoned(
        "abandoned",
        ProviderCallOutcome::Abandoned,
        0,
        Some(metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERROR_TIMEOUT)
    )]
    fn provider_call_metrics__should_time_answers_and_count_only_provider_failures(
        #[case] chain: &str,
        #[case] outcome: ProviderCallOutcome,
        #[case] expected_timed: u64,
        #[case] expected_kind: Option<&str>,
    ) {
        // When
        ProviderCallMetrics.record(
            chain,
            &ProviderId(PROVIDER.to_string()),
            Duration::from_millis(10),
            outcome,
        );

        // Then
        assert_eq!(timed(chain), expected_timed);
        for kind in metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERROR_KINDS {
            let expected = u64::from(Some(kind) == expected_kind);
            assert_eq!(counted(chain, kind), expected, "kind={kind}");
        }
    }

    #[test]
    fn provider_call_metrics_declare__should_publish_a_providers_series_before_its_first_call() {
        // Given
        let chain = "declared";

        // When
        ProviderCallMetrics::declare(chain, &ProviderId(PROVIDER.to_string()));

        // Then
        let mut buffer = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&prometheus::default_registry().gather(), &mut buffer)
            .expect("the default registry encodes");
        let exposed = String::from_utf8(buffer).expect("prometheus text is utf-8");
        let published: Vec<&str> = exposed
            .lines()
            .filter(|line| line.contains(&format!(r#"chain="{chain}""#)))
            .collect();

        for metric in [
            "mpc_foreign_chain_provider_inspection_seconds",
            "mpc_foreign_chain_provider_errors_total",
        ] {
            assert!(
                published.iter().any(|line| line.starts_with(metric)),
                "{metric} was not published; exposed: {published:?}"
            );
        }
    }
}
