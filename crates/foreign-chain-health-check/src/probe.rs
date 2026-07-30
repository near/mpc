//! Asks every configured RPC provider which network it serves and compares the answer against the
//! operator's `expected_chain_identity`.

use std::collections::BTreeMap;
use std::time::Duration;

use foreign_chain_inspector::starknet::inspector::StarknetInspector;
use foreign_chain_inspector::{
    ChainIdentity, FanOut, ForeignChainInspectionError, ProviderFailure,
};
use mpc_node_config::{ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig};
use near_mpc_bounded_collections::NonEmptyVec;
use near_mpc_contract_interface::types::{ForeignChain, ProviderId};

use crate::prepare_jsonrpc;

/// One provider's verdict. Anything other than [`ProviderStatus::Healthy`] is unhealthy.
///
/// Carries no rendered RPC error: `Path`/`Query` auth splices the operator's API key into the URL,
/// and upstream errors interpolate that URL into their text. Dropping the text here keeps the key
/// out of anything built from a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderStatus {
    Healthy,
    WrongNetwork {
        expected: ChainIdentity,
        observed: ChainIdentity,
    },
    /// DNS, TLS, connection refused, 5xx, or rate limiting.
    Unreachable,
    /// The provider answered and refused: credentials invalid, or not enabled for this chain.
    RequestRejected,
    MalformedResponse,
    TimedOut,
    /// The RPC client could not be built, usually an unresolvable auth token.
    ClientSetupFailed,
    /// The chain is configured without an `expected_chain_identity`, so its providers cannot be
    /// checked. Reported rather than skipped: silence would read as healthy.
    MissingExpectedIdentity,
    /// The node can inspect this chain's transactions but has no identity probe for it yet.
    ProbeNotImplemented,
}

impl ProviderStatus {
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderHealth {
    pub chain: ForeignChain,
    pub provider: ProviderId,
    pub status: ProviderStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProviderCounts {
    pub configured: usize,
    pub healthy: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    rows: Vec<ProviderHealth>,
}

impl ProbeReport {
    pub fn rows(&self) -> &[ProviderHealth] {
        &self.rows
    }

    /// Only configured chains appear, never reports on a chain the operator did not configure.
    pub fn counts_per_chain(&self) -> BTreeMap<ForeignChain, ProviderCounts> {
        let mut counts: BTreeMap<ForeignChain, ProviderCounts> = BTreeMap::new();
        for row in &self.rows {
            let entry = counts.entry(row.chain).or_default();
            entry.configured += 1;
            if row.status.is_healthy() {
                entry.healthy += 1;
            }
        }
        counts
    }
}

/// Probe every configured provider concurrently.
///
/// Each provider is tried up to `max_retries` times with `timeout_sec` per try
/// This returns within the largest configured `timeout_sec * max_retries`.
pub async fn probe_all_providers(config: &ForeignChainsConfig) -> ProbeReport {
    let probe_attempts = config
        .iter_chains()
        .map(|(chain, chain_config)| async move {
            match chain {
                ForeignChain::Starknet => {
                    probe_chain(chain, chain_config, |provider| {
                        Ok(StarknetInspector::new(prepare_jsonrpc(provider)?))
                    })
                    .await
                }
                // Other chains to be added in follow up PRs
                _ => rows_of(chain, chain_config, ProviderStatus::ProbeNotImplemented),
            }
        });

    let report_rows = futures::future::join_all(probe_attempts).await.concat();
    ProbeReport { rows: report_rows }
}

async fn probe_chain<I>(
    chain: ForeignChain,
    config: &ForeignChainConfig,
    new_inspector: impl Fn(&ForeignChainProviderConfig) -> anyhow::Result<I>,
) -> Vec<ProviderHealth>
where
    I: foreign_chain_inspector::ChainIdentityInspector + Clone + Send + Sync + 'static,
{
    let Some(expected) = config.expected_chain_identity.clone() else {
        return rows_of(chain, config, ProviderStatus::MissingExpectedIdentity);
    };
    let expected = ChainIdentity::from(expected);

    let mut inspectors = Vec::new();
    let mut rows = Vec::new();
    for (name, provider) in config.providers.iter() {
        let provider_id = ProviderId(name.as_str().to_owned());
        match new_inspector(provider) {
            Ok(inspector) => inspectors.push((provider_id, inspector)),
            Err(_) => rows.push(ProviderHealth {
                chain,
                provider: provider_id,
                status: ProviderStatus::ClientSetupFailed,
            }),
        }
    }

    let Ok(inspectors) = NonEmptyVec::try_from(inspectors) else {
        return rows;
    };

    let timeout = Duration::from_secs(config.timeout_sec.get());
    let identities = FanOut::new(inspectors)
        .chain_identities(timeout, config.max_retries)
        .await;
    for (provider, identity) in identities {
        rows.push(ProviderHealth {
            chain,
            provider,
            status: classify(&expected, identity),
        });
    }
    rows
}

fn rows_of(
    chain: ForeignChain,
    config: &ForeignChainConfig,
    status: ProviderStatus,
) -> Vec<ProviderHealth> {
    config
        .providers
        .keys()
        .map(|name| ProviderHealth {
            chain,
            provider: ProviderId(name.as_str().to_owned()),
            status: status.clone(),
        })
        .collect()
}

fn classify(
    expected: &ChainIdentity,
    identity: Result<ChainIdentity, ForeignChainInspectionError>,
) -> ProviderStatus {
    match identity {
        Ok(observed) if &observed == expected => ProviderStatus::Healthy,
        Ok(observed) => ProviderStatus::WrongNetwork {
            expected: expected.clone(),
            observed,
        },
        Err(error) => match error.provider_failure() {
            Some(ProviderFailure::Unreachable) => ProviderStatus::Unreachable,
            Some(ProviderFailure::Rejected) => ProviderStatus::RequestRejected,
            Some(ProviderFailure::TimedOut) => ProviderStatus::TimedOut,
            Some(ProviderFailure::Malformed) => ProviderStatus::MalformedResponse,
            // The probe inspects no transaction, so a transaction-level error means an impl
            // answered outside its contract.
            None => ProviderStatus::MalformedResponse,
        },
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use mpc_node_config::{AuthConfig, TokenConfig};
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use std::num::NonZeroU64;

    /// Starknet mainnet's chain id, `SN_MAIN` in ASCII.
    const MAINNET: &str = "0x534e5f4d41494e";
    const SEPOLIA: &str = "0x534e5f5345504f4c4941";
    /// Reserved as "discard", so nothing listens there.
    const CLOSED_PORT_URL: &str = "http://127.0.0.1:9";

    fn provider(rpc_url: &str) -> ForeignChainProviderConfig {
        ForeignChainProviderConfig {
            rpc_url: rpc_url.to_string(),
            auth: AuthConfig::None,
        }
    }

    fn chain_config(
        expected: Option<&str>,
        providers: NonEmptyBTreeMap<
            mpc_node_config::foreign_chains::RpcProviderName,
            ForeignChainProviderConfig,
        >,
    ) -> ForeignChainConfig {
        ForeignChainConfig {
            timeout_sec: NonZeroU64::new(1).unwrap(),
            max_retries: NonZeroU64::new(1).unwrap(),
            expected_chain_identity: expected.map(str::to_string),
            providers,
        }
    }

    fn one_provider(
        name: &str,
        rpc_url: &str,
    ) -> NonEmptyBTreeMap<
        mpc_node_config::foreign_chains::RpcProviderName,
        ForeignChainProviderConfig,
    > {
        NonEmptyBTreeMap::new(name.to_string().into(), provider(rpc_url))
    }

    fn starknet_only(config: ForeignChainConfig) -> ForeignChainsConfig {
        ForeignChainsConfig {
            starknet: Some(config),
            ..Default::default()
        }
    }

    async fn mock_chain_id<'a>(
        server: &'a httpmock::MockServer,
        chain_id: &str,
    ) -> httpmock::Mock<'a> {
        let body = serde_json::json!({"jsonrpc": "2.0", "result": chain_id, "id": 0});
        server
            .mock_async(|when, then| {
                when.method(httpmock::Method::POST);
                then.status(200).json_body(body);
            })
            .await
    }

    fn status_of(report: &ProbeReport, provider: &str) -> ProviderStatus {
        report
            .rows()
            .iter()
            .find(|row| row.provider.0 == provider)
            .unwrap_or_else(|| panic!("missing row for provider `{provider}`"))
            .status
            .clone()
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_a_provider_on_the_expected_network_as_healthy() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        let mock = mock_chain_id(&server, MAINNET).await;
        let config = starknet_only(chain_config(
            Some(MAINNET),
            one_provider("publicnode", &server.base_url()),
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then
        mock.assert_async().await;
        assert_eq!(status_of(&report, "publicnode"), ProviderStatus::Healthy);
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_a_provider_on_another_network_as_wrong_network() {
        // Given a provider serving Sepolia while the operator configured mainnet
        let server = httpmock::MockServer::start_async().await;
        mock_chain_id(&server, SEPOLIA).await;
        let config = starknet_only(chain_config(
            Some(MAINNET),
            one_provider("publicnode", &server.base_url()),
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert_eq!(
            status_of(&report, "publicnode"),
            ProviderStatus::WrongNetwork {
                expected: ChainIdentity::from(MAINNET.to_string()),
                observed: ChainIdentity::from(SEPOLIA.to_string()),
            }
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_normalize_the_reported_identity_before_comparing() {
        // Given a provider padding and uppercasing the chain id, as the spec permits
        let server = httpmock::MockServer::start_async().await;
        mock_chain_id(&server, "0x00534E5F4D41494E").await;
        let config = starknet_only(chain_config(
            Some(MAINNET),
            one_provider("publicnode", &server.base_url()),
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert_eq!(status_of(&report, "publicnode"), ProviderStatus::Healthy);
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_a_chain_without_an_expected_identity_without_probing()
     {
        // Given
        let server = httpmock::MockServer::start_async().await;
        let mock = mock_chain_id(&server, MAINNET).await;
        let config = starknet_only(chain_config(
            None,
            one_provider("publicnode", &server.base_url()),
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then the provider is reported rather than skipped, and no request was sent
        assert_eq!(
            status_of(&report, "publicnode"),
            ProviderStatus::MissingExpectedIdentity
        );
        mock.assert_calls_async(0).await;
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_an_unreachable_provider() {
        // Given
        let config = starknet_only(chain_config(
            Some(MAINNET),
            one_provider("publicnode", CLOSED_PORT_URL),
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert_eq!(
            status_of(&report, "publicnode"),
            ProviderStatus::Unreachable
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_a_provider_whose_client_cannot_be_built() {
        // Given a provider whose auth token comes from an environment variable that is not set
        let config = starknet_only(chain_config(
            Some(MAINNET),
            NonEmptyBTreeMap::new(
                "keyed".to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url: CLOSED_PORT_URL.to_string(),
                    auth: AuthConfig::Header {
                        name: http::HeaderName::from_static("authorization"),
                        scheme: Some("Bearer".to_string()),
                        token: TokenConfig::Env {
                            env: "PROBE_TEST_TOKEN_THAT_IS_NOT_SET".to_string(),
                        },
                    },
                },
            ),
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert_eq!(
            status_of(&report, "keyed"),
            ProviderStatus::ClientSetupFailed
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_each_provider_of_a_chain_separately() {
        // Given one healthy provider and one that is unreachable
        let server = httpmock::MockServer::start_async().await;
        mock_chain_id(&server, MAINNET).await;
        let mut providers = one_provider("healthy", &server.base_url());
        providers.insert("broken".to_string().into(), provider(CLOSED_PORT_URL));
        let config = starknet_only(chain_config(Some(MAINNET), providers));

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert_eq!(status_of(&report, "healthy"), ProviderStatus::Healthy);
        assert_eq!(status_of(&report, "broken"), ProviderStatus::Unreachable);
        assert_eq!(
            report.counts_per_chain()[&ForeignChain::Starknet],
            ProviderCounts {
                configured: 2,
                healthy: 1,
            }
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_a_chain_with_no_identity_probe_as_not_implemented()
    {
        // Given a chain the node can inspect but has no identity probe for
        let config = ForeignChainsConfig {
            base: Some(chain_config(
                Some("8453"),
                one_provider("publicnode", CLOSED_PORT_URL),
            )),
            ..Default::default()
        };

        // When
        let report = probe_all_providers(&config).await;

        // Then it is visible in the report rather than silently absent
        assert_eq!(
            status_of(&report, "publicnode"),
            ProviderStatus::ProbeNotImplemented
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_return_an_empty_report_when_no_chains_are_configured() {
        // Given
        let config = ForeignChainsConfig::default();

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert!(report.rows().is_empty());
        assert!(report.counts_per_chain().is_empty());
    }

    #[tokio::test]
    async fn probe_all_providers__should_keep_auth_material_out_of_the_report() {
        // Given a provider whose API key is spliced into the URL path
        let config = starknet_only(chain_config(
            Some(MAINNET),
            NonEmptyBTreeMap::new(
                "keyed".to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url: format!("{CLOSED_PORT_URL}/v2/API_KEY"),
                    auth: AuthConfig::Path {
                        placeholder: "API_KEY".to_string(),
                        token: TokenConfig::Val {
                            val: "super-secret".to_string(),
                        },
                    },
                },
            ),
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then neither the token nor the URL it was spliced into reaches the report
        let rendered = format!("{report:?}");
        assert!(!rendered.contains("super-secret"), "{rendered}");
        assert!(!rendered.contains("127.0.0.1"), "{rendered}");
    }
}
