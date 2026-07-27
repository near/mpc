//! Log-only check that every configured foreign-chain RPC provider is serving the network the
//! operator expects.
//!
//! Runs once per process, right after the indexer starts, so a misconfigured provider is
//! reported at boot rather than by the first signature request that needs it. The failure it
//! catches is worth catching early: a provider pointed at the wrong network of the right chain
//! family answers transaction lookups with a plain "not found", which
//! [`foreign_chain_inspector::FanOut`] counts as a substantive verdict, so it disagrees with
//! the healthy providers and breaks verification for the whole chain.
//!
//! Opt-in per chain via `expected_chain_identity`, and log-only in both directions: an
//! unreachable provider must not turn a transient RPC blip into a boot loop, and a mismatch is
//! surfaced rather than enforced until the logs show the check is trustworthy.

use std::time::Duration;

use foreign_chain_inspector::aptos::inspector::AptosInspector;
use foreign_chain_inspector::bitcoin::inspector::BitcoinInspector;
use foreign_chain_inspector::starknet::inspector::StarknetInspector;
use foreign_chain_inspector::sui::inspector::SuiInspector;
use foreign_chain_inspector::{
    ChainIdentity, ChainIdentityProbe, RpcAuthentication, abstract_chain, arbitrum, base, bnb,
    hyperevm, polygon,
};
use foreign_chain_rpc_auth::auth_config_to_rpc_auth;
use foreign_chain_rpc_interfaces::aptos::ReqwestAptosClient;
use foreign_chain_rpc_interfaces::sui::GrpcSuiClient;
use mpc_node_config::{ForeignChainConfig, ForeignChainsConfig, foreign_chains::RpcProviderName};
use near_mpc_contract_interface::types as dtos;

/// What a single provider answered when asked which network it serves. The error side is
/// already rendered, which keeps [`evaluate`] free of I/O types and trivially testable.
type ProbeOutcome = Result<ChainIdentity, String>;

pub(crate) async fn run(config: ForeignChainsConfig) {
    let per_chain = config
        .iter_chains()
        .map(|(chain, chain_config)| async move { check_chain(chain, chain_config).await });
    let findings: Vec<Finding> = futures::future::join_all(per_chain)
        .await
        .into_iter()
        .flatten()
        .collect();

    for finding in &findings {
        log_finding(finding);
    }

    let mismatches = findings
        .iter()
        .filter(|finding| matches!(finding.kind, FindingKind::Mismatch { .. }))
        .count();
    if mismatches == 0 {
        tracing::info!("foreign-chain identity verifier: no provider is on the wrong network");
    } else {
        tracing::error!(
            mismatches,
            "foreign-chain identity verifier: providers are serving the wrong network; \
             transaction verification will fail for the affected chains"
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    chain: dtos::ForeignChain,
    provider: Option<RpcProviderName>,
    kind: FindingKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FindingKind {
    Match {
        identity: ChainIdentity,
    },
    Mismatch {
        expected: String,
        observed: ChainIdentity,
    },
    /// The provider could not be asked, for any reason: its client would not build, the request
    /// failed, the response was unusable, or the probe exceeded the chain's timeout.
    Unreachable {
        error: String,
    },
    /// The chain has no `expected_chain_identity`, so there is nothing to compare against.
    NotConfigured,
    /// This binary has no inspector for the chain, so there is nothing to ask.
    Unsupported,
}

async fn check_chain(chain: dtos::ForeignChain, config: &ForeignChainConfig) -> Vec<Finding> {
    let Some(expected) = config.expected_chain_identity.as_deref() else {
        return vec![Finding {
            chain,
            provider: None,
            kind: FindingKind::NotConfigured,
        }];
    };
    let Some(probes) = build_probes(chain, config) else {
        return vec![Finding {
            chain,
            provider: None,
            kind: FindingKind::Unsupported,
        }];
    };

    let timeout = Duration::from_secs(config.timeout_sec.get());
    let probed = probe_all(probes, timeout).await;
    evaluate(chain, expected, &probed)
}

/// Decides what the operator needs to be told, given what the providers answered.
///
/// `expected` is compared verbatim against each observation apart from surrounding whitespace,
/// which a TOML/YAML value picks up too easily to be worth reporting as a mismatch.
fn evaluate(
    chain: dtos::ForeignChain,
    expected: &str,
    probed: &[(RpcProviderName, ProbeOutcome)],
) -> Vec<Finding> {
    let expected = expected.trim();
    probed
        .iter()
        .map(|(provider, outcome)| {
            let kind = match outcome {
                Err(error) => FindingKind::Unreachable {
                    error: error.clone(),
                },
                Ok(observed) if observed.as_str() == expected => FindingKind::Match {
                    identity: observed.clone(),
                },
                Ok(observed) => FindingKind::Mismatch {
                    expected: expected.to_string(),
                    observed: observed.clone(),
                },
            };
            Finding {
                chain,
                provider: Some(provider.clone()),
                kind,
            }
        })
        .collect()
}

/// A provider whose client could not be constructed is carried as an `Err` rather than dropped,
/// so it still shows up in the report instead of silently going unchecked.
type ProviderProbe = (RpcProviderName, anyhow::Result<Box<dyn ChainIdentityProbe>>);

async fn probe_all(
    probes: Vec<ProviderProbe>,
    timeout: Duration,
) -> Vec<(RpcProviderName, ProbeOutcome)> {
    let probed = probes
        .into_iter()
        .map(|(provider, probe)| async move { (provider, probe_one(probe, timeout).await) });
    futures::future::join_all(probed).await
}

async fn probe_one(
    probe: anyhow::Result<Box<dyn ChainIdentityProbe>>,
    timeout: Duration,
) -> ProbeOutcome {
    let probe = probe.map_err(|error| format!("{error:#}"))?;
    match tokio::time::timeout(timeout, probe.chain_identity()).await {
        Err(_elapsed) => Err(format!("timed out after {}s", timeout.as_secs())),
        Ok(Err(error)) => Err(error.to_string()),
        Ok(Ok(identity)) => Ok(identity),
    }
}

/// `None` for chains this binary cannot inspect at all: `solana`, `ethereum` and `ton` are
/// accepted by the config but have no inspector, so their identity cannot be checked either.
fn build_probes(
    chain: dtos::ForeignChain,
    config: &ForeignChainConfig,
) -> Option<Vec<ProviderProbe>> {
    /// Mirrors [`crate::providers::verify_foreign_tx`]'s client construction, so the identity
    /// check goes through the same URL, auth and transport that verification would use.
    fn probes<Probe: ChainIdentityProbe + 'static>(
        config: &ForeignChainConfig,
        new_inspector: impl Fn(String, RpcAuthentication, Duration) -> anyhow::Result<Probe>,
    ) -> Vec<ProviderProbe> {
        let timeout = Duration::from_secs(config.timeout_sec.get());
        config
            .providers
            .iter()
            .map(|(name, provider)| {
                let mut url = provider.rpc_url.clone();
                let probe = auth_config_to_rpc_auth(provider.auth.clone(), &mut url)
                    .and_then(|rpc_auth| new_inspector(url, rpc_auth, timeout))
                    .map(|probe| Box::new(probe) as Box<dyn ChainIdentityProbe>);
                (name.clone(), probe)
            })
            .collect()
    }

    /// The jsonrpsee chains take no timeout at construction; [`probe_one`] bounds them, and
    /// every other transport, from the outside.
    fn over_http<Probe>(
        new_inspector: impl Fn(foreign_chain_inspector::http_client::HttpClient) -> Probe,
    ) -> impl Fn(String, RpcAuthentication, Duration) -> anyhow::Result<Probe> {
        move |url, rpc_auth, _timeout| {
            Ok(new_inspector(foreign_chain_inspector::build_http_client(
                url, rpc_auth,
            )?))
        }
    }

    let probes = match chain {
        dtos::ForeignChain::Bitcoin => probes(config, over_http(BitcoinInspector::new)),
        dtos::ForeignChain::Starknet => probes(config, over_http(StarknetInspector::new)),
        dtos::ForeignChain::Abstract => probes(
            config,
            over_http(abstract_chain::inspector::AbstractInspector::new),
        ),
        dtos::ForeignChain::Base => probes(config, over_http(base::inspector::BaseInspector::new)),
        dtos::ForeignChain::Bnb => probes(config, over_http(bnb::inspector::BnbInspector::new)),
        dtos::ForeignChain::Arbitrum => probes(
            config,
            over_http(arbitrum::inspector::ArbitrumInspector::new),
        ),
        dtos::ForeignChain::HyperEvm => probes(
            config,
            over_http(hyperevm::inspector::HyperEvmInspector::new),
        ),
        dtos::ForeignChain::Polygon => {
            probes(config, over_http(polygon::inspector::PolygonInspector::new))
        }
        dtos::ForeignChain::Aptos => probes(config, |url, rpc_auth, timeout| {
            Ok(AptosInspector::new(ReqwestAptosClient::new(
                url,
                auth_header(rpc_auth),
                timeout,
            )))
        }),
        dtos::ForeignChain::Sui => probes(config, |url, rpc_auth, timeout| {
            let client = GrpcSuiClient::new(url, auth_header(rpc_auth), timeout)
                .map_err(|e| anyhow::anyhow!("failed to build the Sui gRPC client: {e}"))?;
            Ok(SuiInspector::new(client))
        }),
        _ => return None,
    };
    Some(probes)
}

fn auth_header(rpc_auth: RpcAuthentication) -> Option<(http::HeaderName, http::HeaderValue)> {
    match rpc_auth {
        RpcAuthentication::KeyInUrl => None,
        RpcAuthentication::CustomHeader {
            header_name,
            header_value,
        } => Some((header_name, header_value)),
    }
}

fn log_finding(finding: &Finding) {
    let chain = finding.chain;
    let provider = finding.provider.as_ref().map(|p| p.as_str());
    match &finding.kind {
        FindingKind::Mismatch { expected, observed } => {
            tracing::error!(
                ?chain,
                provider,
                %expected,
                %observed,
                "foreign-chain provider is serving the wrong network; it will disagree with the \
                 other providers and break transaction verification for this chain",
            );
        }
        FindingKind::Unreachable { error } => {
            tracing::warn!(
                ?chain,
                provider,
                error,
                "could not verify which network this foreign-chain provider serves",
            );
        }
        FindingKind::NotConfigured => {
            tracing::info!(
                ?chain,
                "foreign chain has no `expected_chain_identity`; skipping the identity check",
            );
        }
        FindingKind::Unsupported => {
            tracing::info!(
                ?chain,
                "this node has no inspector for the foreign chain; skipping the identity check",
            );
        }
        FindingKind::Match { identity } => {
            tracing::info!(
                ?chain,
                provider,
                %identity,
                "foreign-chain provider serves the expected network",
            );
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use mpc_node_config::{AuthConfig, ForeignChainProviderConfig};
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;

    const CHAIN: dtos::ForeignChain = dtos::ForeignChain::Starknet;
    const SN_MAIN: &str = "0x534e5f4d41494e";
    const SN_SEPOLIA: &str = "0x534e5f5345504f4c4941";

    fn provider(name: &str) -> RpcProviderName {
        RpcProviderName::from(name.to_string())
    }

    fn observed(name: &str, identity: &str) -> (RpcProviderName, ProbeOutcome) {
        (
            provider(name),
            Ok(ChainIdentity::from(identity.to_string())),
        )
    }

    fn unreachable(name: &str) -> (RpcProviderName, ProbeOutcome) {
        (provider(name), Err("connection refused".to_string()))
    }

    #[test]
    fn evaluate__should_report_a_match_when_the_provider_is_on_the_expected_network() {
        // Given
        let probed = [observed("blast", SN_MAIN)];

        // When
        let findings = evaluate(CHAIN, SN_MAIN, &probed);

        // Then
        assert_matches!(
            &findings[..],
            [Finding {
                kind: FindingKind::Match { .. },
                ..
            }]
        );
    }

    #[test]
    fn evaluate__should_name_the_single_provider_that_is_on_the_wrong_network() {
        // Given — the failure this check exists for: one of three providers points at Sepolia.
        let probed = [
            observed("blast", SN_MAIN),
            observed("misconfigured", SN_SEPOLIA),
            observed("publicnode", SN_MAIN),
        ];

        // When
        let findings = evaluate(CHAIN, SN_MAIN, &probed);

        // Then
        let mismatches: Vec<_> = findings
            .iter()
            .filter(|f| matches!(f.kind, FindingKind::Mismatch { .. }))
            .collect();
        assert_eq!(mismatches.len(), 1);
        assert_eq!(mismatches[0].provider, Some(provider("misconfigured")));
        assert_matches!(
            &mismatches[0].kind,
            FindingKind::Mismatch { expected, observed }
                if expected == SN_MAIN && observed.as_str() == SN_SEPOLIA
        );
    }

    #[test]
    fn evaluate__should_report_an_unreachable_provider_without_claiming_a_mismatch() {
        // Given
        let probed = [observed("blast", SN_MAIN), unreachable("publicnode")];

        // When
        let findings = evaluate(CHAIN, SN_MAIN, &probed);

        // Then — an RPC we could not reach says nothing about which network it serves.
        assert!(
            !findings
                .iter()
                .any(|f| matches!(f.kind, FindingKind::Mismatch { .. }))
        );
        assert_matches!(
            &findings[1],
            Finding {
                kind: FindingKind::Unreachable { .. },
                ..
            }
        );
    }

    #[test]
    fn evaluate__should_ignore_whitespace_around_the_configured_identity() {
        // Given — a value that picked up padding on its way through TOML/YAML.
        let probed = [observed("blast", SN_MAIN)];

        // When
        let findings = evaluate(CHAIN, &format!("  {SN_MAIN}\n"), &probed);

        // Then
        assert_matches!(
            &findings[..],
            [Finding {
                kind: FindingKind::Match { .. },
                ..
            }]
        );
    }

    #[test]
    fn evaluate__should_treat_the_comparison_as_case_sensitive() {
        // Given — every probe normalizes its output, so a case difference is a real difference
        // rather than a rendering artifact the check should paper over.
        let probed = [observed("blast", SN_MAIN)];

        // When
        let findings = evaluate(CHAIN, &SN_MAIN.to_uppercase(), &probed);

        // Then
        assert_matches!(
            &findings[..],
            [Finding {
                kind: FindingKind::Mismatch { .. },
                ..
            }]
        );
    }

    fn chain_config(expected_chain_identity: Option<&str>) -> ForeignChainConfig {
        let providers = BTreeMap::from([(
            provider("public"),
            ForeignChainProviderConfig {
                rpc_url: "https://starknet-rpc.publicnode.com".to_string(),
                auth: AuthConfig::None,
            },
        )]);
        ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers: NonEmptyBTreeMap::try_from(providers)
                .expect("test setup: providers must be non-empty"),
            expected_chain_identity: expected_chain_identity.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn check_chain__should_not_touch_the_network_when_no_identity_is_configured() {
        // Given — the URL is unreachable, so any probe attempt would surface as `Unreachable`.
        let config = chain_config(None);

        // When
        let findings = check_chain(CHAIN, &config).await;

        // Then
        assert_eq!(
            findings,
            vec![Finding {
                chain: CHAIN,
                provider: None,
                kind: FindingKind::NotConfigured,
            }]
        );
    }

    #[tokio::test]
    async fn check_chain__should_report_chains_this_binary_cannot_inspect() {
        // Given — `solana` is accepted by the config but has no inspector.
        let config = chain_config(Some("whatever"));

        // When
        let findings = check_chain(dtos::ForeignChain::Solana, &config).await;

        // Then
        assert_eq!(
            findings,
            vec![Finding {
                chain: dtos::ForeignChain::Solana,
                provider: None,
                kind: FindingKind::Unsupported,
            }]
        );
    }

    #[tokio::test]
    async fn probe_all__should_report_a_provider_whose_client_cannot_be_built() {
        // Given
        let probes = vec![(
            provider("broken"),
            Err(anyhow::anyhow!("invalid RPC URL: `not a url`")),
        )];

        // When
        let probed = probe_all(probes, Duration::from_secs(1)).await;

        // Then — the provider still appears in the report rather than being silently skipped.
        assert_matches!(
            &probed[..],
            [(name, Err(error))] if name == &provider("broken") && error.contains("invalid RPC URL")
        );
    }

    struct StalledProbe;

    impl ChainIdentityProbe for StalledProbe {
        fn chain_identity(&self) -> foreign_chain_inspector::ChainIdentityFuture<'_> {
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn probe_all__should_give_up_on_a_provider_that_never_answers() {
        // Given
        let probes: Vec<ProviderProbe> = vec![(provider("stalled"), Ok(Box::new(StalledProbe)))];

        // When
        let probed = probe_all(probes, Duration::from_secs(30)).await;

        // Then — startup must never hang on a foreign RPC.
        assert_matches!(&probed[..], [(_, Err(error))] if error.contains("timed out"));
    }
}
