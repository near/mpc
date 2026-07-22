//! Healthcheck of every configured foreign-chain RPC provider, via
//! [`foreign_chain_health_check`].

use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;

use foreign_chain_health_check::{
    HealthCheckRoute, NetworkKind, ProviderResult, SkipReason, Status, check_all_providers,
    check_all_providers_with_golden,
};
use futures::FutureExt as _;
use mpc_node_config::{ForeignChainsConfig, HealthCheckGoldenConfig};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::metrics;

/// Healthy provider count per configured chain, keyed by `chain.label()`.
pub type ProviderHealthSnapshot = BTreeMap<String, i64>;

/// Startup healthcheck entrypoint: builds a [`HealthCheckRoute`] from the config
/// and runs it, warning if a golden config is set on a public network. A probe
/// panic is caught and logged, never propagated (diagnostic-only). Publishes
/// per-chain `configured` and `healthy` provider gauges, plus a healthy-count
/// snapshot over `health_publisher`.
pub async fn run_startup_health_check(
    foreign_chains: ForeignChainsConfig,
    network: NetworkKind,
    golden: Option<HealthCheckGoldenConfig>,
    health_publisher: watch::Sender<ProviderHealthSnapshot>,
) {
    for (chain, config) in foreign_chains.iter_chains() {
        metrics::FOREIGN_CHAIN_RPC_PROVIDERS_CONFIGURED
            .with_label_values(&[chain.label()])
            .set(config.providers.len() as i64);
    }

    // A config-supplied golden is only meaningful on a local chain; on
    // mainnet/testnet the built-in set is always used.
    if let NetworkKind::Public(network) = network
        && golden.is_some()
    {
        warn!(
            network = network.label(),
            "foreign_chain_health_check_golden is set in config but ignored on \
             mainnet/testnet; the built-in golden set is always used — remove it \
             from config.yaml"
        );
    }

    // Catch a probe panic (e.g. an inspector bug) and log it, rather than
    // letting it vanish with the spawned task's dropped join handle.
    let probe = async move {
        let results = match HealthCheckRoute::decide(network, golden) {
            HealthCheckRoute::ProbeBuiltIn(network) => {
                info!(
                    network = network.label(),
                    "running foreign-chain RPC provider health check"
                );
                check_all_providers(&foreign_chains, network).await
            }
            HealthCheckRoute::ProbeSupplied(golden) => {
                info!(
                    "running foreign-chain RPC provider health check with config-supplied golden values"
                );
                check_all_providers_with_golden(&foreign_chains, &golden).await
            }
            HealthCheckRoute::Skip(SkipReason::LocalChainWithoutGolden) => {
                debug!(
                    "local or custom chain without golden values; \
                     skipping foreign-chain RPC provider health check"
                );
                return;
            }
            HealthCheckRoute::Skip(SkipReason::Undetermined) => {
                warn!("network undetermined; skipping foreign-chain RPC provider health check");
                return;
            }
        };
        log_results(&results);
        set_healthy_metric(&foreign_chains, &results, &health_publisher);
    };

    if AssertUnwindSafe(probe).catch_unwind().await.is_err() {
        error!(
            "foreign-chain RPC provider health check panicked (diagnostic-only; node unaffected)"
        );
    }
}

/// Emits the per-chain healthy-provider gauge and pushes the same counts to
/// `health_publisher`.
fn set_healthy_metric(
    foreign_chains: &ForeignChainsConfig,
    results: &[ProviderResult],
    health_publisher: &watch::Sender<ProviderHealthSnapshot>,
) {
    let mut healthy_by_chain: BTreeMap<&str, i64> = BTreeMap::new();
    for result in results {
        if matches!(result.status, Status::Passed) {
            *healthy_by_chain.entry(result.chain).or_default() += 1;
        }
    }

    let mut counts = ProviderHealthSnapshot::new();
    for (chain, _) in foreign_chains.iter_chains() {
        let label = chain.label();
        let healthy = healthy_by_chain.get(label).copied().unwrap_or(0);
        metrics::FOREIGN_CHAIN_RPC_PROVIDERS_HEALTHY
            .with_label_values(&[label])
            .set(healthy);
        counts.insert(label.to_string(), healthy);
    }
    let _ = health_publisher.send(counts);
}

fn log_results(results: &[ProviderResult]) {
    let mut healthy = 0;
    let mut failed = 0;
    for result in results {
        match &result.status {
            Status::Passed => {
                healthy += 1;
                debug!(
                    chain = result.chain,
                    provider = %result.provider,
                    "foreign-chain RPC provider health check passed"
                );
            }
            Status::Skipped(reason) => {
                debug!(
                    chain = result.chain,
                    provider = %result.provider,
                    reason = %reason,
                    "foreign-chain RPC provider health check skipped"
                );
            }
            Status::Failed(_) => {
                failed += 1;
                // TODO(#2350): Also log the failure reason once systematic secret redaction is implemented.
                warn!(
                    chain = result.chain,
                    provider = %result.provider,
                    "foreign-chain RPC provider health check failed"
                );
            }
        }
    }
    let checked = healthy + failed;
    if checked == 0 {
        warn!(
            skipped = results.len(),
            "foreign-chain RPC provider health check probed no providers; \
             foreign_chains is empty or every configured chain was skipped"
        );
        return;
    }
    info!(
        "foreign-chain RPC provider health check complete: {healthy}/{checked} providers healthy"
    );
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use mpc_node_config::{
        AuthConfig, BlockHashGolden, ForeignChainConfig, ForeignChainProviderConfig,
    };
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use std::num::NonZeroU64;
    use tracing_test::traced_test;

    fn chain_config(rpc_url: &str) -> ForeignChainConfig {
        ForeignChainConfig {
            timeout_sec: NonZeroU64::new(5).unwrap(),
            max_retries: NonZeroU64::new(1).unwrap(),
            providers: NonEmptyBTreeMap::new(
                "only".to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url: rpc_url.to_string(),
                    auth: AuthConfig::None,
                },
            ),
        }
    }

    fn config_with_unsupported_chain() -> ForeignChainsConfig {
        ForeignChainsConfig {
            ethereum: Some(chain_config("https://rpc.example.com")),
            ..Default::default()
        }
    }

    fn base_golden() -> HealthCheckGoldenConfig {
        HealthCheckGoldenConfig {
            base: Some(BlockHashGolden {
                tx: "aa".repeat(32),
                block_hash: "bb".repeat(32),
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    #[traced_test]
    async fn run_startup_health_check__should_warn_when_network_undetermined() {
        // Given
        let foreign_chains = config_with_unsupported_chain();
        let (publisher, snapshot) = watch::channel(ProviderHealthSnapshot::new());

        // When
        run_startup_health_check(foreign_chains, NetworkKind::Undetermined, None, publisher).await;

        // Then it is flagged loudly (a real deployment that can't resolve its
        // network) and no snapshot is published
        assert!(logs_contain("network undetermined"));
        logs_assert(|lines: &[&str]| {
            match lines
                .iter()
                .any(|l| l.contains("WARN") && l.contains("network undetermined"))
            {
                true => Ok(()),
                false => Err("expected a WARN for undetermined network".to_string()),
            }
        });
        assert!(snapshot.borrow().is_empty());
    }

    #[tokio::test]
    #[traced_test]
    async fn run_startup_health_check__should_skip_quietly_on_a_local_chain() {
        // Given a known local/dev chain (no golden vectors)
        let foreign_chains = config_with_unsupported_chain();
        let (publisher, _snapshot) = watch::channel(ProviderHealthSnapshot::new());

        // When
        run_startup_health_check(foreign_chains, NetworkKind::Local, None, publisher).await;

        // Then it is skipped at debug, not warned
        assert!(logs_contain(
            "skipping foreign-chain RPC provider health check"
        ));
        logs_assert(
            |lines: &[&str]| match lines.iter().any(|l| l.contains("WARN")) {
                true => Err("local chain should not warn".to_string()),
                false => Ok(()),
            },
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn run_startup_health_check__should_probe_with_supplied_golden_on_a_local_chain() {
        // Given a local chain, config-supplied golden values, and a provider
        // nothing listens on (connection refused, no external traffic)
        let foreign_chains = ForeignChainsConfig {
            base: Some(chain_config("http://127.0.0.1:1")),
            ..Default::default()
        };
        let (publisher, _snapshot) = watch::channel(ProviderHealthSnapshot::new());

        // When
        run_startup_health_check(
            foreign_chains,
            NetworkKind::Local,
            Some(base_golden()),
            publisher,
        )
        .await;

        // Then the probe runs end to end and summarizes the one probed provider
        assert!(logs_contain(
            "running foreign-chain RPC provider health check with config-supplied golden values"
        ));
        assert!(logs_contain(
            "foreign-chain RPC provider health check complete: 0/1 providers healthy"
        ));
    }

    #[tokio::test]
    #[traced_test]
    async fn run_startup_health_check__should_probe_with_the_builtin_set_on_a_real_network() {
        // Given a real network and no config-supplied golden
        let foreign_chains = config_with_unsupported_chain();
        let (publisher, _snapshot) = watch::channel(ProviderHealthSnapshot::new());

        // When
        run_startup_health_check(
            foreign_chains,
            NetworkKind::Public(foreign_chain_health_check::Network::Mainnet),
            None,
            publisher,
        )
        .await;

        // Then the built-in check runs, without an ignored-golden warning
        assert!(logs_contain(
            "running foreign-chain RPC provider health check"
        ));
        logs_assert(|lines: &[&str]| {
            match lines
                .iter()
                .any(|l| l.contains("foreign_chain_health_check_golden is set"))
            {
                true => {
                    Err("no golden supplied; must not warn about an ignored golden".to_string())
                }
                false => Ok(()),
            }
        });
    }

    #[tokio::test]
    #[traced_test]
    async fn run_startup_health_check__should_warn_and_use_builtin_when_golden_supplied_on_a_real_network()
     {
        // Given a real network AND a config-supplied golden (a misconfiguration)
        let foreign_chains = config_with_unsupported_chain();
        let (publisher, _snapshot) = watch::channel(ProviderHealthSnapshot::new());

        // When
        run_startup_health_check(
            foreign_chains,
            NetworkKind::Public(foreign_chain_health_check::Network::Mainnet),
            Some(base_golden()),
            publisher,
        )
        .await;

        // Then the operator is warned the golden is ignored, and the built-in set runs
        assert!(logs_contain(
            "foreign_chain_health_check_golden is set in config but ignored"
        ));
        assert!(logs_contain(
            "running foreign-chain RPC provider health check"
        ));
    }

    #[tokio::test]
    async fn run_startup_health_check__should_publish_configured_even_when_network_undetermined() {
        // Given an unsupported chain with one provider and an undetermined network
        let foreign_chains = config_with_unsupported_chain();
        let (publisher, _snapshot) = watch::channel(ProviderHealthSnapshot::new());

        // When
        run_startup_health_check(foreign_chains, NetworkKind::Undetermined, None, publisher).await;

        // Then `configured` is populated up front despite the skipped probe
        assert_eq!(
            metrics::FOREIGN_CHAIN_RPC_PROVIDERS_CONFIGURED
                .with_label_values(&["ethereum"])
                .get(),
            1
        );
    }

    #[tokio::test]
    async fn run_startup_health_check__should_publish_healthy_snapshot_after_probe() {
        // Given an unsupported chain (probed but resolves to skip, so 0 healthy)
        // on a determined network
        let foreign_chains = config_with_unsupported_chain();
        let (publisher, snapshot) = watch::channel(ProviderHealthSnapshot::new());

        // When
        run_startup_health_check(
            foreign_chains,
            NetworkKind::Public(foreign_chain_health_check::Network::Mainnet),
            None,
            publisher,
        )
        .await;

        // Then a snapshot with per-chain healthy counts is published
        let counts = snapshot.borrow();
        assert_eq!(counts.get("ethereum"), Some(&0));
    }

    #[test]
    fn set_healthy_metric__should_count_passed_providers_per_chain_and_publish() {
        // Given three configured chains whose per-provider outcomes span what a
        // real run produces: base fully healthy (2/2), aptos partial (1/3), and
        // ethereum with nothing passing (0/2).
        let provider = || ForeignChainProviderConfig {
            rpc_url: "https://rpc.example.com".to_string(),
            auth: AuthConfig::None,
        };
        let chain = || ForeignChainConfig {
            timeout_sec: NonZeroU64::new(5).unwrap(),
            max_retries: NonZeroU64::new(1).unwrap(),
            providers: NonEmptyBTreeMap::new("only".to_string().into(), provider()),
        };
        let foreign_chains = ForeignChainsConfig {
            base: Some(chain()),
            aptos: Some(chain()),
            ethereum: Some(chain()),
            ..Default::default()
        };
        let result = |chain: &'static str, provider: &str, status: Status| ProviderResult {
            chain,
            provider: provider.to_string(),
            status,
        };
        let results = vec![
            result("base", "a", Status::Passed),
            result("base", "b", Status::Passed),
            result("aptos", "a", Status::Passed),
            result("aptos", "b", Status::Failed("boom".to_string())),
            result("aptos", "c", Status::Skipped("unsupported".to_string())),
            result("ethereum", "a", Status::Failed("boom".to_string())),
            result("ethereum", "b", Status::Failed("boom".to_string())),
        ];

        // When
        let (publisher, receiver) = watch::channel(ProviderHealthSnapshot::new());
        set_healthy_metric(&foreign_chains, &results, &publisher);

        // Then both the gauge and the pushed snapshot report each chain's
        // passing count, including 0 for a chain where nothing passed.
        let counts = receiver.borrow();
        assert_eq!(counts.get("base"), Some(&2));
        assert_eq!(counts.get("aptos"), Some(&1));
        assert_eq!(counts.get("ethereum"), Some(&0));
        let healthy = |chain| {
            metrics::FOREIGN_CHAIN_RPC_PROVIDERS_HEALTHY
                .with_label_values(&[chain])
                .get()
        };
        assert_eq!(healthy("base"), 2);
        assert_eq!(healthy("aptos"), 1);
        assert_eq!(healthy("ethereum"), 0);
    }

    #[tokio::test]
    #[traced_test]
    async fn log_results__should_not_log_the_failure_reason() {
        // Given a failed result carrying a key-bearing reason
        let results = vec![ProviderResult {
            chain: "base",
            provider: "alchemy".to_string(),
            status: Status::Failed("boom at https://x/key-bearing-url".to_string()),
        }];

        // When
        log_results(&results);

        // Then the failure is announced (chain + provider) but the reason —
        // which can carry a secret — is not logged anywhere.
        assert!(logs_contain(
            "foreign-chain RPC provider health check failed"
        ));
        logs_assert(|lines: &[&str]| {
            if lines.iter().any(|line| line.contains("key-bearing-url")) {
                Err("failure reason was logged".to_string())
            } else {
                Ok(())
            }
        });
    }

    #[test]
    #[traced_test]
    fn log_results__should_summarize_healthy_ratio_at_info() {
        // Given one healthy and one failed provider
        let results = vec![
            ProviderResult {
                chain: "base",
                provider: "healthy".to_string(),
                status: Status::Passed,
            },
            ProviderResult {
                chain: "base",
                provider: "broken".to_string(),
                status: Status::Failed("boom".to_string()),
            },
        ];

        // When
        log_results(&results);

        // Then the detached probe announces completion with a human-readable ratio
        assert!(logs_contain(
            "foreign-chain RPC provider health check complete: 1/2 providers healthy"
        ));
    }

    #[test]
    #[traced_test]
    fn log_results__should_warn_when_no_providers_were_probed() {
        // Given only skipped rows — nothing was actually probed
        let results = vec![ProviderResult {
            chain: "base",
            provider: "-".to_string(),
            status: Status::Skipped("not configured".to_string()),
        }];

        // When
        log_results(&results);

        // Then a check that verified nothing is flagged loudly, not reported as 0/0
        logs_assert(|lines: &[&str]| {
            match lines
                .iter()
                .any(|l| l.contains("WARN") && l.contains("probed no providers"))
            {
                true => Ok(()),
                false => Err("expected a WARN when nothing was probed".to_string()),
            }
        });
    }
}
