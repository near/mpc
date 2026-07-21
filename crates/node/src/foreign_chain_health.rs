//! Healthcheck of every configured foreign-chain RPC provider, via
//! [`foreign_chain_health_check`].

use foreign_chain_health_check::{
    HealthCheckPlan, NetworkKind, ProviderResult, SkipReason, Status, check_all_providers,
    check_all_providers_with_golden,
};
use mpc_node_config::{ForeignChainsConfig, HealthCheckGoldenConfig};
use tracing::{debug, info, warn};

/// Healthcheck entrypoint, dispatched from startup. Folds the operator's config
/// (`network` + optional golden) into a [`HealthCheckPlan`] and runs it: probes
/// with the built-in set on a public network, with the supplied golden on a local
/// chain, or skips. Warns when a golden is configured on a public network, where
/// it is ignored.
pub async fn run_startup_health_check(
    foreign_chains: ForeignChainsConfig,
    network: NetworkKind,
    golden: Option<HealthCheckGoldenConfig>,
) {
    // A config-supplied golden is only meaningful on a local chain; on
    // mainnet/testnet the built-in set is always used, so flag it as ignored.
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

    let results = match HealthCheckPlan::decide(network, golden) {
        HealthCheckPlan::ProbeBuiltIn(network) => {
            info!(
                network = network.label(),
                "running foreign-chain RPC provider health check"
            );
            check_all_providers(&foreign_chains, network).await
        }
        HealthCheckPlan::ProbeSupplied(golden) => {
            info!(
                "running foreign-chain RPC provider health check with config-supplied golden values"
            );
            check_all_providers_with_golden(&foreign_chains, &golden).await
        }
        HealthCheckPlan::Skip(SkipReason::LocalChainWithoutGolden) => {
            debug!(
                "local or custom chain without golden values; \
                 skipping foreign-chain RPC provider health check"
            );
            return;
        }
        HealthCheckPlan::Skip(SkipReason::Undetermined) => {
            warn!("network undetermined; skipping foreign-chain RPC provider health check");
            return;
        }
    };
    log_results(&results);
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

        // When
        run_startup_health_check(foreign_chains, NetworkKind::Undetermined, None).await;

        // Then it is flagged loudly (a real deployment that can't resolve its network)
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
    }

    #[tokio::test]
    #[traced_test]
    async fn run_startup_health_check__should_skip_quietly_on_a_local_chain() {
        // Given a known local/dev chain (no golden vectors)
        let foreign_chains = config_with_unsupported_chain();

        // When
        run_startup_health_check(foreign_chains, NetworkKind::Local, None).await;

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

        // When
        run_startup_health_check(foreign_chains, NetworkKind::Local, Some(base_golden())).await;

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

        // When
        run_startup_health_check(
            foreign_chains,
            NetworkKind::Public(foreign_chain_health_check::Network::Mainnet),
            None,
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

        // When
        run_startup_health_check(
            foreign_chains,
            NetworkKind::Public(foreign_chain_health_check::Network::Mainnet),
            Some(base_golden()),
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
