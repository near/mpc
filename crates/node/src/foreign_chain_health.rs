//! Healthcheck of every configured foreign-chain RPC provider, via
//! [`foreign_chain_health_check`].

use foreign_chain_health_check::{
    NetworkResolution, ProviderResult, SkipReason, Status, check_all_providers,
};
use mpc_node_config::ForeignChainsConfig;
use tracing::{debug, info, warn};

/// Healthcheck entrypoint, dispatched from startup.
pub async fn run_startup_health_check(
    foreign_chains: ForeignChainsConfig,
    network: NetworkResolution,
) {
    let network = match network {
        NetworkResolution::Probe(network) => network,
        NetworkResolution::Skip(SkipReason::LocalChain) => {
            debug!("local or custom chain; skipping foreign-chain RPC provider health check");
            return;
        }
        NetworkResolution::Skip(SkipReason::Undetermined) => {
            warn!("network undetermined; skipping foreign-chain RPC provider health check");
            return;
        }
    };

    info!(
        network = network.label(),
        "running foreign-chain RPC provider health check"
    );
    let results = check_all_providers(&foreign_chains, network).await;
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
    info!(
        "foreign-chain RPC provider health check complete: {healthy}/{checked} providers healthy"
    );
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use mpc_node_config::{AuthConfig, ForeignChainConfig, ForeignChainProviderConfig};
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use std::num::NonZeroU64;
    use tracing_test::traced_test;

    fn config_with_unsupported_chain() -> ForeignChainsConfig {
        ForeignChainsConfig {
            ethereum: Some(ForeignChainConfig {
                timeout_sec: NonZeroU64::new(5).unwrap(),
                max_retries: NonZeroU64::new(1).unwrap(),
                providers: NonEmptyBTreeMap::new(
                    "only".to_string().into(),
                    ForeignChainProviderConfig {
                        rpc_url: "https://rpc.example.com".to_string(),
                        auth: AuthConfig::None,
                    },
                ),
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
        run_startup_health_check(
            foreign_chains,
            NetworkResolution::Skip(SkipReason::Undetermined),
        )
        .await;

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
        run_startup_health_check(
            foreign_chains,
            NetworkResolution::Skip(SkipReason::LocalChain),
        )
        .await;

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
}
