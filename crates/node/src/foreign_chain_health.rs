//! Healthcheck of every configured foreign-chain RPC provider, via
//! [`foreign_chain_health_check`].

use std::panic::AssertUnwindSafe;

use foreign_chain_health_check::{ExpectedIdentities, ProviderResult, Status, check_all_providers};
use futures::FutureExt as _;
use mpc_node_config::ForeignChainsConfig;
use tracing::{debug, error, info, warn};

/// Startup healthcheck entrypoint: probes every configured provider against its configured
/// expected identity ([`foreign_chain_health_check`]) and logs a per-provider result plus an
/// `x/y providers healthy` summary. A probe panic is caught and logged, never propagated
/// (the check is diagnostic-only; the node runs regardless).
pub async fn run_startup_health_check(
    foreign_chains: ForeignChainsConfig,
    identities: ExpectedIdentities,
) {
    // Catch a probe panic (e.g. an inspector bug) and log it, rather than letting it vanish
    // with the spawned task's dropped join handle.
    let probe = async move {
        info!("running foreign-chain RPC provider health check");
        let results = check_all_providers(&foreign_chains, &identities).await;
        log_results(&results);
    };

    if AssertUnwindSafe(probe).catch_unwind().await.is_err() {
        error!(
            "foreign-chain RPC provider health check panicked (diagnostic-only; node unaffected)"
        );
    }
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
    use mpc_node_config::{AuthConfig, ForeignChainConfig, ForeignChainProviderConfig};
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

    #[tokio::test]
    #[traced_test]
    async fn run_startup_health_check__should_probe_configured_providers_against_their_identity() {
        // Given a `base` provider with a configured identity but nothing listening on the URL
        // (connection refused, no external traffic)
        let foreign_chains = ForeignChainsConfig {
            base: Some(chain_config("http://127.0.0.1:1")),
            ..Default::default()
        };
        let identities = ExpectedIdentities {
            base: Some("8453".to_string()),
            ..Default::default()
        };

        // When
        run_startup_health_check(foreign_chains, identities).await;

        // Then the probe runs end to end and summarizes the one probed provider (it fails to
        // connect, so 0 of 1 are healthy)
        assert!(logs_contain(
            "running foreign-chain RPC provider health check"
        ));
        assert!(logs_contain(
            "foreign-chain RPC provider health check complete: 0/1 providers healthy"
        ));
    }

    #[test]
    #[traced_test]
    fn log_results__should_not_log_the_failure_reason() {
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
