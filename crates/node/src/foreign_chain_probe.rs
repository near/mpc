//! Startup probe of every configured foreign-chain RPC provider, via
//! [`foreign_chain_health_check::probe`].

use std::panic::AssertUnwindSafe;

use foreign_chain_health_check::probe::{ProbeReport, ProviderStatus, probe_all_providers};
use futures::FutureExt as _;
use mpc_node_config::ForeignChainsConfig;
use tracing::{debug, error, info, warn};

/// Asks every configured provider which network it serves and logs a line per provider plus an
/// `x/y providers healthy` summary. Diagnostic only: a provider on the wrong network keeps
/// serving, because a boot time blip should not take a chain out of signing.
///
/// A panic is caught and logged rather than vanishing with the spawned task's dropped handle.
pub async fn run_startup_probe(foreign_chains: ForeignChainsConfig) {
    let probe = async move {
        info!("probing foreign-chain RPC providers");
        log_report(&probe_all_providers(&foreign_chains).await);
    };

    if AssertUnwindSafe(probe).catch_unwind().await.is_err() {
        error!("foreign-chain RPC provider probe panicked (diagnostic only; node unaffected)");
    }
}

/// A [`ProviderStatus`] carries no provider text and no auth material, so it is logged whole.
fn log_report(report: &ProbeReport) {
    for row in report.rows() {
        match &row.status {
            ProviderStatus::Healthy => debug!(
                chain = ?row.chain,
                provider = %row.provider,
                "foreign-chain RPC provider serves the expected network",
            ),
            ProviderStatus::ProbeNotImplemented => debug!(
                chain = ?row.chain,
                provider = %row.provider,
                "foreign-chain RPC provider cannot be probed",
            ),
            unhealthy => warn!(
                chain = ?row.chain,
                provider = %row.provider,
                status = ?unhealthy,
                "foreign-chain RPC provider is unhealthy",
            ),
        }
    }

    let counts = report.counts_per_chain();
    let configured: usize = counts.values().map(|count| count.configured).sum();
    if configured == 0 {
        warn!("foreign-chain RPC provider probe found nothing to probe: no chain is configured");
        return;
    }
    let healthy: usize = counts.values().map(|count| count.healthy).sum();
    info!("foreign-chain RPC provider probe complete: {healthy}/{configured} providers healthy");
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use mpc_node_config::{AuthConfig, ForeignChainConfig, ForeignChainProviderConfig};
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use std::num::NonZeroU64;
    use tracing_test::traced_test;

    /// Reserved as "discard", so nothing listens there.
    const CLOSED_PORT_URL: &str = "http://127.0.0.1:9";

    fn chain_config(expected: &str, rpc_url: &str) -> ForeignChainConfig {
        ForeignChainConfig {
            timeout_sec: NonZeroU64::new(1).unwrap(),
            max_retries: NonZeroU64::new(1).unwrap(),
            expected_network_fingerprint: Some(expected.to_string()),
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
    async fn run_startup_probe__should_probe_every_configured_provider() {
        // Given
        let foreign_chains = ForeignChainsConfig {
            base: Some(chain_config("8453", CLOSED_PORT_URL)),
            ..Default::default()
        };

        // When
        run_startup_probe(foreign_chains).await;

        // Then
        assert!(logs_contain("probing foreign-chain RPC providers"));
        assert!(logs_contain(
            "foreign-chain RPC provider probe complete: 0/1 providers healthy"
        ));
    }

    #[tokio::test]
    #[traced_test]
    async fn run_startup_probe__should_warn_when_no_chain_is_configured() {
        // Given
        let foreign_chains = ForeignChainsConfig::default();

        // When
        run_startup_probe(foreign_chains).await;

        // Then
        assert!(logs_contain("no chain is configured"));
    }

    #[tokio::test]
    #[traced_test]
    async fn run_startup_probe__should_name_the_unhealthy_provider_and_its_status() {
        // Given
        let foreign_chains = ForeignChainsConfig {
            base: Some(chain_config("8453", CLOSED_PORT_URL)),
            ..Default::default()
        };

        // When
        run_startup_probe(foreign_chains).await;

        // Then
        assert!(logs_contain("foreign-chain RPC provider is unhealthy"));
        assert!(logs_contain("Unreachable"));
    }
}
