//! Startup probe of every configured foreign-chain RPC provider, via
//! [`foreign_chain_health_check::probe`].

use std::panic::AssertUnwindSafe;

use foreign_chain_health_check::probe::{ProbeReport, ProviderStatus, probe_all_providers};
use futures::FutureExt as _;
use mpc_node_config::ForeignChainsConfig;
use tracing::{debug, error, info, warn};

use crate::metrics;

/// Asks every configured provider which network it serves and logs a line per provider plus an
/// `x/y providers healthy` summary. Diagnostic only: a provider on the wrong network keeps
/// serving, because a boot time blip should not take a chain out of signing.
///
/// A panic is caught and logged rather than vanishing with the spawned task's dropped handle.
pub async fn run_startup_probe(foreign_chains: ForeignChainsConfig) {
    let probe = async move {
        info!("probing foreign-chain RPC providers");
        let report = probe_all_providers(&foreign_chains).await;
        publish_metrics(&report);
        log_report(&report);
    };

    if AssertUnwindSafe(probe).catch_unwind().await.is_err() {
        error!("foreign-chain RPC provider probe panicked (diagnostic only; node unaffected)");
    }
}

/// A [`ProviderStatus`] carries no auth material and no rendered error text, and its one
/// provider written field is length capped, so it is logged whole.
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

    // A provider no probe can reach counts in neither total: it would otherwise hold the summary
    // below full forever on a node that configures a chain the probe cannot identify.
    let rows = report.rows();
    let probed = rows
        .iter()
        .filter(|row| row.status != ProviderStatus::ProbeNotImplemented)
        .count();
    if probed == 0 {
        warn!(
            "foreign-chain RPC provider probe found nothing to probe: no configured chain supports it"
        );
        return;
    }
    let healthy = rows.iter().filter(|row| row.status.is_healthy()).count();
    info!("foreign-chain RPC provider probe complete: {healthy}/{probed} providers healthy");
}

/// Per chain rather than per provider: a provider id is operator chosen, so it would put an
/// unbounded label on a time series.
fn publish_metrics(report: &ProbeReport) {
    for (chain, counts) in report.counts_per_chain() {
        metrics::FOREIGN_CHAIN_RPC_PROVIDERS_CONFIGURED
            .with_label_values(&[chain.label()])
            .set(counts.configured as i64);
        metrics::FOREIGN_CHAIN_RPC_PROVIDERS_HEALTHY
            .with_label_values(&[chain.label()])
            .set(counts.healthy as i64);
    }
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
    /// For a chain with no probe: the value is never read, only whether it is set at all.
    const ANY_FINGERPRINT: &str = "any-fingerprint";

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
        assert!(logs_contain("found nothing to probe"));
    }

    /// Solana has no probe, so its providers belong in neither side of the summary.
    #[tokio::test]
    #[traced_test]
    async fn run_startup_probe__should_leave_an_unprobeable_chain_out_of_the_summary() {
        // Given — two configured providers, only one of them probeable.
        let foreign_chains = ForeignChainsConfig {
            base: Some(chain_config("8453", CLOSED_PORT_URL)),
            solana: Some(chain_config(ANY_FINGERPRINT, CLOSED_PORT_URL)),
            ..Default::default()
        };

        // When
        run_startup_probe(foreign_chains).await;

        // Then
        assert!(logs_contain("probe complete: 0/1 providers healthy"));
    }

    #[tokio::test]
    #[traced_test]
    async fn run_startup_probe__should_warn_when_no_configured_chain_can_be_probed() {
        // Given
        let foreign_chains = ForeignChainsConfig {
            solana: Some(chain_config(ANY_FINGERPRINT, CLOSED_PORT_URL)),
            ..Default::default()
        };

        // When
        run_startup_probe(foreign_chains).await;

        // Then
        assert!(logs_contain("found nothing to probe"));
    }

    #[tokio::test]
    async fn run_startup_probe__should_publish_the_provider_counts_per_chain() {
        // Given
        let foreign_chains = ForeignChainsConfig {
            aptos: Some(chain_config("1", CLOSED_PORT_URL)),
            ..Default::default()
        };

        // When
        run_startup_probe(foreign_chains).await;

        // Then — unreachable, so configured counts it and healthy does not.
        let counts = |gauge: &prometheus::IntGaugeVec| gauge.with_label_values(&["aptos"]).get();
        assert_eq!(counts(&metrics::FOREIGN_CHAIN_RPC_PROVIDERS_CONFIGURED), 1);
        assert_eq!(counts(&metrics::FOREIGN_CHAIN_RPC_PROVIDERS_HEALTHY), 0);
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
