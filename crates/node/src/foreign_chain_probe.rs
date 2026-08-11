//! Startup probe of every configured foreign-chain RPC provider, via
//! [`foreign_chain_health_check::probe`].

use std::collections::BTreeSet;

use foreign_chain_health_check::probe::{
    ProbeReport, ProviderHealth, ProviderStatus, probe_all_providers,
};
use mpc_node_config::ForeignChainsConfig;
use near_mpc_contract_interface::types as dtos;
use tracing::{debug, info, warn};

use crate::metrics;

/// Asks every configured provider which network it serves and logs a line per provider plus an
/// `x/y providers healthy` summary. Diagnostic only: a provider on the wrong network keeps
/// serving, because a boot time blip should not take a chain out of signing.
pub async fn run_startup_probe(foreign_chains: ForeignChainsConfig) {
    if foreign_chains.is_empty() {
        debug!("no foreign chain is configured, skipping the RPC provider probe");
        return;
    }

    info!("probing foreign-chain RPC providers");
    let report = probe_all_providers(&foreign_chains).await;
    publish_metrics(&report);
    log_report(&report);
}

/// Whether any probe covers this provider. What none covers stays out of both the summary and the
/// gauges: it would otherwise read as an unhealthy provider for as long as the chain has no probe.
fn is_probed(row: &ProviderHealth) -> bool {
    row.status != ProviderStatus::ProbeNotImplemented
}

struct Summary {
    probed: usize,
    healthy: usize,
}

fn summarize(rows: &[ProviderHealth]) -> Summary {
    Summary {
        probed: rows.iter().filter(|row| is_probed(row)).count(),
        healthy: rows.iter().filter(|row| row.status.is_healthy()).count(),
    }
}

/// A [`ProviderStatus`] carries no auth material and no rendered error text, and its one
/// provider written field is length capped, so it is logged whole.
fn log_report(report: &ProbeReport) {
    let rows = report.rows();
    for row in rows {
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

    let Summary { probed, healthy } = summarize(rows);
    if probed == 0 {
        warn!(
            "foreign-chain RPC provider probe found nothing to probe: no configured chain supports it"
        );
        return;
    }
    info!("foreign-chain RPC provider probe complete: {healthy}/{probed} providers healthy");
}

/// Publish healthy/Configured counts per chain
fn publish_metrics(report: &ProbeReport) {
    let probed_chains: BTreeSet<dtos::ForeignChain> = report
        .rows()
        .iter()
        .filter(|row| is_probed(row))
        .map(|row| row.chain)
        .collect();

    for (chain, counts) in report.counts_per_chain() {
        if !probed_chains.contains(&chain) {
            continue;
        }
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
    use prometheus::core::Collector as _;
    use std::num::NonZeroU64;

    const CLOSED_PORT_URL: &str = "http://127.0.0.1:9";
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

    /// The chains a gauge holds a series for.
    fn labelled_chains(gauge: &prometheus::IntGaugeVec) -> Vec<String> {
        gauge
            .collect()
            .iter()
            .flat_map(|family| family.get_metric())
            .flat_map(|metric| metric.get_label())
            .map(|label| label.value().to_string())
            .collect()
    }

    fn row(chain: dtos::ForeignChain, status: ProviderStatus) -> ProviderHealth {
        ProviderHealth {
            chain,
            provider: dtos::ProviderId("only".to_string()),
            status,
        }
    }

    /// Solana has no probe, so its provider belongs in neither total.
    #[test]
    fn summarize__should_count_only_the_providers_a_probe_covers() {
        // Given
        let rows = [
            row(dtos::ForeignChain::Base, ProviderStatus::Healthy),
            row(dtos::ForeignChain::Bnb, ProviderStatus::Unreachable),
            row(
                dtos::ForeignChain::Solana,
                ProviderStatus::ProbeNotImplemented,
            ),
        ];

        // When
        let summary = summarize(&rows);

        // Then
        assert_eq!((summary.healthy, summary.probed), (1, 2));
    }

    #[test]
    fn summarize__should_count_nothing_probed_when_no_chain_has_a_probe() {
        // Given
        let rows = [row(
            dtos::ForeignChain::Solana,
            ProviderStatus::ProbeNotImplemented,
        )];

        // When
        let summary = summarize(&rows);

        // Then
        assert_eq!(summary.probed, 0);
    }

    #[tokio::test]
    async fn run_startup_probe__should_publish_the_provider_counts_per_chain() {
        // Given
        let foreign_chains = ForeignChainsConfig {
            aptos: Some(chain_config(ANY_FINGERPRINT, CLOSED_PORT_URL)),
            ..Default::default()
        };

        // When
        run_startup_probe(foreign_chains).await;

        // Then — unreachable, so configured counts it and healthy does not.
        let counts = |gauge: &prometheus::IntGaugeVec| gauge.with_label_values(&["aptos"]).get();
        assert_eq!(counts(&metrics::FOREIGN_CHAIN_RPC_PROVIDERS_CONFIGURED), 1);
        assert_eq!(counts(&metrics::FOREIGN_CHAIN_RPC_PROVIDERS_HEALTHY), 0);
    }

    /// A `0` healthy for a chain no probe covers would read as every provider failing.
    #[tokio::test]
    async fn run_startup_probe__should_publish_no_counts_for_an_unprobeable_chain() {
        // Given
        let foreign_chains = ForeignChainsConfig {
            bnb: Some(chain_config(ANY_FINGERPRINT, CLOSED_PORT_URL)),
            solana: Some(chain_config(ANY_FINGERPRINT, CLOSED_PORT_URL)),
            ..Default::default()
        };

        // When
        run_startup_probe(foreign_chains).await;

        // Then
        let chains = labelled_chains(&metrics::FOREIGN_CHAIN_RPC_PROVIDERS_CONFIGURED);
        assert!(chains.contains(&"bnb".to_string()));
        assert!(!chains.contains(&"solana".to_string()));
    }
}
