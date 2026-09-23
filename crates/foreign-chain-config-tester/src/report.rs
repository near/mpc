//! Human readable table rendering of a probe report.

use std::borrow::Cow;
use std::fmt::Write as _;

use foreign_chain_health_check::probe::{ProbeReport, ProviderStatus};
use mpc_node_config::ForeignChainsConfig;

enum Outcome {
    Passed,
    Failed,
    Skipped,
}

fn outcome(status: Option<&ProviderStatus>) -> Outcome {
    match status {
        None => Outcome::Skipped,
        Some(status) if status.is_healthy() => Outcome::Passed,
        Some(status) if status.was_probed() => Outcome::Failed,
        Some(_) => Outcome::Skipped,
    }
}

/// Whether any probed provider is unhealthy. A chain no probe covers does not count, matching the
/// node's healthy count.
pub fn any_failed(report: &ProbeReport) -> bool {
    report
        .rows()
        .iter()
        .any(|row| matches!(outcome(Some(&row.status)), Outcome::Failed))
}

/// The tester's wording for a status in the `RESULT` column and the failure list. Carries no URL
/// or token.
fn reason(status: &ProviderStatus) -> Cow<'static, str> {
    match status {
        ProviderStatus::Healthy => "serves the expected network".into(),
        ProviderStatus::WrongNetwork { expected, observed } => {
            format!("wrong network: expected `{expected}`, provider reports `{observed}`").into()
        }
        ProviderStatus::Unreachable => {
            "unreachable: DNS, TLS, connection refused, 5xx, or rate limited".into()
        }
        ProviderStatus::RequestRejected => {
            "request rejected: credentials invalid, or not enabled for this chain".into()
        }
        ProviderStatus::MalformedResponse => "malformed response".into(),
        ProviderStatus::TimedOut => "timed out on every attempt".into(),
        ProviderStatus::AuthTokenUnresolved => "auth token environment variable is not set".into(),
        ProviderStatus::ClientSetupFailed => "client setup failed: check rpc_url and auth".into(),
        ProviderStatus::MissingExpectedFingerprint => {
            "expected_network_fingerprint is not set for this chain".into()
        }
        ProviderStatus::ProbeNotImplemented => "no probe for this chain".into(),
    }
}

/// A table row: a probed provider, or the placeholder for a chain absent from the config.
struct Line {
    chain: &'static str,
    provider: String,
    status: Option<ProviderStatus>,
}

impl Line {
    fn result(&self) -> String {
        match outcome(self.status.as_ref()) {
            Outcome::Passed => "✓ ok".to_string(),
            Outcome::Failed => "✗ failed".to_string(),
            Outcome::Skipped => match &self.status {
                Some(status) => format!("– skipped ({})", reason(status)),
                None => "– skipped (not configured)".to_string(),
            },
        }
    }

    fn failure(&self) -> Option<&ProviderStatus> {
        match outcome(self.status.as_ref()) {
            Outcome::Failed => self.status.as_ref(),
            _ => None,
        }
    }
}

fn lines(config: &ForeignChainsConfig, report: &ProbeReport) -> Vec<Line> {
    let mut lines: Vec<Line> = config
        .chain_slots()
        .flat_map(|(chain, chain_config)| {
            let label = chain.label();
            if chain_config.is_none() {
                return vec![Line {
                    chain: label,
                    provider: "-".to_string(),
                    status: None,
                }];
            }
            report
                .rows()
                .iter()
                .filter(|row| row.chain == chain)
                .map(|row| Line {
                    chain: label,
                    provider: row.provider.to_string(),
                    status: Some(row.status.clone()),
                })
                .collect()
        })
        .collect();
    // Probe results arrive in completion order, so the table is ordered alphabetically by chain,
    // then provider, to stay stable across runs.
    lines.sort_by_key(|line| (line.chain, line.provider.clone()));
    lines
}

/// One row per configured provider and a placeholder per chain absent from `config`, then a
/// summary. Failure reasons go below the table rather than into the `RESULT` column, so long text
/// cannot break the alignment.
pub fn render(config: &ForeignChainsConfig, report: &ProbeReport) -> String {
    let lines = lines(config, report);
    let chain_w = lines
        .iter()
        .map(|line| line.chain.len())
        .max()
        .unwrap_or(0)
        .max("CHAIN".len());
    let provider_w = lines
        .iter()
        .map(|line| line.provider.len())
        .max()
        .unwrap_or(0)
        .max("PROVIDER".len());

    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<chain_w$}  {:<provider_w$}  RESULT",
        "CHAIN", "PROVIDER",
    );

    let (mut passed, mut failed, mut skipped) = (0usize, 0usize, 0usize);
    for line in &lines {
        match outcome(line.status.as_ref()) {
            Outcome::Passed => passed += 1,
            Outcome::Failed => failed += 1,
            Outcome::Skipped => skipped += 1,
        }
        let _ = writeln!(
            out,
            "{:<chain_w$}  {:<provider_w$}  {}",
            line.chain,
            line.provider,
            line.result(),
        );
    }

    let _ = writeln!(out, "\n{passed} passed, {failed} failed, {skipped} skipped");

    if failed > 0 {
        let _ = writeln!(out, "\nFailures:");
        for (line, status) in lines
            .iter()
            .filter_map(|line| line.failure().map(|status| (line, reason(status))))
        {
            let _ = writeln!(out, "  {} / {}: {status}", line.chain, line.provider);
        }
    }

    if config.is_empty() {
        let _ = writeln!(
            out,
            "\nNo foreign chain is configured: this node cannot verify foreign chain transactions."
        );
    }

    out
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use foreign_chain_health_check::probe::ProviderHealth;
    use mpc_node_config::{AuthConfig, ForeignChainConfig, ForeignChainProviderConfig};
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use near_mpc_contract_interface::types::{ForeignChain, ProviderId};
    use std::num::NonZeroU64;

    fn section() -> ForeignChainConfig {
        ForeignChainConfig {
            timeout_sec: NonZeroU64::new(1).unwrap(),
            max_retries: NonZeroU64::new(1).unwrap(),
            expected_network_fingerprint: None,
            providers: NonEmptyBTreeMap::new(
                "only".to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url: "https://rpc.example.com".to_string(),
                    auth: AuthConfig::None,
                },
            ),
        }
    }

    fn row(chain: ForeignChain, provider: &str, status: ProviderStatus) -> ProviderHealth {
        ProviderHealth {
            chain,
            provider: ProviderId(provider.to_string()),
            status,
        }
    }

    fn configurable_chains() -> usize {
        ForeignChainsConfig::default().chain_slots().count()
    }

    fn row_for<'a>(table: &'a str, chain: &str, provider: &str) -> &'a str {
        table
            .lines()
            .find(|line| line.starts_with(chain) && line.contains(provider))
            .unwrap_or_else(|| panic!("no row for {chain} / {provider} in:\n{table}"))
    }

    #[test]
    fn render__should_print_one_row_per_configured_provider() {
        // Given
        let config = ForeignChainsConfig {
            base: Some(section()),
            ..Default::default()
        };
        let report = ProbeReport::from(vec![
            row(ForeignChain::Base, "alchemy", ProviderStatus::Healthy),
            row(ForeignChain::Base, "quicknode", ProviderStatus::Unreachable),
        ]);

        // When
        let table = render(&config, &report);

        // Then
        assert!(row_for(&table, "base", "alchemy").ends_with("✓ ok"));
        assert!(row_for(&table, "base", "quicknode").ends_with("✗ failed"));
        let summary = format!("1 passed, 1 failed, {} skipped", configurable_chains() - 1);
        assert!(table.contains(&summary), "{table}");
    }

    #[test]
    fn render__should_order_rows_by_chain_then_provider() {
        // Given — providers arrive in completion order, not alphabetical order.
        let config = ForeignChainsConfig {
            aptos: Some(section()),
            base: Some(section()),
            ..Default::default()
        };
        let report = ProbeReport::from(vec![
            row(ForeignChain::Aptos, "quicknode", ProviderStatus::Healthy),
            row(ForeignChain::Base, "official", ProviderStatus::Healthy),
            row(ForeignChain::Aptos, "alchemy", ProviderStatus::Healthy),
            row(ForeignChain::Aptos, "geomi", ProviderStatus::Healthy),
        ]);

        // When
        let table = render(&config, &report);

        // Then
        let rows: Vec<&str> = table
            .lines()
            .filter(|line| line.starts_with("aptos") || line.starts_with("base"))
            .collect();
        let order: Vec<String> = rows
            .iter()
            .map(|line| {
                line.split_whitespace()
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect();
        assert_eq!(
            order,
            [
                "aptos alchemy",
                "aptos geomi",
                "aptos quicknode",
                "base official",
            ]
        );
    }

    #[test]
    fn render__should_add_a_placeholder_row_for_each_unconfigured_chain() {
        // Given
        let config = ForeignChainsConfig::default();
        let report = ProbeReport::from(vec![]);

        // When
        let table = render(&config, &report);

        // Then
        let placeholders = table
            .lines()
            .filter(|line| line.ends_with("– skipped (not configured)"))
            .count();
        assert_eq!(placeholders, configurable_chains());
        let summary = format!("0 passed, 0 failed, {} skipped", configurable_chains());
        assert!(table.contains(&summary), "{table}");
        assert!(table.contains("No foreign chain is configured"), "{table}");
    }

    #[test]
    fn render__should_list_failure_reasons_below_the_table() {
        // Given
        let config = ForeignChainsConfig {
            base: Some(section()),
            ..Default::default()
        };
        let report = ProbeReport::from(vec![row(
            ForeignChain::Base,
            "alchemy",
            ProviderStatus::MissingExpectedFingerprint,
        )]);

        // When
        let table = render(&config, &report);

        // Then
        let expected = format!(
            "base / alchemy: {}",
            reason(&ProviderStatus::MissingExpectedFingerprint)
        );
        assert!(table.contains("Failures:"), "{table}");
        assert!(table.contains(&expected), "{table}");
        assert!(!table.contains("No foreign chain is configured"), "{table}");
    }

    #[test]
    fn render__should_count_a_chain_without_a_probe_as_skipped() {
        // Given
        let config = ForeignChainsConfig {
            solana: Some(section()),
            ..Default::default()
        };
        let report = ProbeReport::from(vec![row(
            ForeignChain::Solana,
            "only",
            ProviderStatus::ProbeNotImplemented,
        )]);

        // When
        let table = render(&config, &report);

        // Then
        let expected = format!(
            "– skipped ({})",
            reason(&ProviderStatus::ProbeNotImplemented)
        );
        assert!(row_for(&table, "solana", "only").ends_with(&expected));
        let summary = format!("0 passed, 0 failed, {} skipped", configurable_chains());
        assert!(table.contains(&summary), "{table}");
        assert!(!table.contains("Failures:"), "{table}");
    }

    #[test]
    fn any_failed__should_count_only_probed_unhealthy_statuses() {
        // Given
        let healthy_and_skipped = ProbeReport::from(vec![
            row(ForeignChain::Base, "a", ProviderStatus::Healthy),
            row(
                ForeignChain::Solana,
                "b",
                ProviderStatus::ProbeNotImplemented,
            ),
        ]);
        let failing = ProbeReport::from(vec![row(
            ForeignChain::Base,
            "a",
            ProviderStatus::MissingExpectedFingerprint,
        )]);

        // When
        let healthy = any_failed(&healthy_and_skipped);
        let failed = any_failed(&failing);

        // Then
        assert!(!healthy);
        assert!(failed);
    }
}
