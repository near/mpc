use std::time::Duration;

use foreign_chain_inspector::{ProviderFailure, RecordProviderCall};
use near_mpc_contract_interface::types::{ForeignChain, ProviderId};

use crate::metrics;

pub(super) struct ProviderCallMetrics {
    chain: ForeignChain,
}

impl ProviderCallMetrics {
    pub(super) fn new<'a>(
        chain: ForeignChain,
        providers: impl IntoIterator<Item = &'a ProviderId>,
    ) -> Self {
        for provider in providers {
            metrics::MPC_FOREIGN_CHAIN_PROVIDER_INSPECTION_SECONDS
                .with_label_values(&[chain.label(), &provider.0]);
            for kind in metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERROR_KINDS {
                metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERRORS_TOTAL.with_label_values(&[
                    chain.label(),
                    &provider.0,
                    kind,
                ]);
            }
        }
        Self { chain }
    }
}

impl RecordProviderCall for ProviderCallMetrics {
    fn record(&self, provider: &ProviderId, elapsed: Duration, failure: Option<ProviderFailure>) {
        let Some(failure) = failure else {
            metrics::MPC_FOREIGN_CHAIN_PROVIDER_INSPECTION_SECONDS
                .with_label_values(&[self.chain.label(), &provider.0])
                .observe(elapsed.as_secs_f64());
            return;
        };
        let kind = match failure {
            ProviderFailure::Unreachable => metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERROR_TRANSIENT,
            ProviderFailure::Rejected | ProviderFailure::Malformed => {
                metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERROR_NON_TRANSIENT
            }
            ProviderFailure::TimedOut => metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERROR_TIMEOUT,
        };
        metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERRORS_TOTAL
            .with_label_values(&[self.chain.label(), &provider.0, kind])
            .inc();
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use prometheus::Encoder;

    const PROVIDER: &str = "a-provider";

    /// The registry is process global, so each test records under its own chain label.
    #[test]
    fn provider_call_metrics__should_time_answers_and_count_failures() {
        // Given
        let chain = ForeignChain::Bitcoin;
        let provider = ProviderId(PROVIDER.to_string());
        let recorder = ProviderCallMetrics::new(chain, [&provider]);

        // When
        for failure in [
            None,
            Some(ProviderFailure::Unreachable),
            Some(ProviderFailure::Rejected),
            Some(ProviderFailure::Malformed),
            Some(ProviderFailure::TimedOut),
        ] {
            recorder.record(&provider, Duration::from_millis(10), failure);
        }

        // Then
        let timed = metrics::MPC_FOREIGN_CHAIN_PROVIDER_INSPECTION_SECONDS
            .with_label_values(&[chain.label(), PROVIDER])
            .get_sample_count();
        assert_eq!(timed, 1);
        let counted = |kind: &str| {
            metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERRORS_TOTAL
                .with_label_values(&[chain.label(), PROVIDER, kind])
                .get()
        };
        assert_eq!(
            counted(metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERROR_TRANSIENT),
            1
        );
        assert_eq!(
            counted(metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERROR_NON_TRANSIENT),
            2
        );
        assert_eq!(
            counted(metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERROR_TIMEOUT),
            1
        );
    }

    #[test]
    fn provider_call_metrics_new__should_publish_every_series_before_the_first_call() {
        // When
        let _recorder =
            ProviderCallMetrics::new(ForeignChain::Ethereum, [&ProviderId(PROVIDER.to_string())]);

        // Then
        let mut buffer = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&prometheus::default_registry().gather(), &mut buffer)
            .unwrap();
        let exposed = String::from_utf8(buffer).unwrap();
        let series = |metric: &str| {
            exposed
                .lines()
                .filter(|line| line.starts_with(metric) && line.contains(r#"chain="ethereum""#))
                .count()
        };
        assert_eq!(
            series("mpc_foreign_chain_provider_inspection_seconds_count"),
            1
        );
        assert_eq!(series("mpc_foreign_chain_provider_errors_total"), 3);
    }
}
