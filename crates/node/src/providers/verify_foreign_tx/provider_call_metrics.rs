use std::collections::BTreeMap;

use foreign_chain_inspector::{ObserveProviderCall, ProviderFailure, TimeProviderCall};
use near_mpc_contract_interface::types::{ForeignChain, ProviderId};
use prometheus::HistogramTimer;

use crate::metrics;

/// Records provider calls under pseudonymous labels (`p0`, `p1`, ...). The `/metrics`
/// endpoint is public, so real provider names would reveal which RPC vendors the node uses.
#[derive(Clone)]
pub(crate) struct ProviderCallMetrics {
    chain: ForeignChain,
    labels: BTreeMap<ProviderId, String>,
}

impl ProviderCallMetrics {
    pub(super) fn new<'a>(
        chain: ForeignChain,
        providers: impl IntoIterator<Item = &'a ProviderId>,
    ) -> Self {
        let mut names: Vec<_> = providers.into_iter().collect();
        names.sort();
        let labels: BTreeMap<_, _> = names
            .into_iter()
            .enumerate()
            .map(|(index, provider)| (provider.clone(), format!("p{index}")))
            .collect();
        for label in labels.values() {
            for outcome in Outcome::ALL {
                metrics::MPC_FOREIGN_CHAIN_PROVIDER_INSPECTION_SECONDS.with_label_values(&[
                    chain.label(),
                    label,
                    outcome.label(),
                ]);
            }
            metrics::MPC_FOREIGN_CHAIN_PROVIDER_DROPPED_SECONDS
                .with_label_values(&[chain.label(), label]);
            for kind in Kind::ALL {
                metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERRORS_TOTAL.with_label_values(&[
                    chain.label(),
                    label,
                    kind.label(),
                ]);
            }
        }
        Self { chain, labels }
    }
}

impl TimeProviderCall for ProviderCallMetrics {
    fn start_timer(&self, provider: &ProviderId) -> impl ObserveProviderCall {
        // The node builds the fan-out and this recorder from the same provider list, so an
        // unknown provider is unreachable in practice. Should it happen, the call goes
        // unrecorded rather than panicking.
        let Some(label) = self.labels.get(provider) else {
            tracing::debug!(
                chain = self.chain.label(),
                %provider,
                "provider call started for an unknown provider; not recording it"
            );
            return ProviderCallTimer(None);
        };
        let timer = metrics::MPC_FOREIGN_CHAIN_PROVIDER_DROPPED_SECONDS
            .with_label_values(&[self.chain.label(), label])
            .start_timer();
        ProviderCallTimer(Some(RunningTimer {
            timer,
            chain: self.chain,
            label: label.clone(),
        }))
    }
}

/// Times one provider call. Dropped unobserved, the prometheus timer records the call as
/// abandoned; [`ObserveProviderCall::observe`] disarms it and records the outcome instead.
struct ProviderCallTimer(Option<RunningTimer>);

struct RunningTimer {
    timer: HistogramTimer,
    chain: ForeignChain,
    label: String,
}

impl ObserveProviderCall for ProviderCallTimer {
    fn observe(self, failure: Option<ProviderFailure>) {
        let Some(running) = self.0 else {
            return;
        };
        let elapsed = running.timer.stop_and_discard();
        metrics::MPC_FOREIGN_CHAIN_PROVIDER_INSPECTION_SECONDS
            .with_label_values(&[
                running.chain.label(),
                &running.label,
                Outcome::of(failure).label(),
            ])
            .observe(elapsed);
        if let Some(failure) = failure {
            metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERRORS_TOTAL
                .with_label_values(&[
                    running.chain.label(),
                    &running.label,
                    Kind::from(failure).label(),
                ])
                .inc();
        }
    }
}

/// The `outcome` label of [`metrics::MPC_FOREIGN_CHAIN_PROVIDER_INSPECTION_SECONDS`].
#[derive(Clone, Copy)]
enum Outcome {
    Answered,
    Failed,
}

impl Outcome {
    const ALL: [Self; 2] = [Self::Answered, Self::Failed];

    fn of(failure: Option<ProviderFailure>) -> Self {
        if failure.is_some() {
            Self::Failed
        } else {
            Self::Answered
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Answered => "answered",
            Self::Failed => "failed",
        }
    }
}

/// The `kind` label of [`metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERRORS_TOTAL`]. `Timeout` is the
/// RPC client giving up on an answer; a call the fan-out abandoned is timed in
/// [`metrics::MPC_FOREIGN_CHAIN_PROVIDER_DROPPED_SECONDS`] instead.
#[derive(Clone, Copy)]
enum Kind {
    Transient,
    NonTransient,
    Timeout,
}

impl Kind {
    const ALL: [Self; 3] = [Self::Transient, Self::NonTransient, Self::Timeout];

    fn label(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::NonTransient => "non_transient",
            Self::Timeout => "timeout",
        }
    }
}

impl From<ProviderFailure> for Kind {
    fn from(failure: ProviderFailure) -> Self {
        match failure {
            ProviderFailure::Unreachable => Self::Transient,
            ProviderFailure::Rejected | ProviderFailure::Malformed => Self::NonTransient,
            ProviderFailure::TimedOut => Self::Timeout,
        }
    }
}

/// The registry is process global, so each test records under its own chain label.
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use prometheus::Encoder;

    const PROVIDER: &str = "a-provider";

    fn timed(chain: ForeignChain, label: &str, outcome: Outcome) -> u64 {
        metrics::MPC_FOREIGN_CHAIN_PROVIDER_INSPECTION_SECONDS
            .with_label_values(&[chain.label(), label, outcome.label()])
            .get_sample_count()
    }

    fn dropped(chain: ForeignChain, label: &str) -> u64 {
        metrics::MPC_FOREIGN_CHAIN_PROVIDER_DROPPED_SECONDS
            .with_label_values(&[chain.label(), label])
            .get_sample_count()
    }

    fn errored(chain: ForeignChain, label: &str, kind: Kind) -> u64 {
        metrics::MPC_FOREIGN_CHAIN_PROVIDER_ERRORS_TOTAL
            .with_label_values(&[chain.label(), label, kind.label()])
            .get()
    }

    fn exposed_registry() -> String {
        let mut buffer = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&prometheus::default_registry().gather(), &mut buffer)
            .unwrap();
        String::from_utf8(buffer).unwrap()
    }

    #[test]
    fn provider_call_metrics__should_time_every_returned_call_and_count_failures() {
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
            recorder.start_timer(&provider).observe(failure);
        }

        // Then
        assert_eq!(timed(chain, "p0", Outcome::Answered), 1);
        assert_eq!(timed(chain, "p0", Outcome::Failed), 4);
        assert_eq!(dropped(chain, "p0"), 0);
        assert_eq!(errored(chain, "p0", Kind::Transient), 1);
        assert_eq!(errored(chain, "p0", Kind::NonTransient), 2);
        assert_eq!(errored(chain, "p0", Kind::Timeout), 1);
    }

    #[test]
    fn provider_call_metrics__should_time_a_dropped_call_when_its_handle_is_dropped() {
        // Given
        let chain = ForeignChain::Base;
        let provider = ProviderId(PROVIDER.to_string());
        let recorder = ProviderCallMetrics::new(chain, [&provider]);

        // When
        drop(recorder.start_timer(&provider));

        // Then
        assert_eq!(dropped(chain, "p0"), 1);
        assert_eq!(timed(chain, "p0", Outcome::Answered), 0);
        assert_eq!(timed(chain, "p0", Outcome::Failed), 0);
        for kind in Kind::ALL {
            assert_eq!(errored(chain, "p0", kind), 0);
        }
    }

    #[test]
    fn provider_call_metrics__should_assign_labels_by_sorted_provider_name() {
        // Given
        let chain = ForeignChain::Starknet;
        let providers: Vec<ProviderId> = ["zeta", "alpha", "mid"]
            .into_iter()
            .map(|name| ProviderId(name.to_string()))
            .collect();
        let recorder = ProviderCallMetrics::new(chain, &providers);

        // When: the alphabetically middle provider answers once and fails once.
        recorder.start_timer(&providers[2]).observe(None);
        recorder
            .start_timer(&providers[2])
            .observe(Some(ProviderFailure::Unreachable));

        // Then: its series is p1, not p2, so input order does not matter.
        assert_eq!(timed(chain, "p1", Outcome::Answered), 1);
        assert_eq!(timed(chain, "p1", Outcome::Failed), 1);
        assert_eq!(errored(chain, "p1", Kind::Transient), 1);
        for label in ["p0", "p2"] {
            assert_eq!(timed(chain, label, Outcome::Answered), 0);
            assert_eq!(timed(chain, label, Outcome::Failed), 0);
            assert_eq!(errored(chain, label, Kind::Transient), 0);
        }
    }

    #[test]
    fn provider_call_metrics_new__should_publish_every_series_before_the_first_call() {
        // When
        let _recorder =
            ProviderCallMetrics::new(ForeignChain::Ethereum, [&ProviderId(PROVIDER.to_string())]);

        // Then
        let exposed = exposed_registry();
        let count = |metric: &str| {
            exposed
                .lines()
                .filter(|line| {
                    line.starts_with(metric)
                        && line.contains(r#"chain="ethereum""#)
                        && line.contains(r#"provider="p0""#)
                })
                .count()
        };
        assert_eq!(
            count("mpc_foreign_chain_provider_inspection_seconds_count"),
            2
        );
        assert_eq!(count("mpc_foreign_chain_provider_dropped_seconds_count"), 1);
        assert_eq!(count("mpc_foreign_chain_provider_errors_total"), 3);
    }
}
