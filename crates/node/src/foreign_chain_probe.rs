//! Periodic probe of every configured foreign-chain RPC provider, via
//! [`foreign_chain_health_check::probe`].

use std::future::Future;

use foreign_chain_health_check::probe::{ProbeReport, probe_all_providers};
use foreign_chain_rpc_factory::inspectors::InspectorFactory;
use mpc_node_config::ForeignChainsConfig;
use tracing::{info, warn};

use crate::tick::Tick;

mod report;
#[cfg(test)]
mod test_utils;

/// Asks every configured RPC provider which network it serves, once per tick of `ticker`, and
/// reports the verdicts as logs and metrics. Diagnostic only: nothing gates on the result.
pub async fn run_periodic_probe(foreign_chains: ForeignChainsConfig, ticker: impl Tick) {
    if foreign_chains.is_empty() {
        warn!("no foreign chain is configured: this node cannot verify foreign-chain transactions");
        return;
    }

    probe_periodically(
        || probe_all_providers(&foreign_chains, &InspectorFactory),
        ticker,
    )
    .await;
}

async fn probe_periodically<Probe: Future<Output = ProbeReport>>(
    probe: impl Fn() -> Probe,
    mut ticker: impl Tick,
) {
    loop {
        ticker.tick().await;

        info!("probing foreign-chain RPC providers");
        let report = probe().await;
        report::publish_metrics(&report);
        report::log_report(&report);
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    use foreign_chain_health_check::probe::{ProviderCounts, ProviderStatus};
    use near_mpc_contract_interface::types as dtos;

    use super::*;
    use crate::async_testing::{MaybeReady, run_future_once};
    use crate::foreign_chain_probe::test_utils::{gauges, row};
    use crate::tick::MockTicker;

    #[test]
    fn probe_periodically__should_probe_once_per_tick() {
        // Given
        let probe_count = Cell::new(0);
        let probe = || {
            probe_count.update(|count| count + 1);
            std::future::ready(ProbeReport::from(vec![]))
        };

        // When
        run_future_once(probe_periodically(probe, MockTicker::new(3)));

        // Then
        assert_eq!(probe_count.get(), 3);
    }

    #[test]
    fn probe_periodically__should_replace_the_gauges_of_the_previous_round() {
        // Given
        let rounds = RefCell::new(VecDeque::from([
            ProbeReport::from(vec![row(
                dtos::ForeignChain::Starknet,
                "only",
                ProviderStatus::Healthy,
            )]),
            ProbeReport::from(vec![row(
                dtos::ForeignChain::Starknet,
                "only",
                ProviderStatus::Unreachable,
            )]),
        ]));
        let probe_dispatch =
            || std::future::ready(rounds.borrow_mut().pop_front().expect("a report per tick"));
        let ticker = MockTicker::new(1);

        // When
        let MaybeReady::Future(parked_probe_loop) =
            run_future_once(probe_periodically(probe_dispatch, ticker.clone()))
        else {
            panic!("the loop should park once its ticker runs out");
        };
        let metrics_after_the_first_round = gauges("starknet");
        ticker.schedule(1);
        run_future_once(parked_probe_loop);

        // Then
        assert_eq!(
            metrics_after_the_first_round,
            ProviderCounts {
                configured: 1,
                healthy: 1
            }
        );
        assert_eq!(
            gauges("starknet"),
            ProviderCounts {
                configured: 1,
                healthy: 0
            }
        );
    }

    #[test]
    fn run_periodic_probe__should_stop_when_no_foreign_chain_is_configured() {
        // Given
        let foreign_chains = ForeignChainsConfig::default();
        let ticker = MockTicker::new(1);

        // When
        let outcome = run_future_once(run_periodic_probe(foreign_chains, ticker.clone()));

        // Then
        assert_eq!(ticker.unspent(), 1, "no round should have run");
        assert!(
            matches!(outcome, MaybeReady::Ready(())),
            "the probe should return rather than park on its ticker"
        );
    }
}
