//! Periodic probe of every configured foreign-chain RPC provider, via
//! [`foreign_chain_health_check::probe`], with the local config compared and each chain judged
//! against the on chain provider whitelist.

use std::future::Future;

use foreign_chain_health_check::probe::{ProbeReport, probe_all_providers};
use foreign_chain_rpc_factory::inspectors::InspectorFactory;
use mpc_node_config::ForeignChainsConfig;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::indexer::foreign_chain::ForeignChainWhitelist;
use crate::tick::Tick;

mod chain_health;
mod report;
#[cfg(test)]
mod test_utils;
mod whitelist_diagnostics;

/// Asks every configured RPC provider which network it serves, once per tick of `ticker` and
/// whenever `whitelist_rx` changes, and reports the verdicts as logs and metrics. Diagnostic only:
/// nothing gates on the result.
///
/// Once the whitelist is read, each round also logs every difference between the local config and
/// the whitelist, see [`whitelist_diagnostics`], and judges each probed chain, see
/// [`ChainHealth`](chain_health::ChainHealth). Until then, each round logs that the whitelist is
/// not read yet.
pub async fn run_periodic_probe(
    foreign_chains: ForeignChainsConfig,
    whitelist_rx: watch::Receiver<Option<ForeignChainWhitelist>>,
    ticker: impl Tick,
) {
    if foreign_chains.is_empty() {
        warn!("no foreign chain is configured: this node cannot verify foreign-chain transactions");
        return;
    }

    probe_periodically(
        || probe_all_providers(&foreign_chains, &InspectorFactory),
        &foreign_chains,
        whitelist_rx,
        ticker,
    )
    .await;
}

/// [`run_periodic_probe`] starts before the indexer has read the whitelist, so it takes an `Option`
/// that this fills once the indexer hands the whitelist over.
pub(crate) async fn forward_foreign_chain_whitelist(
    mut from_indexer: watch::Receiver<ForeignChainWhitelist>,
    to_probe: watch::Sender<Option<ForeignChainWhitelist>>,
) {
    loop {
        let whitelist = from_indexer.borrow_and_update().clone();
        if to_probe.send(Some(whitelist)).is_err() {
            return;
        }
        if from_indexer.changed().await.is_err() {
            return;
        }
    }
}

async fn probe_periodically<Probe: Future<Output = ProbeReport>>(
    probe: impl Fn() -> Probe,
    local: &ForeignChainsConfig,
    mut whitelist_rx: watch::Receiver<Option<ForeignChainWhitelist>>,
    mut ticker: impl Tick,
) {
    loop {
        // `biased`: a whitelist change that lands with a tick is handled in that round, not in an
        // extra one. `Ok(())` drops the branch once the sender is gone, so the loop never spins.
        tokio::select! {
            biased;
            () = ticker.tick() => {}
            Ok(()) = whitelist_rx.changed() => {}
        }

        info!("probing foreign-chain RPC providers");
        let report = probe().await;
        report::publish_metrics(&report);
        report::log_report(&report);
        let whitelist = whitelist_rx.borrow_and_update().clone();
        match whitelist {
            Some(whitelist) => {
                whitelist_diagnostics::log_differences(local, &whitelist);
                chain_health::log(&chain_health::judge(&report, local, &whitelist));
            }
            None => info!("foreign chain whitelist: not read from the contract yet"),
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    use foreign_chain_health_check::probe::{ProviderCounts, ProviderStatus};
    use futures::FutureExt as _;
    use near_mpc_contract_interface::types as dtos;
    use tracing_test::traced_test;

    use super::*;
    use crate::async_testing::{MaybeReady, run_future_once};
    use crate::foreign_chain_probe::test_utils::{
        ALCHEMY_URL, capped_probe, empty_report, gauges, logged_times, no_whitelist,
        polygon_with_report, row, whitelist_of,
    };
    use crate::tick::MockTicker;

    const NOT_READ: &str = "foreign chain whitelist: not read from the contract yet";

    #[test]
    fn probe_periodically__should_probe_once_per_tick() {
        // Given
        let probe_count = Cell::new(0);

        // When
        run_future_once(probe_periodically(
            capped_probe(&probe_count, 3, empty_report()),
            &ForeignChainsConfig::default(),
            no_whitelist(),
            MockTicker::new(3),
        ));

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
        let local = ForeignChainsConfig::default();

        // When
        let MaybeReady::Future(parked_probe_loop) = run_future_once(probe_periodically(
            probe_dispatch,
            &local,
            no_whitelist(),
            ticker.clone(),
        )) else {
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
        let outcome = run_future_once(run_periodic_probe(
            foreign_chains,
            no_whitelist(),
            ticker.clone(),
        ));

        // Then
        assert_eq!(ticker.unspent(), 1, "no round should have run");
        assert!(
            matches!(outcome, MaybeReady::Ready(())),
            "the probe should return rather than park on its ticker"
        );
    }

    #[test]
    fn forward_foreign_chain_whitelist__should_forward_the_first_whitelist_and_each_change() {
        // Given
        let first = whitelist_of(dtos::ForeignChain::Polygon, &["alchemy"], 1);
        let second = whitelist_of(dtos::ForeignChain::Polygon, &["alchemy", "quicknode"], 2);
        let (indexer_tx, indexer_rx) = watch::channel(first.clone());
        let (probe_tx, probe_rx) = watch::channel(None);
        let MaybeReady::Future(mut forwarder) =
            run_future_once(forward_foreign_chain_whitelist(indexer_rx, probe_tx))
        else {
            panic!("the forwarder should wait for the next change");
        };
        let forwarded_first = probe_rx.borrow().clone();

        // When
        indexer_tx.send_replace(second.clone());
        let outcome = forwarder.as_mut().now_or_never();

        // Then
        assert_eq!(forwarded_first, Some(first));
        assert_eq!(*probe_rx.borrow(), Some(second));
        assert!(outcome.is_none(), "the forwarder should keep waiting");
    }

    #[test]
    fn forward_foreign_chain_whitelist__should_return_once_the_indexer_drops_its_sender() {
        // Given
        let (indexer_tx, indexer_rx) =
            watch::channel(whitelist_of(dtos::ForeignChain::Polygon, &["alchemy"], 1));
        let (probe_tx, _probe_rx) = watch::channel(None);
        let MaybeReady::Future(mut forwarder) =
            run_future_once(forward_foreign_chain_whitelist(indexer_rx, probe_tx))
        else {
            panic!("the forwarder should wait for the next change");
        };

        // When
        drop(indexer_tx);
        let outcome = forwarder.as_mut().now_or_never();

        // Then
        assert!(outcome.is_some());
    }

    #[test]
    fn forward_foreign_chain_whitelist__should_return_once_the_probe_drops_its_receiver() {
        // Given
        let (_indexer_tx, indexer_rx) =
            watch::channel(whitelist_of(dtos::ForeignChain::Polygon, &["alchemy"], 1));
        let (probe_tx, probe_rx) = watch::channel(None);
        drop(probe_rx);

        // When
        let outcome = run_future_once(forward_foreign_chain_whitelist(indexer_rx, probe_tx));

        // Then
        // assert_matches! requires Debug, which MaybeReady doesn't implement
        assert!(matches!(outcome, MaybeReady::Ready(())));
    }

    #[test]
    #[traced_test]
    fn probe_periodically__should_log_that_the_whitelist_is_not_read_until_it_is_then_probe_again()
    {
        // Given
        let probe_count = Cell::new(0);
        let (whitelist_tx, whitelist_rx) = watch::channel(None);
        let local = ForeignChainsConfig::default();
        let MaybeReady::Future(parked_probe_loop) = run_future_once(probe_periodically(
            capped_probe(&probe_count, 2, empty_report()),
            &local,
            whitelist_rx,
            MockTicker::new(1),
        )) else {
            panic!("the loop should park once its ticker runs out");
        };

        // When
        whitelist_tx.send_replace(Some(whitelist_of(
            dtos::ForeignChain::Polygon,
            &["alchemy"],
            1,
        )));
        run_future_once(parked_probe_loop);

        // Then
        assert_eq!(probe_count.get(), 2);
        logs_assert(|lines: &[&str]| {
            [NOT_READ, "local config matches the contract whitelist"]
                .iter()
                .try_for_each(|message| logged_times(lines, "INFO", message, 1))
        });
    }

    #[test]
    fn probe_periodically__should_probe_once_when_a_whitelist_change_lands_with_a_tick() {
        // Without `biased`, `select!` polls a random branch first, so a single run would catch
        // that only half the time.
        for _ in 0..64 {
            // Given
            let probe_count = Cell::new(0);
            let (whitelist_tx, whitelist_rx) = watch::channel(None);
            whitelist_tx.send_replace(Some(whitelist_of(
                dtos::ForeignChain::Polygon,
                &["alchemy"],
                1,
            )));

            // When
            run_future_once(probe_periodically(
                capped_probe(&probe_count, 1, empty_report()),
                &ForeignChainsConfig::default(),
                whitelist_rx,
                MockTicker::new(1),
            ));

            // Then
            assert_eq!(probe_count.get(), 1);
        }
    }

    #[test]
    #[traced_test]
    fn probe_periodically__should_compare_with_a_whitelist_that_changes_during_the_probe() {
        // Given
        let (local, report) =
            polygon_with_report(&[("alchemy", ALCHEMY_URL, ProviderStatus::Healthy)]);
        let without_alchemy = whitelist_of(dtos::ForeignChain::Polygon, &["quicknode"], 1);
        let with_alchemy = whitelist_of(dtos::ForeignChain::Polygon, &["alchemy"], 1);
        let (whitelist_tx, whitelist_rx) = watch::channel(Some(without_alchemy));
        let probe_count = Cell::new(0);
        let counted_probe = capped_probe(&probe_count, 1, report);
        let probe = || {
            whitelist_tx.send_replace(Some(with_alchemy.clone()));
            counted_probe()
        };

        // When
        run_future_once(probe_periodically(
            probe,
            &local,
            whitelist_rx,
            MockTicker::new(1),
        ));

        // Then
        assert_eq!(probe_count.get(), 1);
        assert!(logs_contain("local config matches the contract whitelist"));
        assert!(!logs_contain("extra provider"));
    }

    #[test]
    #[traced_test]
    fn probe_periodically__should_log_whitelist_diagnostics_and_chain_health_every_round() {
        // Given
        let (local, report) =
            polygon_with_report(&[("alchemy", ALCHEMY_URL, ProviderStatus::Healthy)]);
        let probe = || std::future::ready(report.clone());
        let (_whitelist_tx, whitelist_rx) = watch::channel(Some(whitelist_of(
            dtos::ForeignChain::Polygon,
            &["alchemy", "quicknode"],
            2,
        )));

        // When
        run_future_once(probe_periodically(
            probe,
            &local,
            whitelist_rx,
            MockTicker::new(2),
        ));

        // Then
        logs_assert(|lines: &[&str]| {
            [
                ("INFO", "local config matches the contract whitelist"),
                ("WARN", "foreign chain is below quorum"),
            ]
            .iter()
            .try_for_each(|(level, message)| logged_times(lines, level, message, 2))
        });
    }

    #[test]
    fn probe_periodically__should_keep_probing_on_ticks_once_the_whitelist_sender_is_gone() {
        // Given
        let probe_count = Cell::new(0);
        let local = ForeignChainsConfig::default();
        let (whitelist_tx, whitelist_rx) = watch::channel(None);
        drop(whitelist_tx);
        let ticker = MockTicker::new(1);
        let MaybeReady::Future(parked_probe_loop) = run_future_once(probe_periodically(
            capped_probe(&probe_count, 2, empty_report()),
            &local,
            whitelist_rx,
            ticker.clone(),
        )) else {
            panic!("the loop should park once its ticker runs out");
        };

        // When
        ticker.schedule(1);
        run_future_once(parked_probe_loop);

        // Then
        assert_eq!(probe_count.get(), 2);
    }
}
