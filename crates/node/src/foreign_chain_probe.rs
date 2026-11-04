//! Periodic probe of every configured foreign-chain RPC provider, via
//! [`foreign_chain_health_check::probe`], with the local config compared and each chain judged
//! against the on chain provider whitelist.

use std::future::{Future, ready};
use std::pin::pin;

use foreign_chain_health_check::probe::{ProbeReport, probe_all_providers};
use foreign_chain_rpc_factory::inspectors::InspectorFactory;
use futures::{FutureExt as _, Stream, StreamExt as _, stream};
use mpc_node_config::ForeignChainsConfig;
use tokio::sync::{oneshot, watch};
use tokio_stream::wrappers::WatchStream;
use tracing::{info, warn};

use crate::indexer::foreign_chain::ForeignChainWhitelist;
use crate::tick::Tick;

mod chain_health;
mod report;
#[cfg(test)]
mod test_utils;
mod whitelist_diagnostics;

/// Asks every configured RPC provider which network it serves, once per tick of `ticker` and
/// whenever the whitelist changes, and reports the verdicts as logs and metrics. Diagnostic only:
/// nothing gates on the result.
///
/// The probe starts before the indexer has read the whitelist, so `indexer_whitelist` delivers the
/// indexer's whitelist receiver later. Until then, each round logs that it is not read yet. Once it
/// is read, each round logs every difference between the local config and the whitelist, see
/// [`whitelist_diagnostics`], and judges each probed chain, see
/// [`ChainHealth`](chain_health::ChainHealth).
pub async fn run_periodic_probe(
    foreign_chains: ForeignChainsConfig,
    indexer_whitelist: oneshot::Receiver<watch::Receiver<ForeignChainWhitelist>>,
    ticker: impl Tick,
) {
    if foreign_chains.is_empty() {
        warn!("no foreign chain is configured: this node cannot verify foreign-chain transactions");
        return;
    }

    probe_periodically(
        || probe_all_providers(&foreign_chains, &InspectorFactory),
        |report, whitelist| finish_round(report, &foreign_chains, whitelist),
        whitelist_updates(indexer_whitelist),
        ticker,
    )
    .await;
}

const WHITELIST_NOT_READ: &str = "foreign chain whitelist: not read from the contract yet";

fn finish_round(
    report: &ProbeReport,
    local: &ForeignChainsConfig,
    whitelist: Option<&ForeignChainWhitelist>,
) {
    report::publish_metrics(report);
    report::log_report(report);
    match whitelist {
        Some(whitelist) => {
            whitelist_diagnostics::log_differences(local, whitelist);
            chain_health::log(&chain_health::judge(report, local, whitelist));
        }
        None => info!("{WHITELIST_NOT_READ}"),
    }
}

/// Yields nothing until the indexer hands its receiver over, then its current whitelist and each
/// change. Ends when either side is dropped.
fn whitelist_updates(
    indexer_whitelist: oneshot::Receiver<watch::Receiver<ForeignChainWhitelist>>,
) -> impl Stream<Item = ForeignChainWhitelist> {
    stream::once(indexer_whitelist.map(Result::ok))
        .filter_map(ready)
        .flat_map(WatchStream::new)
}

/// Each round ends with `finish_round`, given the latest whitelist as of the end of the probe, so
/// a change that lands during the probe is used in that round.
async fn probe_periodically<Probe: Future<Output = ProbeReport>>(
    probe: impl Fn() -> Probe,
    finish_round: impl Fn(&ProbeReport, Option<&ForeignChainWhitelist>),
    whitelists: impl Stream<Item = ForeignChainWhitelist>,
    mut ticker: impl Tick,
) {
    let mut whitelists = pin!(whitelists.fuse());
    let mut whitelist = None;
    loop {
        // `biased`: a whitelist change that lands with a tick is handled in that round, not in an
        // extra one. `Some` disables the branch once the stream ends, so the loop never spins.
        tokio::select! {
            biased;
            () = ticker.tick() => {}
            Some(latest) = whitelists.next() => whitelist = Some(latest),
        }

        info!("probing foreign-chain RPC providers");
        let report = probe().await;
        // The whitelists come from a watch, so asking once is enough.
        if let Some(Some(latest)) = whitelists.next().now_or_never() {
            whitelist = Some(latest);
        }
        finish_round(&report, whitelist.as_ref());
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    use foreign_chain_health_check::probe::{ProviderCounts, ProviderStatus};
    use futures::channel::mpsc;
    use near_mpc_contract_interface::types as dtos;
    use rstest::rstest;
    use tracing_test::traced_test;

    use super::*;
    use crate::async_testing::{MaybeReady, run_future_once};
    use crate::foreign_chain_probe::chain_health::CHAIN_HEALTHY;
    use crate::foreign_chain_probe::test_utils::{
        ALCHEMY_URL, ProbedConfig, ProbedProvider, empty_report, gauges, mock_finish_round,
        mock_probe, no_whitelist, polygon_with_report, row, whitelist_of,
    };
    use crate::foreign_chain_probe::whitelist_diagnostics::CONFIG_MATCHES_WHITELIST;
    use crate::tick::MockTicker;

    #[test]
    fn probe_periodically__should_probe_once_per_tick() {
        // Given
        let probe_count = Cell::new(0);

        // When
        run_future_once(probe_periodically(
            mock_probe(&probe_count, 3, empty_report()),
            |_, _| {},
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

        // When
        let MaybeReady::Future(parked_probe_loop) = run_future_once(probe_periodically(
            probe_dispatch,
            |report, whitelist| finish_round(report, &ForeignChainsConfig::default(), whitelist),
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
            oneshot::channel().1,
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
    fn whitelist_updates__should_yield_the_whitelist_and_each_change_once_handed_over() {
        // Given
        let first = whitelist_of(dtos::ForeignChain::Polygon, &["alchemy"], 1);
        let second = whitelist_of(dtos::ForeignChain::Polygon, &["alchemy", "quicknode"], 2);
        let (hand_over, indexer_whitelist) = oneshot::channel();
        let mut whitelists = pin!(whitelist_updates(indexer_whitelist));
        let (indexer_tx, indexer_rx) = watch::channel(first.clone());

        // When
        let before_hand_over = whitelists.next().now_or_never();
        hand_over
            .send(indexer_rx)
            .expect("the stream holds the other end");
        let after_hand_over = whitelists.next().now_or_never();
        indexer_tx.send_replace(second.clone());
        let after_change = whitelists.next().now_or_never();
        let without_change = whitelists.next().now_or_never();

        // Then
        assert_eq!(before_hand_over, None);
        assert_eq!(after_hand_over, Some(Some(first)));
        assert_eq!(after_change, Some(Some(second)));
        assert_eq!(without_change, None);
    }

    #[test]
    fn whitelist_updates__should_end_when_the_indexer_never_hands_over() {
        // Given
        let (hand_over, indexer_whitelist) = oneshot::channel();

        // When
        drop(hand_over);
        let yielded = whitelist_updates(indexer_whitelist)
            .collect::<Vec<_>>()
            .now_or_never();

        // Then
        assert_eq!(yielded, Some(vec![]));
    }

    #[test]
    fn whitelist_updates__should_end_once_the_indexer_drops_its_sender() {
        // Given
        let whitelist = whitelist_of(dtos::ForeignChain::Polygon, &["alchemy"], 1);
        let (hand_over, indexer_whitelist) = oneshot::channel();
        let (indexer_tx, indexer_rx) = watch::channel(whitelist.clone());
        hand_over
            .send(indexer_rx)
            .expect("the stream holds the other end");

        // When
        drop(indexer_tx);
        let yielded = whitelist_updates(indexer_whitelist)
            .collect::<Vec<_>>()
            .now_or_never();

        // Then
        assert_eq!(yielded, Some(vec![whitelist]));
    }

    #[test]
    fn probe_periodically__should_finish_rounds_without_a_whitelist_until_it_is_read_then_probe_again()
     {
        // Given
        let probe_count = Cell::new(0);
        let whitelists_seen = RefCell::new(Vec::new());
        let whitelist = whitelist_of(dtos::ForeignChain::Polygon, &["alchemy"], 1);
        let (whitelist_tx, whitelists) = mpsc::unbounded();
        let MaybeReady::Future(parked_probe_loop) = run_future_once(probe_periodically(
            mock_probe(&probe_count, 2, empty_report()),
            mock_finish_round(&whitelists_seen),
            whitelists,
            MockTicker::new(1),
        )) else {
            panic!("the loop should park once its ticker runs out");
        };

        // When
        whitelist_tx
            .unbounded_send(whitelist.clone())
            .expect("the loop holds the receiver");
        run_future_once(parked_probe_loop);

        // Then
        assert_eq!(*whitelists_seen.borrow(), vec![None, Some(whitelist)]);
    }

    #[test]
    fn probe_periodically__should_probe_once_when_a_whitelist_change_lands_with_a_tick() {
        // Without `biased`, `select!` polls a random branch first, so a single run would catch
        // that only half the time.
        for _ in 0..64 {
            // Given
            let probe_count = Cell::new(0);
            let (whitelist_tx, whitelists) = mpsc::unbounded();
            whitelist_tx
                .unbounded_send(whitelist_of(dtos::ForeignChain::Polygon, &["alchemy"], 1))
                .expect("the loop holds the receiver");

            // When
            run_future_once(probe_periodically(
                mock_probe(&probe_count, 1, empty_report()),
                |_, _| {},
                whitelists,
                MockTicker::new(1),
            ));

            // Then
            assert_eq!(probe_count.get(), 1);
        }
    }

    #[test]
    fn probe_periodically__should_use_a_whitelist_that_arrives_during_the_probe() {
        // Given
        let whitelist = whitelist_of(dtos::ForeignChain::Polygon, &["alchemy"], 1);
        let (whitelist_tx, whitelists) = mpsc::unbounded();
        let probe_count = Cell::new(0);
        let counted_probe = mock_probe(&probe_count, 1, empty_report());
        let probe = || {
            whitelist_tx
                .unbounded_send(whitelist.clone())
                .expect("the loop holds the receiver");
            counted_probe()
        };
        let whitelists_seen = RefCell::new(Vec::new());

        // When
        run_future_once(probe_periodically(
            probe,
            mock_finish_round(&whitelists_seen),
            whitelists,
            MockTicker::new(1),
        ));

        // Then
        assert_eq!(*whitelists_seen.borrow(), vec![Some(whitelist)]);
    }

    #[traced_test]
    #[rstest]
    #[case::without_a_whitelist(None, WHITELIST_NOT_READ, CONFIG_MATCHES_WHITELIST)]
    #[case::with_a_whitelist(
        Some(whitelist_of(dtos::ForeignChain::Polygon, &["alchemy"], 1)),
        CONFIG_MATCHES_WHITELIST,
        WHITELIST_NOT_READ
    )]
    fn finish_round__should_compare_the_config_with_the_whitelist_or_log_that_it_is_not_read(
        #[case] whitelist: Option<ForeignChainWhitelist>,
        #[case] logged: &str,
        #[case] not_logged: &str,
    ) {
        // When
        finish_round(
            &empty_report(),
            &ForeignChainsConfig::default(),
            whitelist.as_ref(),
        );

        // Then
        assert!(logs_contain(logged));
        assert!(!logs_contain(not_logged));
    }

    #[test]
    #[traced_test]
    fn finish_round__should_judge_each_chain_once_the_whitelist_is_read() {
        // Given
        let ProbedConfig { local, report } = polygon_with_report(&[ProbedProvider {
            name: "alchemy",
            rpc_url: ALCHEMY_URL,
            status: ProviderStatus::Healthy,
        }]);
        let whitelist = whitelist_of(dtos::ForeignChain::Polygon, &["alchemy"], 1);

        // When
        finish_round(&report, &local, Some(&whitelist));

        // Then
        assert!(logs_contain(CHAIN_HEALTHY));
    }

    #[test]
    fn probe_periodically__should_keep_probing_on_ticks_once_the_whitelist_stream_ends() {
        // Given
        let probe_count = Cell::new(0);
        let (whitelist_tx, whitelists) = mpsc::unbounded();
        drop(whitelist_tx);
        let ticker = MockTicker::new(1);
        let MaybeReady::Future(parked_probe_loop) = run_future_once(probe_periodically(
            mock_probe(&probe_count, 2, empty_report()),
            |_, _| {},
            whitelists,
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
