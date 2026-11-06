//! Periodic probe of every configured foreign-chain RPC provider, via
//! [`foreign_chain_health_check::probe`], with the local config compared and each chain judged
//! against the on chain provider whitelist.

use std::future::Future;

use foreign_chain_health_check::probe::{ProbeReport, probe_all_providers};
use foreign_chain_rpc_factory::inspectors::InspectorFactory;
use mpc_node_config::ForeignChainsConfig;
use tokio::sync::watch;

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
/// Each round logs a line per unhealthy provider and per difference between the local config and
/// the whitelist, see [`whitelist_diagnostics`], and per chain that is not healthy, see
/// [`ChainHealth`](chain_health::ChainHealth), then one summary line. The probe starts before the
/// indexer has read the whitelist from the contract, so `whitelist_rx` holds `None` until then, and
/// the summary says the whitelist is not read yet.
pub async fn run_periodic_probe(
    foreign_chains: ForeignChainsConfig,
    whitelist_rx: watch::Receiver<Option<ForeignChainWhitelist>>,
    ticker: impl Tick,
) {
    if foreign_chains.is_empty() {
        tracing::warn!(
            "no foreign chain is configured: this node cannot verify foreign-chain transactions"
        );
        return;
    }

    probe_periodically(
        || probe_all_providers(&foreign_chains, &InspectorFactory),
        |report, whitelist| finish_round(report, &foreign_chains, whitelist),
        whitelist_rx,
        ticker,
    )
    .await;
}

const ROUND_COMPLETE: &str = "foreign chain probe round complete";
const WHITELIST_NOT_READ: &str = "not read yet";
const WHITELIST_MATCHES: &str = "matches the local config";

fn finish_round(
    report: &ProbeReport,
    local: &ForeignChainsConfig,
    whitelist: Option<&ForeignChainWhitelist>,
) {
    report::publish_metrics(report);
    let rows = report.rows();
    rows.iter()
        .filter(|row| report::provider_is_unhealthy(row))
        .for_each(report::log_unhealthy_provider);
    let report::Summary {
        probed,
        healthy,
        unchecked,
        unchecked_chains,
    } = report::summarize(rows);
    if probed == 0 {
        report::log_nothing_checked(rows);
    }

    let whitelist_differences =
        whitelist.map(|whitelist| whitelist_diagnostics::compare(local, whitelist));
    whitelist_differences
        .iter()
        .flatten()
        .for_each(whitelist_diagnostics::log);
    let health_per_chain = whitelist
        .map(|whitelist| chain_health::judge(report, local, whitelist))
        .unwrap_or_default();
    health_per_chain
        .iter()
        .for_each(|(chain, health)| chain_health::log_if_unhealthy(*chain, health));
    let healthy_chains = health_per_chain
        .values()
        .filter(|health| matches!(health, chain_health::ChainHealth::Healthy))
        .count();
    let judged_chains = health_per_chain.len();

    let whitelist_state = match whitelist_differences.map(|differences| differences.len()) {
        None => WHITELIST_NOT_READ.to_string(),
        Some(0) => WHITELIST_MATCHES.to_string(),
        Some(1) => "1 difference from the local config".to_string(),
        Some(count) => format!("{count} differences from the local config"),
    };
    tracing::info!(
        healthy,
        probed,
        unchecked,
        ?unchecked_chains,
        whitelist = whitelist_state,
        healthy_chains,
        judged_chains,
        "{ROUND_COMPLETE}"
    );
}

/// Each round ends with `finish_round`, given the whitelist as read after the probe, so a change
/// that lands during the probe is used in that round.
async fn probe_periodically<Probe: Future<Output = ProbeReport>>(
    probe: impl Fn() -> Probe,
    finish_round: impl Fn(&ProbeReport, Option<&ForeignChainWhitelist>),
    mut whitelist_rx: watch::Receiver<Option<ForeignChainWhitelist>>,
    mut ticker: impl Tick,
) {
    loop {
        // `biased`: a whitelist change that lands with a tick is handled in that round, not in an
        // extra one. `Ok(())` disables the branch once the sender is gone, so the loop never spins.
        tokio::select! {
            biased;
            () = ticker.tick() => {}
            Ok(()) = whitelist_rx.changed() => {}
        }

        tracing::info!("probing foreign-chain RPC providers");
        let report = probe().await;
        let whitelist = whitelist_rx.borrow_and_update().clone();
        finish_round(&report, whitelist.as_ref());
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::{BTreeMap, VecDeque};

    use foreign_chain_health_check::probe::{ProviderCounts, ProviderStatus};
    use mpc_node_config::{AuthConfig, ForeignChainProviderConfig};
    use near_mpc_contract_interface::types as dtos;
    use rstest::rstest;
    use tracing_test::traced_test;

    use super::*;
    use crate::async_testing::{MaybeReady, run_future_once};
    use crate::foreign_chain_probe::test_utils::{
        ALCHEMY_URL, ProbedConfig, ProbedProvider, chain_config, empty_report, foreign_chains,
        gauges, mock_finish_round, mock_probe, no_whitelist, polygon_with_report, row,
        whitelist_of,
    };
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
    fn probe_periodically__should_finish_rounds_without_a_whitelist_until_it_is_read_then_probe_again()
     {
        // Given
        let probe_count = Cell::new(0);
        let whitelists_seen = RefCell::new(Vec::new());
        let whitelist = whitelist_of(dtos::ForeignChain::Polygon, &["alchemy"], 1);
        let (whitelist_tx, whitelist_rx) = watch::channel(None);
        let MaybeReady::Future(parked_probe_loop) = run_future_once(probe_periodically(
            mock_probe(&probe_count, 2, empty_report()),
            mock_finish_round(&whitelists_seen),
            whitelist_rx,
            MockTicker::new(1),
        )) else {
            panic!("the loop should park once its ticker runs out");
        };

        // When
        whitelist_tx.send_replace(Some(whitelist.clone()));
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
            let (whitelist_tx, whitelist_rx) = watch::channel(None);
            whitelist_tx.send_replace(Some(whitelist_of(
                dtos::ForeignChain::Polygon,
                &["alchemy"],
                1,
            )));

            // When
            run_future_once(probe_periodically(
                mock_probe(&probe_count, 1, empty_report()),
                |_, _| {},
                whitelist_rx,
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
        let (whitelist_tx, whitelist_rx) = watch::channel(None);
        let probe_count = Cell::new(0);
        let counted_probe = mock_probe(&probe_count, 1, empty_report());
        let probe = || {
            whitelist_tx.send_replace(Some(whitelist.clone()));
            counted_probe()
        };
        let whitelists_seen = RefCell::new(Vec::new());

        // When
        run_future_once(probe_periodically(
            probe,
            mock_finish_round(&whitelists_seen),
            whitelist_rx,
            MockTicker::new(1),
        ));

        // Then
        assert_eq!(*whitelists_seen.borrow(), vec![Some(whitelist)]);
    }

    fn polygon_config() -> ForeignChainsConfig {
        let alchemy = ForeignChainProviderConfig {
            rpc_url: "https://polygon-mainnet.g.alchemy.com/v2".to_string(),
            auth: AuthConfig::None,
        };
        foreign_chains([(
            dtos::ForeignChain::Polygon,
            chain_config(&[("alchemy", alchemy)]),
        )])
    }

    #[traced_test]
    #[rstest]
    #[case::without_a_whitelist(ForeignChainsConfig::default(), None, WHITELIST_NOT_READ)]
    #[case::with_a_matching_whitelist(
        ForeignChainsConfig::default(),
        Some(BTreeMap::new()),
        WHITELIST_MATCHES
    )]
    #[case::with_a_differing_whitelist(
        polygon_config(),
        Some(BTreeMap::new()),
        "1 difference from the local config"
    )]
    fn finish_round__should_end_with_one_line_that_says_how_the_config_compares_with_the_whitelist(
        #[case] local: ForeignChainsConfig,
        #[case] whitelist: Option<ForeignChainWhitelist>,
        #[case] whitelist_state: &str,
    ) {
        // When
        finish_round(&empty_report(), &local, whitelist.as_ref());

        // Then
        logs_assert(|lines: &[&str]| {
            let round_lines: Vec<_> = lines
                .iter()
                .filter(|line| line.contains(ROUND_COMPLETE))
                .collect();
            match round_lines.as_slice() {
                [line] if line.contains(whitelist_state) => Ok(()),
                _ => Err(format!(
                    "expected one round line with {whitelist_state:?}, got {round_lines:?}"
                )),
            }
        });
    }

    #[test]
    #[traced_test]
    fn finish_round__should_log_each_problem_then_one_summary_line() {
        // Given
        let report = ProbeReport::from(vec![
            row(
                dtos::ForeignChain::Polygon,
                "alchemy",
                ProviderStatus::Healthy,
            ),
            row(
                dtos::ForeignChain::Polygon,
                "quicknode",
                ProviderStatus::Unreachable,
            ),
            row(
                dtos::ForeignChain::Ton,
                "toncenter",
                ProviderStatus::ProbeNotImplemented,
            ),
        ]);
        let whitelist = ForeignChainWhitelist::new();

        // When
        finish_round(&report, &polygon_config(), Some(&whitelist));

        // Then
        logs_assert(|lines: &[&str]| {
            let matching = |text: &str| -> Vec<&&str> {
                lines.iter().filter(|line| line.contains(text)).collect()
            };
            let unhealthy = matching("provider is unhealthy");
            let not_whitelisted = matching("chain is not whitelisted yet");
            let round = matching(ROUND_COMPLETE);
            let checks = [
                (
                    "one unhealthy line, for quicknode",
                    matches!(unhealthy.as_slice(), [line] if line.contains("quicknode")),
                ),
                ("one whitelist difference line", not_whitelisted.len() == 1),
                (
                    "no line for the healthy or the unchecked provider",
                    matching("alchemy").is_empty() && matching("toncenter").is_empty(),
                ),
                (
                    "one summary line with the counts and the whitelist state",
                    matches!(round.as_slice(), [line] if line.contains(
                        r#"healthy=1 probed=2 unchecked=1 unchecked_chains={"ton"} whitelist="1 difference from the local config""#
                    )),
                ),
            ];
            match checks.iter().find(|(_, passed)| !passed) {
                Some((check, _)) => Err(format!("expected {check}, got {lines:#?}")),
                None => Ok(()),
            }
        });
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
        assert!(logs_contain("healthy_chains=1 judged_chains=1"));
    }

    #[test]
    fn probe_periodically__should_keep_probing_on_ticks_once_the_whitelist_sender_is_gone() {
        // Given
        let probe_count = Cell::new(0);
        let (whitelist_tx, whitelist_rx) = watch::channel(None);
        drop(whitelist_tx);
        let ticker = MockTicker::new(1);
        let MaybeReady::Future(parked_probe_loop) = run_future_once(probe_periodically(
            mock_probe(&probe_count, 2, empty_report()),
            |_, _| {},
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
