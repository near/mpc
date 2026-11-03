//! Judges each probed chain against the provider whitelist and its quorum.

use std::collections::{BTreeMap, BTreeSet};

use foreign_chain_health_check::probe::{ProbeReport, ProviderHealth, ProviderStatus};
use mpc_node_config::ForeignChainsConfig;
use mpc_node_config::foreign_chains::RpcProviderName;
use near_mpc_contract_interface::types as dtos;
use tracing::{info, warn};

use crate::foreign_chain_rpc_policy::{ChainQuorum, RpcQuorumStatus};
use crate::indexer::foreign_chain::ForeignChainWhitelist;

/// A probed chain judged against the provider whitelist.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ChainHealth {
    Healthy,
    /// The same verdict that keeps the chain from being registered.
    BelowQuorum(RpcQuorumStatus),
    /// Every configured provider joins the verify fan-out, whitelisted or not, and their verdicts
    /// must all agree. So one provider that serves another network fails every verify request.
    WrongNetwork {
        providers: usize,
    },
    /// `unhealthy` counts whitelist providers, see [`ChainQuorum`].
    UnhealthyProviders {
        unhealthy: usize,
        quorum: RpcQuorumStatus,
    },
}

/// Leaves out a chain missing from the whitelist and a chain no probe covers.
pub(super) fn judge(
    report: &ProbeReport,
    local: &ForeignChainsConfig,
    whitelist: &ForeignChainWhitelist,
) -> BTreeMap<dtos::ForeignChain, ChainHealth> {
    local
        .iter_chains()
        .filter_map(|(chain, local_chain)| {
            let whitelist_entry = whitelist.get(&chain)?;
            let probed_rows: Vec<&ProviderHealth> = report
                .rows()
                .iter()
                .filter(|row| row.chain == chain && row.status.was_probed())
                .collect();
            if probed_rows.is_empty() {
                return None;
            }
            let quorum = ChainQuorum::new(local_chain, whitelist_entry)?;
            Some((chain, judge_chain(&probed_rows, quorum)))
        })
        .collect()
}

/// A whitelist provider counts once, however many local providers match it. It is healthy only
/// when all of them are. Providers missing from the whitelist only count when they serve another
/// network.
fn judge_chain(
    probed_rows: &[&ProviderHealth],
    ChainQuorum {
        conforming,
        status: quorum,
    }: ChainQuorum,
) -> ChainHealth {
    if !quorum.reaches_quorum() {
        return ChainHealth::BelowQuorum(quorum);
    }

    let wrong_network = probed_rows
        .iter()
        .filter(|row| matches!(row.status, ProviderStatus::WrongNetwork { .. }))
        .count();
    if wrong_network > 0 {
        return ChainHealth::WrongNetwork {
            providers: wrong_network,
        };
    }

    // Probe rows name a provider by its local config name.
    let unhealthy: BTreeSet<&dtos::ProviderId> = probed_rows
        .iter()
        .filter(|row| !row.status.is_healthy())
        .filter_map(|row| {
            conforming.whitelist_provider_id(&RpcProviderName::from(row.provider.0.clone()))
        })
        .collect();
    if unhealthy.is_empty() {
        ChainHealth::Healthy
    } else {
        ChainHealth::UnhealthyProviders {
            unhealthy: unhealthy.len(),
            quorum,
        }
    }
}

pub(super) fn log(health_per_chain: &BTreeMap<dtos::ForeignChain, ChainHealth>) {
    for (chain, health) in health_per_chain {
        let chain = chain.label();
        match health {
            ChainHealth::Healthy => info!(%chain, "foreign chain is healthy"),
            ChainHealth::BelowQuorum(quorum) => warn!(
                %chain,
                whitelisted = quorum.configured_whitelisted_providers,
                quorum = quorum.required_whitelisted_providers.get(),
                "foreign chain is below quorum: configure more whitelisted RPC providers",
            ),
            ChainHealth::WrongNetwork { providers } => warn!(
                %chain,
                providers,
                "foreign chain is unhealthy: an RPC provider serves another network, so every verify request fails",
            ),
            ChainHealth::UnhealthyProviders { unhealthy, quorum } => warn!(
                %chain,
                unhealthy,
                whitelisted = quorum.configured_whitelisted_providers,
                quorum = quorum.required_whitelisted_providers.get(),
                "foreign chain is unhealthy: a whitelisted RPC provider did not pass the probe",
            ),
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::num::NonZeroUsize;

    use foreign_chain_inspector::NetworkFingerprint;
    use rstest::rstest;
    use tracing_test::traced_test;

    use super::*;
    use crate::foreign_chain_probe::test_utils::{
        ALCHEMY_URL, OWN_NODE_URL, ProbedConfig, ProbedProvider, QUICKNODE_URL, config_with_report,
        logged_times, polygon_with_report, whitelist_of,
    };

    fn quorum(required: usize, configured: usize) -> RpcQuorumStatus {
        RpcQuorumStatus {
            required_whitelisted_providers: NonZeroUsize::new(required).unwrap(),
            configured_whitelisted_providers: configured,
        }
    }

    fn wrong_network() -> ProviderStatus {
        ProviderStatus::WrongNetwork {
            expected: NetworkFingerprint::new("137"),
            observed: NetworkFingerprint::new("1"),
        }
    }

    #[rstest]
    #[case::healthy_when_quorum_whitelisted_providers_pass(
        &[
            ProbedProvider { name: "alchemy", rpc_url: ALCHEMY_URL, status: ProviderStatus::Healthy },
            ProbedProvider { name: "quicknode", rpc_url: QUICKNODE_URL, status: ProviderStatus::Healthy },
        ],
        &["alchemy", "quicknode"],
        2,
        ChainHealth::Healthy
    )]
    #[case::matched_by_url_not_by_name(
        &[
            ProbedProvider { name: "my_alchemy", rpc_url: ALCHEMY_URL, status: ProviderStatus::Healthy },
            ProbedProvider { name: "my_quicknode", rpc_url: QUICKNODE_URL, status: ProviderStatus::Healthy },
        ],
        &["alchemy", "quicknode"],
        2,
        ChainHealth::Healthy
    )]
    #[case::unhealthy_when_any_whitelisted_provider_fails(
        &[
            ProbedProvider { name: "alchemy", rpc_url: ALCHEMY_URL, status: ProviderStatus::Healthy },
            ProbedProvider { name: "quicknode", rpc_url: QUICKNODE_URL, status: ProviderStatus::Unreachable },
        ],
        &["alchemy", "quicknode"],
        1,
        ChainHealth::UnhealthyProviders { unhealthy: 1, quorum: quorum(1, 2) }
    )]
    #[case::below_quorum_wins_over_a_failing_provider(
        &[
            ProbedProvider { name: "alchemy", rpc_url: ALCHEMY_URL, status: ProviderStatus::Unreachable },
            ProbedProvider { name: "own_node", rpc_url: OWN_NODE_URL, status: ProviderStatus::Healthy },
        ],
        &["alchemy", "quicknode"],
        2,
        ChainHealth::BelowQuorum(quorum(2, 1))
    )]
    #[case::unreachable_provider_missing_from_the_whitelist_ignored(
        &[
            ProbedProvider { name: "alchemy", rpc_url: ALCHEMY_URL, status: ProviderStatus::Healthy },
            ProbedProvider { name: "own_node", rpc_url: OWN_NODE_URL, status: ProviderStatus::Unreachable },
        ],
        &["alchemy"],
        1,
        ChainHealth::Healthy
    )]
    #[case::provider_missing_from_the_whitelist_on_another_network_fails_the_chain(
        &[
            ProbedProvider { name: "alchemy", rpc_url: ALCHEMY_URL, status: ProviderStatus::Healthy },
            ProbedProvider { name: "own_node", rpc_url: OWN_NODE_URL, status: wrong_network() },
        ],
        &["alchemy"],
        1,
        ChainHealth::WrongNetwork { providers: 1 }
    )]
    #[case::whitelisted_provider_on_another_network_fails_the_chain(
        &[
            ProbedProvider { name: "alchemy", rpc_url: ALCHEMY_URL, status: ProviderStatus::Healthy },
            ProbedProvider { name: "quicknode", rpc_url: QUICKNODE_URL, status: wrong_network() },
        ],
        &["alchemy", "quicknode"],
        1,
        ChainHealth::WrongNetwork { providers: 1 }
    )]
    #[case::provider_that_differs_from_its_whitelist_provider_not_counted(
        &[ProbedProvider { name: "alchemy", rpc_url: "http://alchemy.example.com", status: ProviderStatus::Healthy }],
        &["alchemy"],
        1,
        ChainHealth::BelowQuorum(quorum(1, 0))
    )]
    #[case::whitelist_provider_counted_once_and_healthy_only_when_all_its_local_providers_are(
        &[
            ProbedProvider { name: "alchemy_a", rpc_url: "https://alchemy.example.com/a", status: ProviderStatus::Healthy },
            ProbedProvider { name: "alchemy_b", rpc_url: "https://alchemy.example.com/b", status: ProviderStatus::Unreachable },
        ],
        &["alchemy"],
        1,
        ChainHealth::UnhealthyProviders { unhealthy: 1, quorum: quorum(1, 1) }
    )]
    #[case::whitelist_provider_unhealthy_once_however_many_of_its_local_providers_fail(
        &[
            ProbedProvider { name: "alchemy_a", rpc_url: "https://alchemy.example.com/a", status: ProviderStatus::Unreachable },
            ProbedProvider { name: "alchemy_b", rpc_url: "https://alchemy.example.com/b", status: ProviderStatus::Unreachable },
        ],
        &["alchemy"],
        1,
        ChainHealth::UnhealthyProviders { unhealthy: 1, quorum: quorum(1, 1) }
    )]
    #[case::below_quorum_wins_over_a_provider_on_another_network(
        &[ProbedProvider { name: "alchemy", rpc_url: ALCHEMY_URL, status: wrong_network() }],
        &["alchemy", "quicknode"],
        2,
        ChainHealth::BelowQuorum(quorum(2, 1))
    )]
    fn judge__should_judge_a_chain_by_its_counted_whitelist_providers(
        #[case] local_providers: &[ProbedProvider],
        #[case] whitelist_providers: &[&str],
        #[case] whitelist_quorum: u64,
        #[case] expected: ChainHealth,
    ) {
        // Given
        let ProbedConfig { local, report } = polygon_with_report(local_providers);
        let whitelist = whitelist_of(
            dtos::ForeignChain::Polygon,
            whitelist_providers,
            whitelist_quorum,
        );

        // When
        let health = judge(&report, &local, &whitelist);

        // Then
        assert_eq!(
            health,
            BTreeMap::from([(dtos::ForeignChain::Polygon, expected)])
        );
    }

    #[test]
    fn judge__should_judge_each_chain_by_its_own_providers_and_leave_out_the_ones_it_cannot_judge()
    {
        // Given
        let alchemy = |status| ProbedProvider {
            name: "alchemy",
            rpc_url: ALCHEMY_URL,
            status,
        };
        let ProbedConfig { local, report } = config_with_report(&[
            (
                dtos::ForeignChain::Polygon,
                alchemy(ProviderStatus::Healthy),
            ),
            (dtos::ForeignChain::Ethereum, alchemy(wrong_network())),
            (dtos::ForeignChain::Base, alchemy(ProviderStatus::Healthy)),
            (
                dtos::ForeignChain::Bnb,
                alchemy(ProviderStatus::ProbeNotImplemented),
            ),
        ]);
        let whitelist: ForeignChainWhitelist = [
            dtos::ForeignChain::Polygon,
            dtos::ForeignChain::Ethereum,
            dtos::ForeignChain::Bnb,
        ]
        .into_iter()
        .flat_map(|chain| whitelist_of(chain, &["alchemy"], 1))
        .collect();

        // When
        let health = judge(&report, &local, &whitelist);

        // Then
        assert_eq!(
            health,
            BTreeMap::from([
                (dtos::ForeignChain::Polygon, ChainHealth::Healthy),
                (
                    dtos::ForeignChain::Ethereum,
                    ChainHealth::WrongNetwork { providers: 1 }
                ),
            ])
        );
    }

    #[test]
    #[traced_test]
    fn log__should_warn_only_for_a_chain_below_quorum_or_unhealthy() {
        // Given
        let health_per_chain = BTreeMap::from([
            (dtos::ForeignChain::Polygon, ChainHealth::Healthy),
            (
                dtos::ForeignChain::Base,
                ChainHealth::BelowQuorum(quorum(2, 1)),
            ),
            (
                dtos::ForeignChain::Bnb,
                ChainHealth::UnhealthyProviders {
                    unhealthy: 1,
                    quorum: quorum(1, 2),
                },
            ),
            (
                dtos::ForeignChain::Arbitrum,
                ChainHealth::WrongNetwork { providers: 1 },
            ),
        ]);

        // When
        log(&health_per_chain);

        // Then
        let expected_levels = [
            ("INFO", "foreign chain is healthy"),
            ("WARN", "foreign chain is below quorum"),
            (
                "WARN",
                "foreign chain is unhealthy: a whitelisted RPC provider",
            ),
            (
                "WARN",
                "foreign chain is unhealthy: an RPC provider serves another network",
            ),
        ];
        logs_assert(|lines: &[&str]| {
            expected_levels
                .iter()
                .try_for_each(|(level, message)| logged_times(lines, level, message, 1))
        });
    }
}
