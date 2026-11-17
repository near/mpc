//! Judges each whitelisted chain against its quorum, and each probed one also by its probe results.

use std::collections::{BTreeMap, BTreeSet};

use foreign_chain_health_check::probe::{ProbeReport, ProviderHealth, ProviderStatus};
use mpc_node_config::ForeignChainConfig;
use near_mpc_contract_interface::types as dtos;

use crate::foreign_chain_rpc_policy::{ChainQuorum, RpcQuorumStatus};
use crate::indexer::foreign_chain::ForeignChainWhitelist;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ChainHealth {
    Healthy,
    /// The voted quorum is zero or too large for this node. The contract rejects such votes.
    InvalidQuorum(u64),
    BelowQuorum(RpcQuorumStatus),
    WrongNetwork {
        providers: usize,
    },
    /// Every verify request fails: too few whitelisted providers are left to reach the quorum.
    TooFewHealthyProviders {
        healthy: usize,
        quorum: RpcQuorumStatus,
    },
    /// Verify requests still reach the quorum.
    UnhealthyProviders {
        unhealthy: usize,
        quorum: RpcQuorumStatus,
    },
}

impl ChainHealth {
    /// For a chain whose configured providers reach the quorum.
    fn from_probe(quorum: RpcQuorumStatus, tally: ProviderTally) -> Self {
        let ProviderTally {
            wrong_network,
            healthy,
            unhealthy,
        } = tally;
        if wrong_network > 0 {
            Self::WrongNetwork {
                providers: wrong_network,
            }
        } else if !quorum.is_met_by(healthy) {
            Self::TooFewHealthyProviders { healthy, quorum }
        } else if unhealthy > 0 {
            Self::UnhealthyProviders { unhealthy, quorum }
        } else {
            Self::Healthy
        }
    }
}

/// `healthy` and `unhealthy` count only the providers in [`ChainQuorum::counted_providers`],
/// `wrong_network` counts every probed provider.
#[derive(Default)]
struct ProviderTally {
    wrong_network: usize,
    healthy: usize,
    unhealthy: usize,
}

/// Leaves out a chain that is not whitelisted. A chain whose quorum cannot be enforced or is not
/// reached is judged from the config alone. Otherwise a chain is left out when it has no probe or no
/// expected network fingerprint: the probe already warns about each provider of a chain without a
/// fingerprint, and verify does not need one.
pub(crate) fn judge<'a>(
    report: &ProbeReport,
    local: impl IntoIterator<Item = (dtos::ForeignChain, &'a ForeignChainConfig)>,
    whitelist: &ForeignChainWhitelist,
) -> BTreeMap<dtos::ForeignChain, ChainHealth> {
    local
        .into_iter()
        .filter_map(|(chain, local_chain)| {
            let whitelist_entry = whitelist.get(&chain)?;
            let probed_rows: Vec<&ProviderHealth> = report
                .rows()
                .iter()
                .filter(|row| {
                    row.chain == chain
                        && row.status.was_probed()
                        && row.status != ProviderStatus::MissingExpectedFingerprint
                })
                .collect();
            let health = match ChainQuorum::new(local_chain, whitelist_entry) {
                None => Some(ChainHealth::InvalidQuorum(whitelist_entry.quorum)),
                Some(chain_quorum) if !chain_quorum.status.reaches_quorum() => {
                    Some(ChainHealth::BelowQuorum(chain_quorum.status))
                }
                Some(chain_quorum) => judge_probed_chain(&probed_rows, &chain_quorum),
            };
            health.map(|health| (chain, health))
        })
        .collect()
}

/// Mirrors the verify path: a whitelist provider is healthy when the local provider that counts for
/// it there passed the probe, see [`ChainQuorum::counted_providers`]. [`None`] when no provider was
/// probed.
fn judge_probed_chain(
    probed_rows: &[&ProviderHealth],
    chain_quorum: &ChainQuorum,
) -> Option<ChainHealth> {
    if probed_rows.is_empty() {
        return None;
    }
    let counted: BTreeSet<&str> = chain_quorum
        .counted_providers()
        .into_values()
        .map(|local_name| local_name.as_str())
        .collect();
    let tally = probed_rows
        .iter()
        .fold(ProviderTally::default(), |tally, row| {
            let is_counted = counted.contains(row.provider.0.as_str());
            let is_healthy = row.status.is_healthy();
            ProviderTally {
                wrong_network: tally.wrong_network.saturating_add(usize::from(matches!(
                    row.status,
                    ProviderStatus::WrongNetwork { .. }
                ))),
                healthy: tally
                    .healthy
                    .saturating_add(usize::from(is_counted && is_healthy)),
                unhealthy: tally
                    .unhealthy
                    .saturating_add(usize::from(is_counted && !is_healthy)),
            }
        });
    Some(ChainHealth::from_probe(chain_quorum.status, tally))
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Summary {
    pub(crate) healthy_chains: usize,
    pub(crate) judged_chains: usize,
}

pub(crate) fn summarize(health_per_chain: &BTreeMap<dtos::ForeignChain, ChainHealth>) -> Summary {
    Summary {
        healthy_chains: health_per_chain
            .values()
            .filter(|health| **health == ChainHealth::Healthy)
            .count(),
        judged_chains: health_per_chain.len(),
    }
}

pub(crate) fn log_if_unhealthy(chain: dtos::ForeignChain, health: &ChainHealth) {
    let chain = chain.label();
    match health {
        ChainHealth::Healthy => {}
        ChainHealth::InvalidQuorum(quorum) => tracing::error!(
            %chain,
            quorum,
            "foreign chain quorum cannot be enforced: the voted quorum is zero or too large, so the node does not serve the chain",
        ),
        ChainHealth::BelowQuorum(quorum) => tracing::warn!(
            %chain,
            whitelisted = quorum.configured_whitelisted_providers,
            quorum = quorum.required_whitelisted_providers.get(),
            "foreign chain is below quorum: too few configured RPC providers match the whitelist, see the whitelist differences above",
        ),
        ChainHealth::WrongNetwork { providers } => tracing::warn!(
            %chain,
            providers,
            "foreign chain is unhealthy: an RPC provider serves another network, so every verify request fails",
        ),
        ChainHealth::TooFewHealthyProviders { healthy, quorum } => tracing::warn!(
            %chain,
            healthy,
            whitelisted = quorum.configured_whitelisted_providers,
            quorum = quorum.required_whitelisted_providers.get(),
            "foreign chain is unhealthy: too few whitelisted RPC providers passed the probe, so every verify request fails",
        ),
        ChainHealth::UnhealthyProviders { unhealthy, quorum } => tracing::warn!(
            %chain,
            unhealthy,
            whitelisted = quorum.configured_whitelisted_providers,
            quorum = quorum.required_whitelisted_providers.get(),
            "foreign chain is unhealthy: a whitelisted RPC provider did not pass the probe, the others still reach the quorum",
        ),
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
    #[case::failed_backup_provider_ignored(
        &[
            ProbedProvider { name: "alchemy_a", rpc_url: "https://alchemy.example.com/a", status: ProviderStatus::Healthy },
            ProbedProvider { name: "alchemy_b", rpc_url: "https://alchemy.example.com/b", status: ProviderStatus::Unreachable },
        ],
        &["alchemy"],
        1,
        ChainHealth::Healthy
    )]
    #[case::backup_provider_not_standing_in_for_the_failed_first_one(
        &[
            ProbedProvider { name: "alchemy_a", rpc_url: "https://alchemy.example.com/a", status: ProviderStatus::Unreachable },
            ProbedProvider { name: "alchemy_b", rpc_url: "https://alchemy.example.com/b", status: ProviderStatus::Healthy },
        ],
        &["alchemy"],
        1,
        ChainHealth::TooFewHealthyProviders { healthy: 0, quorum: quorum(1, 1) }
    )]
    #[case::whitelist_provider_unhealthy_once_however_many_of_its_local_providers_fail(
        &[
            ProbedProvider { name: "alchemy_a", rpc_url: "https://alchemy.example.com/a", status: ProviderStatus::Unreachable },
            ProbedProvider { name: "alchemy_b", rpc_url: "https://alchemy.example.com/b", status: ProviderStatus::Unreachable },
        ],
        &["alchemy"],
        1,
        ChainHealth::TooFewHealthyProviders { healthy: 0, quorum: quorum(1, 1) }
    )]
    #[case::too_few_healthy_when_failing_providers_leave_less_than_the_quorum(
        &[
            ProbedProvider { name: "alchemy", rpc_url: ALCHEMY_URL, status: ProviderStatus::Healthy },
            ProbedProvider { name: "quicknode", rpc_url: QUICKNODE_URL, status: ProviderStatus::Unreachable },
        ],
        &["alchemy", "quicknode"],
        2,
        ChainHealth::TooFewHealthyProviders { healthy: 1, quorum: quorum(2, 2) }
    )]
    #[case::below_quorum_wins_over_a_provider_on_another_network(
        &[ProbedProvider { name: "alchemy", rpc_url: ALCHEMY_URL, status: wrong_network() }],
        &["alchemy", "quicknode"],
        2,
        ChainHealth::BelowQuorum(quorum(2, 1))
    )]
    #[case::below_quorum_even_without_a_fingerprint(
        &[ProbedProvider { name: "alchemy", rpc_url: ALCHEMY_URL, status: ProviderStatus::MissingExpectedFingerprint }],
        &["alchemy", "quicknode"],
        2,
        ChainHealth::BelowQuorum(quorum(2, 1))
    )]
    #[case::invalid_quorum_even_without_a_probe(
        &[ProbedProvider { name: "alchemy", rpc_url: ALCHEMY_URL, status: ProviderStatus::ProbeNotImplemented }],
        &["alchemy"],
        0,
        ChainHealth::InvalidQuorum(0)
    )]
    #[case::invalid_quorum_when_the_voted_quorum_is_zero(
        &[ProbedProvider { name: "alchemy", rpc_url: ALCHEMY_URL, status: ProviderStatus::Healthy }],
        &["alchemy"],
        0,
        ChainHealth::InvalidQuorum(0)
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
            (
                dtos::ForeignChain::Arbitrum,
                alchemy(ProviderStatus::MissingExpectedFingerprint),
            ),
        ]);
        let whitelist: ForeignChainWhitelist = [
            dtos::ForeignChain::Polygon,
            dtos::ForeignChain::Ethereum,
            dtos::ForeignChain::Bnb,
            dtos::ForeignChain::Arbitrum,
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
    fn summarize__should_count_the_healthy_and_the_judged_chains() {
        // Given
        let health_per_chain = BTreeMap::from([
            (dtos::ForeignChain::Polygon, ChainHealth::Healthy),
            (
                dtos::ForeignChain::Base,
                ChainHealth::BelowQuorum(quorum(2, 1)),
            ),
            (
                dtos::ForeignChain::Arbitrum,
                ChainHealth::WrongNetwork { providers: 1 },
            ),
        ]);

        // When
        let summary = summarize(&health_per_chain);

        // Then
        assert_eq!(
            summary,
            Summary {
                healthy_chains: 1,
                judged_chains: 3,
            }
        );
    }

    #[test]
    #[traced_test]
    fn log_if_unhealthy__should_log_every_chain_that_is_not_healthy() {
        // Given
        let health_per_chain = BTreeMap::from([
            (dtos::ForeignChain::Polygon, ChainHealth::Healthy),
            (dtos::ForeignChain::Bitcoin, ChainHealth::InvalidQuorum(0)),
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
            (
                dtos::ForeignChain::Ethereum,
                ChainHealth::TooFewHealthyProviders {
                    healthy: 0,
                    quorum: quorum(1, 1),
                },
            ),
        ]);

        // When
        health_per_chain
            .iter()
            .for_each(|(chain, health)| log_if_unhealthy(*chain, health));

        // Then
        let expected_levels = [
            ("ERROR", "foreign chain quorum cannot be enforced"),
            ("WARN", "foreign chain is below quorum"),
            (
                "WARN",
                "foreign chain is unhealthy: a whitelisted RPC provider",
            ),
            (
                "WARN",
                "foreign chain is unhealthy: an RPC provider serves another network",
            ),
            (
                "WARN",
                "foreign chain is unhealthy: too few whitelisted RPC providers",
            ),
        ];
        logs_assert(|lines: &[&str]| {
            expected_levels
                .iter()
                .try_for_each(|(level, message)| logged_times(lines, level, message, 1))?;
            logged_times(lines, "", "chain=polygon", 0)
        });
    }
}
