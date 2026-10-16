//! Compares the local foreign chain RPC config with the on chain whitelist
//! (`allowed_foreign_chain_providers`) and logs each difference. The result does not change node
//! behavior.
//!
//! A local provider matches a whitelist provider by its URL host, as [`provider_identity`]
//! describes.
//!
//! Log levels:
//! - Error: a whitelisted `base_url` is invalid (a bug or a bad vote).
//! - Error: a whitelist entry uses a variant this node version does not know (upgrade the node).
//! - Warn: a local provider differs from its whitelist provider, or two local providers match a single whitelist entry.
//! - Info: a local provider or chain is not in the whitelist. Both are normal.
//! - Info: the local config matches the whitelist.
//!
//! Logs show the chain, the local provider name, local auth names and schemes, and public whitelist
//! values. They never show the local `rpc_url` or a token.

use std::collections::BTreeMap;

use mpc_node_config::{
    ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig,
    foreign_chains::{
        RpcProviderName,
        provider_identity::{self, Mismatch, WhitelistMatch},
    },
};
use near_mpc_contract_interface::types::{self as dtos, ChainEntry, ProviderConfig, ProviderId};
use tokio::sync::watch;
use url::Url;

use crate::indexer::foreign_chain::ForeignChainWhitelist;

/// Compares the local config with each whitelist that
/// [`monitor_foreign_chain_whitelist`](crate::indexer::foreign_chain::monitor_foreign_chain_whitelist)
/// publishes. Waits for the first whitelist read, then compares again on each change.
///
/// `run` does not read the contract: the monitor polls it, so a change to how the node reads the
/// whitelist changes only the monitor.
pub(crate) async fn run(
    mut whitelist_rx: watch::Receiver<Option<ForeignChainWhitelist>>,
    local: ForeignChainsConfig,
) {
    loop {
        let diagnostics = whitelist_rx
            .borrow_and_update()
            .as_ref()
            .map(|whitelist| compare(&local, whitelist));
        if let Some(diagnostics) = diagnostics {
            log_diagnostics(&diagnostics);
        }
        if whitelist_rx.changed().await.is_err() {
            // Sender dropped: the indexer is shutting down, nothing left to verify against.
            break;
        }
    }
}

/// Holds no local `rpc_url` and no token, because it is logged.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Diagnostic {
    chain: dtos::ForeignChain,
    local_name: Option<RpcProviderName>,
    kind: DiagnosticKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DiagnosticKind {
    ChainNotInWhitelist,
    UnparseableBaseUrl {
        whitelist_id: ProviderId,
        whitelist_base_url: String,
    },
    ProviderNotInWhitelist,
    Misconfigured {
        whitelist_id: ProviderId,
        whitelist_provider: ProviderConfig,
        mismatch: Mismatch,
    },
    /// Another local provider matches the same whitelist provider.
    Duplicate {
        whitelist_id: ProviderId,
        first_local_name: RpcProviderName,
    },
}

fn compare(local: &ForeignChainsConfig, whitelist: &ForeignChainWhitelist) -> Vec<Diagnostic> {
    local
        .iter_chains()
        .flat_map(|(chain, local_config)| match whitelist.get(&chain) {
            Some(whitelist_entry) => compare_chain(chain, local_config, whitelist_entry),
            None => vec![Diagnostic {
                chain,
                local_name: None,
                kind: DiagnosticKind::ChainNotInWhitelist,
            }],
        })
        .collect()
}

fn compare_chain(
    chain: dtos::ForeignChain,
    local_config: &ForeignChainConfig,
    whitelist_entry: &ChainEntry,
) -> Vec<Diagnostic> {
    let mut diagnostics: Vec<Diagnostic> = whitelist_entry
        .providers
        .iter()
        .filter(|(_, whitelist_provider)| {
            provider_identity::parse_base_url(&whitelist_provider.base_url).is_none()
        })
        .map(|(whitelist_id, whitelist_provider)| Diagnostic {
            chain,
            local_name: None,
            kind: DiagnosticKind::UnparseableBaseUrl {
                whitelist_id: whitelist_id.clone(),
                whitelist_base_url: whitelist_provider.base_url.clone(),
            },
        })
        .collect();
    let mut first_local_name_by_whitelist_id: BTreeMap<&ProviderId, &RpcProviderName> =
        BTreeMap::new();
    for (local_name, local_provider) in local_config.providers.iter() {
        let diagnostic = |kind| Diagnostic {
            chain,
            local_name: Some(local_name.clone()),
            kind,
        };
        let Some(whitelist_match) = find_whitelist_match(whitelist_entry, local_provider) else {
            diagnostics.push(diagnostic(DiagnosticKind::ProviderNotInWhitelist));
            continue;
        };
        let first_local_name = *first_local_name_by_whitelist_id
            .entry(whitelist_match.id)
            .or_insert(local_name);
        if first_local_name != local_name {
            diagnostics.push(diagnostic(DiagnosticKind::Duplicate {
                whitelist_id: whitelist_match.id.clone(),
                first_local_name: first_local_name.clone(),
            }));
        }
        diagnostics.extend(whitelist_match.mismatches.into_iter().map(|mismatch| {
            diagnostic(DiagnosticKind::Misconfigured {
                whitelist_id: whitelist_match.id.clone(),
                whitelist_provider: whitelist_match.whitelisted.clone(),
                mismatch,
            })
        }));
    }
    diagnostics
}

/// A local `rpc_url` that does not parse matches nothing.
pub(crate) fn find_whitelist_match<'w>(
    whitelist_entry: &'w ChainEntry,
    local_provider: &ForeignChainProviderConfig,
) -> Option<WhitelistMatch<'w>> {
    let local_url = Url::parse(&local_provider.rpc_url).ok()?;
    provider_identity::find_match(whitelist_entry, &local_url, (&local_provider.auth).into())
}

fn log_diagnostics(diagnostics: &[Diagnostic]) {
    if diagnostics.is_empty() {
        tracing::info!("foreign chain whitelist: local config matches the contract whitelist");
    }
    diagnostics.iter().for_each(log_diagnostic);
}

fn log_diagnostic(diagnostic: &Diagnostic) {
    let chain = diagnostic.chain;
    let local_provider = diagnostic.local_name.as_deref();
    match &diagnostic.kind {
        DiagnosticKind::ChainNotInWhitelist => {
            tracing::info!(
                ?chain,
                "foreign chain whitelist: chain is not whitelisted yet"
            );
        }
        DiagnosticKind::UnparseableBaseUrl {
            whitelist_id,
            whitelist_base_url,
        } => {
            tracing::error!(
                ?chain,
                %whitelist_id,
                whitelist_base_url,
                "foreign chain whitelist: cannot parse the on chain whitelist entry, contact the NEAR MPC team"
            );
        }
        DiagnosticKind::ProviderNotInWhitelist => {
            tracing::info!(
                ?chain,
                local_provider,
                "foreign chain whitelist: extra provider (its host matches no whitelist entry)"
            );
        }
        DiagnosticKind::Misconfigured {
            whitelist_id,
            whitelist_provider,
            mismatch: Mismatch::UnknownContractVariant,
        } => {
            tracing::error!(
                ?chain,
                local_provider,
                %whitelist_id,
                ?whitelist_provider,
                "foreign chain whitelist: entry uses a variant this node version does not know, upgrade the node"
            );
        }
        DiagnosticKind::Misconfigured {
            whitelist_id,
            whitelist_provider,
            mismatch,
        } => {
            tracing::warn!(
                ?chain,
                local_provider,
                %whitelist_id,
                ?whitelist_provider,
                ?mismatch,
                "foreign chain whitelist: provider differs from its whitelist entry"
            );
        }
        DiagnosticKind::Duplicate {
            whitelist_id,
            first_local_name,
        } => {
            tracing::warn!(
                ?chain,
                local_provider,
                first_local_provider = first_local_name.as_str(),
                %whitelist_id,
                "foreign chain whitelist: two providers match the same whitelist entry"
            );
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::async_testing::{MaybeReady, run_future_once};
    use mpc_node_config::{AuthConfig, TokenConfig};
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use near_mpc_contract_interface::types::{AuthScheme, ChainRouting};
    use rstest::rstest;
    use tracing_test::traced_test;

    fn local_provider(rpc_url: &str, auth: AuthConfig) -> ForeignChainProviderConfig {
        ForeignChainProviderConfig {
            rpc_url: rpc_url.to_string(),
            auth,
        }
    }

    fn token(val: &str) -> TokenConfig {
        TokenConfig::Val {
            val: val.to_string(),
        }
    }

    fn local_path_auth(rpc_url: &str) -> ForeignChainProviderConfig {
        let auth = AuthConfig::Path {
            placeholder: "{api_key}".to_string(),
            token: token("abc"),
        };
        local_provider(rpc_url, auth)
    }

    fn must_local_ethereum(
        providers: &[(&str, ForeignChainProviderConfig)],
    ) -> ForeignChainsConfig {
        let providers: BTreeMap<RpcProviderName, ForeignChainProviderConfig> = providers
            .iter()
            .map(|(name, config)| (RpcProviderName::from(name.to_string()), config.clone()))
            .collect();
        ForeignChainsConfig {
            ethereum: Some(ForeignChainConfig {
                timeout_sec: std::num::NonZeroU64::new(30).unwrap(),
                max_retries: std::num::NonZeroU64::new(3).unwrap(),
                expected_network_fingerprint: None,
                providers: NonEmptyBTreeMap::try_from(providers)
                    .expect("a test chain has a provider"),
            }),
            ..Default::default()
        }
    }

    fn whitelist_provider(base_url: &str, auth_scheme: AuthScheme) -> ProviderConfig {
        ProviderConfig {
            base_url: base_url.to_string(),
            auth_scheme,
            chain_routing: ChainRouting::Embedded,
        }
    }

    fn must_ethereum_whitelist(
        providers: &[(&str, ProviderConfig)],
    ) -> BTreeMap<dtos::ForeignChain, ChainEntry> {
        let providers: BTreeMap<ProviderId, ProviderConfig> = providers
            .iter()
            .map(|(id, config)| (ProviderId(id.to_string()), config.clone()))
            .collect();
        let entry = ChainEntry {
            providers: NonEmptyBTreeMap::try_from(providers)
                .expect("a test whitelist has a provider"),
            quorum: 1,
        };
        BTreeMap::from([(dtos::ForeignChain::Ethereum, entry)])
    }

    fn alchemy() -> ProviderConfig {
        let auth_scheme = AuthScheme::Path {
            placeholder: "{API_KEY}".to_string(),
        };
        whitelist_provider("https://eth-mainnet.g.alchemy.com/v2/", auth_scheme)
    }

    fn quicknode() -> ProviderConfig {
        let auth_scheme = AuthScheme::Path {
            placeholder: "{API_KEY}".to_string(),
        };
        whitelist_provider("https://{}.quiknode.pro", auth_scheme)
    }

    fn diagnostic(local_name: &str, kind: DiagnosticKind) -> Diagnostic {
        Diagnostic {
            chain: dtos::ForeignChain::Ethereum,
            local_name: Some(RpcProviderName::from(local_name.to_string())),
            kind,
        }
    }

    #[rstest]
    #[case::config_names_swap_the_whitelist_ids(
        must_local_ethereum(&[
            ("alchemy", local_path_auth("https://my-slug.quiknode.pro/{api_key}")),
            ("quicknode", local_path_auth("https://eth-mainnet.g.alchemy.com/v2/{api_key}")),
        ]),
        must_ethereum_whitelist(&[("alchemy", alchemy()), ("quicknode", quicknode())])
    )]
    #[case::whitelisted_chain_not_configured(
        ForeignChainsConfig::default(),
        must_ethereum_whitelist(&[("alchemy", alchemy())])
    )]
    fn compare__should_be_silent_when_every_provider_conforms_to_an_entry_with_its_host(
        #[case] local: ForeignChainsConfig,
        #[case] whitelist: BTreeMap<dtos::ForeignChain, ChainEntry>,
    ) {
        // When
        let diagnostics = compare(&local, &whitelist);

        // Then
        assert_eq!(diagnostics, vec![]);
    }

    #[test]
    fn compare__should_emit_chain_not_in_whitelist_when_the_chain_is_missing_from_the_contract() {
        // Given
        let local = must_local_ethereum(&[(
            "alchemy",
            local_provider("https://eth-mainnet.example.com", AuthConfig::None),
        )]);

        // When
        let diagnostics = compare(&local, &BTreeMap::new());

        // Then
        assert_eq!(
            diagnostics,
            vec![Diagnostic {
                chain: dtos::ForeignChain::Ethereum,
                local_name: None,
                kind: DiagnosticKind::ChainNotInWhitelist,
            }]
        );
    }

    #[rstest]
    #[case::unlisted_host("ankr", "https://rpc.ankr.com/eth")]
    #[case::whitelist_id_as_name("alchemy", "https://eth.infura.io/v3/key")]
    fn compare__should_emit_provider_not_in_whitelist_when_no_entry_has_its_host(
        #[case] name: &str,
        #[case] rpc_url: &str,
    ) {
        // Given
        let local = must_local_ethereum(&[(name, local_provider(rpc_url, AuthConfig::None))]);
        let whitelist = must_ethereum_whitelist(&[("alchemy", alchemy())]);

        // When
        let diagnostics = compare(&local, &whitelist);

        // Then
        assert_eq!(
            diagnostics,
            vec![diagnostic(name, DiagnosticKind::ProviderNotInWhitelist)]
        );
    }

    #[rstest]
    #[case::not_a_url("slug.quiknode.pro")]
    #[case::wildcard_inside_a_label("https://{}-eth.quiknode.pro")]
    #[case::two_wildcards("https://{}.{}.quiknode.pro")]
    fn compare__should_emit_unparseable_base_url_and_still_match_the_other_entries(
        #[case] base_url: &str,
    ) {
        // Given
        let local = must_local_ethereum(&[
            (
                "alchemy",
                local_path_auth("https://eth-mainnet.g.alchemy.com/v2/{api_key}"),
            ),
            (
                "quicknode",
                local_path_auth("https://slug.quiknode.pro/{api_key}"),
            ),
        ]);
        let unparseable = whitelist_provider(base_url, AuthScheme::None);
        let whitelist =
            must_ethereum_whitelist(&[("alchemy", alchemy()), ("quicknode", unparseable)]);

        // When
        let diagnostics = compare(&local, &whitelist);

        // Then
        let unparseable_base_url = Diagnostic {
            chain: dtos::ForeignChain::Ethereum,
            local_name: None,
            kind: DiagnosticKind::UnparseableBaseUrl {
                whitelist_id: ProviderId("quicknode".to_string()),
                whitelist_base_url: base_url.to_string(),
            },
        };
        assert_eq!(
            diagnostics,
            vec![
                unparseable_base_url,
                diagnostic("quicknode", DiagnosticKind::ProviderNotInWhitelist),
            ]
        );
    }

    #[test]
    fn compare__should_emit_misconfigured_for_each_part_that_differs() {
        // Given
        let local = must_local_ethereum(&[(
            "my-alchemy",
            local_path_auth("http://eth-mainnet.g.alchemy.com/v2/x/{api_key}"),
        )]);
        let whitelist = must_ethereum_whitelist(&[("alchemy", alchemy())]);

        // When
        let diagnostics = compare(&local, &whitelist);

        // Then
        let misconfigured = |mismatch| {
            diagnostic(
                "my-alchemy",
                DiagnosticKind::Misconfigured {
                    whitelist_id: ProviderId("alchemy".to_string()),
                    whitelist_provider: alchemy(),
                    mismatch,
                },
            )
        };
        assert_eq!(
            diagnostics,
            vec![
                misconfigured(Mismatch::BaseUrl),
                misconfigured(Mismatch::PlaceholderPosition),
            ]
        );
    }

    #[test]
    fn compare__should_emit_duplicate_when_two_providers_match_one_entry() {
        // Given
        let local = must_local_ethereum(&[
            (
                "quicknode-a",
                local_path_auth("https://slug-a.quiknode.pro/{api_key}"),
            ),
            (
                "quicknode-b",
                local_path_auth("https://slug-b.quiknode.pro/{api_key}"),
            ),
        ]);
        let whitelist = must_ethereum_whitelist(&[("quicknode", quicknode())]);

        // When
        let diagnostics = compare(&local, &whitelist);

        // Then
        let expected = DiagnosticKind::Duplicate {
            whitelist_id: ProviderId("quicknode".to_string()),
            first_local_name: RpcProviderName::from("quicknode-a".to_string()),
        };
        assert_eq!(diagnostics, vec![diagnostic("quicknode-b", expected)]);
    }

    /// Each local value that must not appear in logs contains this marker.
    const SECRET_MARKER: &str = "zq7";

    #[tokio::test]
    #[traced_test]
    async fn run__should_keep_configured_urls_and_tokens_out_of_logs() {
        // Given
        let header = AuthConfig::Header {
            name: "x-token".parse().expect("a test header name parses"),
            scheme: None,
            token: token("token-zq7"),
        };
        let query = AuthConfig::Query {
            name: "dkey".to_string(),
            token: token("token-zq7"),
        };
        let local = must_local_ethereum(&[
            (
                "duplicate-a",
                local_path_auth("https://slug-zq7-a.quiknode.pro/{api_key}"),
            ),
            (
                "duplicate-b",
                local_path_auth("https://slug-zq7-b.quiknode.pro/key-zq7"),
            ),
            (
                "wrong-path",
                local_provider("https://eth-mainnet.g.alchemy.com/v3-zq7/key-zq7", header),
            ),
            (
                "unlisted",
                local_provider("https://own-node-zq7.internal/key-zq7", AuthConfig::None),
            ),
            (
                "query",
                local_provider("https://lb.drpc.org/ogrpc?network=zq7", query),
            ),
        ]);
        let drpc = whitelist_provider(
            "https://lb.drpc.org/ogrpc",
            AuthScheme::Query {
                name: "apikey".to_string(),
            },
        );
        let whitelist = must_ethereum_whitelist(&[
            ("alchemy", alchemy()),
            ("drpc", drpc),
            ("quicknode", quicknode()),
        ]);
        let (whitelist_tx, whitelist_rx) = watch::channel(Some(whitelist));
        drop(whitelist_tx);

        // When
        run(whitelist_rx, local).await;

        // Then
        assert!(logs_contain("provider differs from its whitelist entry"));
        assert!(logs_contain("two providers match the same whitelist entry"));
        assert!(logs_contain("extra provider"));
        assert!(!logs_contain(SECRET_MARKER));
    }

    #[test]
    #[traced_test]
    fn run__should_compare_only_once_the_whitelist_is_read() {
        // Given
        let local = must_local_ethereum(&[(
            "alchemy",
            local_path_auth("https://eth-mainnet.g.alchemy.com/v2/{api_key}"),
        )]);
        let whitelist = must_ethereum_whitelist(&[("alchemy", alchemy())]);
        let (whitelist_tx, whitelist_rx) = watch::channel(None);

        // When
        let MaybeReady::Future(parked_verifier) = run_future_once(run(whitelist_rx, local)) else {
            panic!("the verifier should park until the whitelist is read");
        };
        let logged_before_the_read = logs_contain("foreign chain whitelist");
        whitelist_tx.send_replace(Some(whitelist));
        run_future_once(parked_verifier);

        // Then
        assert!(!logged_before_the_read);
        assert!(logs_contain("local config matches the contract whitelist"));
    }
}
