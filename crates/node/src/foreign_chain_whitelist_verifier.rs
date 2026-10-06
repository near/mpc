//! Checks that the node's local foreign chain RPC config matches the on chain whitelist
//! (`allowed_foreign_chain_providers`) and logs every divergence. Nothing gates on the result.
//!
//! A configured provider links to a whitelist entry by its URL host, never by its config name, as
//! [`provider_identity`] describes. A provider whose host matches no entry, every way a provider
//! differs from its entry, two providers linked to one entry, and a whitelisted `base_url` that
//! does not parse are logged as warnings. Logs name the chain, the config provider name and the
//! public whitelist entry, never the configured `rpc_url` or a token.
//!
//! On a fresh deployment with an unvoted whitelist, the verifier emits one
//! [`ChainNotInWhitelist`](DiagnosticKind::ChainNotInWhitelist) info per configured chain. That is
//! expected during rollout and clears once the whitelist is populated and the watch channel
//! updates.

use std::collections::BTreeMap;

use mpc_node_config::{
    ForeignChainConfig, ForeignChainsConfig,
    foreign_chains::{
        RpcProviderName,
        provider_identity::{self, Mismatch},
    },
};
use near_mpc_contract_interface::types::{self as dtos, ChainEntry, ProviderConfig, ProviderId};
use tokio::sync::watch;
use url::Url;

/// Subscribes to the contract's `allowed_foreign_chain_providers` whitelist (published by
/// [`monitor_allowed_foreign_chain_providers`](crate::indexer::tee::monitor_allowed_foreign_chain_providers))
/// and logs any divergence from the local config. Processes the current value immediately, then
/// reacts to each change.
///
/// `run` owns no I/O: the polling and retry live in the monitor adapter, so when the chain gateway
/// exposes a native subscription only the adapter changes, and `run` can be driven from a
/// [`watch::channel`] in tests.
pub(crate) async fn run(
    mut whitelist_rx: watch::Receiver<BTreeMap<dtos::ForeignChain, ChainEntry>>,
    local: ForeignChainsConfig,
) {
    loop {
        let diagnostics = compare(&local, &whitelist_rx.borrow_and_update());
        if diagnostics.is_empty() {
            tracing::info!("foreign chain whitelist: local config matches the contract whitelist");
        }
        diagnostics.iter().for_each(log_diagnostic);
        if whitelist_rx.changed().await.is_err() {
            // Sender dropped: the indexer is shutting down, nothing left to verify against.
            break;
        }
    }
}

/// Never holds a configured `rpc_url` or token, since it is logged.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Diagnostic {
    chain: dtos::ForeignChain,
    provider: Option<RpcProviderName>,
    kind: DiagnosticKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DiagnosticKind {
    ChainNotInWhitelist,
    /// No configured provider can link to this whitelist entry.
    UnparseableBaseUrl {
        whitelist_id: ProviderId,
        base_url: String,
    },
    /// No whitelisted `base_url` has the host of the configured `rpc_url`.
    ProviderNotInWhitelist,
    Misconfigured {
        whitelist_id: ProviderId,
        whitelisted: ProviderConfig,
        mismatch: Mismatch,
    },
    /// Another configured provider links to the same whitelist entry.
    Duplicate {
        whitelist_id: ProviderId,
        first: RpcProviderName,
    },
}

fn compare(
    local: &ForeignChainsConfig,
    whitelist: &BTreeMap<dtos::ForeignChain, ChainEntry>,
) -> Vec<Diagnostic> {
    local
        .iter_chains()
        .flat_map(|(chain, config)| match whitelist.get(&chain) {
            Some(entry) => compare_chain(chain, config, entry),
            None => vec![Diagnostic {
                chain,
                provider: None,
                kind: DiagnosticKind::ChainNotInWhitelist,
            }],
        })
        .collect()
}

fn compare_chain(
    chain: dtos::ForeignChain,
    local: &ForeignChainConfig,
    entry: &ChainEntry,
) -> Vec<Diagnostic> {
    let mut diagnostics: Vec<Diagnostic> = entry
        .providers
        .iter()
        .filter(|(_, whitelisted)| Url::parse(&whitelisted.base_url).is_err())
        .map(|(id, whitelisted)| Diagnostic {
            chain,
            provider: None,
            kind: DiagnosticKind::UnparseableBaseUrl {
                whitelist_id: id.clone(),
                base_url: whitelisted.base_url.clone(),
            },
        })
        .collect();
    let mut first_linked: BTreeMap<&ProviderId, &RpcProviderName> = BTreeMap::new();
    for (name, provider) in local.providers.iter() {
        let diagnostic = |kind| Diagnostic {
            chain,
            provider: Some(name.clone()),
            kind,
        };
        let link = Url::parse(&provider.rpc_url)
            .ok()
            .and_then(|url| provider_identity::link(entry, &url, (&provider.auth).into()));
        let Some(link) = link else {
            diagnostics.push(diagnostic(DiagnosticKind::ProviderNotInWhitelist));
            continue;
        };
        let first = *first_linked.entry(link.id).or_insert(name);
        if first != name {
            diagnostics.push(diagnostic(DiagnosticKind::Duplicate {
                whitelist_id: link.id.clone(),
                first: first.clone(),
            }));
        }
        diagnostics.extend(link.mismatches.into_iter().map(|mismatch| {
            diagnostic(DiagnosticKind::Misconfigured {
                whitelist_id: link.id.clone(),
                whitelisted: link.whitelisted.clone(),
                mismatch,
            })
        }));
    }
    diagnostics
}

fn log_diagnostic(diagnostic: &Diagnostic) {
    let chain = diagnostic.chain;
    let provider = diagnostic.provider.as_deref();
    match &diagnostic.kind {
        DiagnosticKind::ChainNotInWhitelist => {
            tracing::info!(
                ?chain,
                "foreign chain whitelist: chain is not whitelisted yet"
            );
        }
        DiagnosticKind::UnparseableBaseUrl {
            whitelist_id,
            base_url,
        } => {
            tracing::warn!(
                ?chain,
                %whitelist_id,
                base_url,
                "foreign chain whitelist: whitelisted base_url does not parse, so no provider can link to it"
            );
        }
        DiagnosticKind::ProviderNotInWhitelist => {
            tracing::warn!(
                ?chain,
                provider,
                "foreign chain whitelist: provider is not in the whitelist because no whitelisted base_url has the host of its rpc_url"
            );
        }
        DiagnosticKind::Misconfigured {
            whitelist_id,
            whitelisted,
            mismatch: Mismatch::UnknownContractVariant,
        } => {
            tracing::error!(
                ?chain,
                provider,
                %whitelist_id,
                ?whitelisted,
                "foreign chain whitelist entry uses a variant this node binary does not recognize: upgrade the node"
            );
        }
        DiagnosticKind::Misconfigured {
            whitelist_id,
            whitelisted,
            mismatch,
        } => {
            tracing::warn!(
                ?chain,
                provider,
                %whitelist_id,
                ?whitelisted,
                ?mismatch,
                "foreign chain whitelist: provider differs from its whitelist entry"
            );
        }
        DiagnosticKind::Duplicate {
            whitelist_id,
            first,
        } => {
            tracing::warn!(
                ?chain,
                provider,
                first_provider = first.as_str(),
                %whitelist_id,
                "foreign chain whitelist: two providers link to the same whitelist entry, which doubles the RPC requests"
            );
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use mpc_node_config::{AuthConfig, ForeignChainProviderConfig, TokenConfig};
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use near_mpc_contract_interface::types::{AuthScheme, ChainRouting};
    use rstest::rstest;
    use tracing_test::traced_test;

    fn provider(rpc_url: &str, auth: AuthConfig) -> ForeignChainProviderConfig {
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

    fn path_auth(rpc_url: &str) -> ForeignChainProviderConfig {
        let auth = AuthConfig::Path {
            placeholder: "{api_key}".to_string(),
            token: token("abc"),
        };
        provider(rpc_url, auth)
    }

    fn must_ethereum(providers: &[(&str, ForeignChainProviderConfig)]) -> ForeignChainsConfig {
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

    fn whitelisted(base_url: &str, auth_scheme: AuthScheme) -> ProviderConfig {
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
        whitelisted("https://eth-mainnet.g.alchemy.com/v2/", auth_scheme)
    }

    fn quicknode() -> ProviderConfig {
        let auth_scheme = AuthScheme::Path {
            placeholder: "{API_KEY}".to_string(),
        };
        whitelisted("https://{}.quiknode.pro", auth_scheme)
    }

    fn diagnostic(provider: &str, kind: DiagnosticKind) -> Diagnostic {
        Diagnostic {
            chain: dtos::ForeignChain::Ethereum,
            provider: Some(RpcProviderName::from(provider.to_string())),
            kind,
        }
    }

    #[rstest]
    #[case::config_names_swap_the_whitelist_ids(
        must_ethereum(&[
            ("alchemy", path_auth("https://my-slug.quiknode.pro/{api_key}")),
            ("quicknode", path_auth("https://eth-mainnet.g.alchemy.com/v2/{api_key}")),
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
        let local = must_ethereum(&[(
            "alchemy",
            provider("https://eth-mainnet.example.com", AuthConfig::None),
        )]);

        // When
        let diagnostics = compare(&local, &BTreeMap::new());

        // Then
        assert_eq!(
            diagnostics,
            vec![Diagnostic {
                chain: dtos::ForeignChain::Ethereum,
                provider: None,
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
        let local = must_ethereum(&[(name, provider(rpc_url, AuthConfig::None))]);
        let whitelist = must_ethereum_whitelist(&[("alchemy", alchemy())]);

        // When
        let diagnostics = compare(&local, &whitelist);

        // Then
        assert_eq!(
            diagnostics,
            vec![diagnostic(name, DiagnosticKind::ProviderNotInWhitelist)]
        );
    }

    #[test]
    fn compare__should_emit_unparseable_base_url_and_still_link_to_the_other_entries() {
        // Given
        let local = must_ethereum(&[
            (
                "alchemy",
                path_auth("https://eth-mainnet.g.alchemy.com/v2/{api_key}"),
            ),
            (
                "quicknode",
                path_auth("https://slug.quiknode.pro/{api_key}"),
            ),
        ]);
        let unparseable = whitelisted("slug.quiknode.pro", AuthScheme::None);
        let whitelist =
            must_ethereum_whitelist(&[("alchemy", alchemy()), ("quicknode", unparseable)]);

        // When
        let diagnostics = compare(&local, &whitelist);

        // Then
        let unparseable_base_url = Diagnostic {
            chain: dtos::ForeignChain::Ethereum,
            provider: None,
            kind: DiagnosticKind::UnparseableBaseUrl {
                whitelist_id: ProviderId("quicknode".to_string()),
                base_url: "slug.quiknode.pro".to_string(),
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
        let local = must_ethereum(&[(
            "my-alchemy",
            path_auth("http://eth-mainnet.g.alchemy.com/v2/x/{api_key}"),
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
                    whitelisted: alchemy(),
                    mismatch,
                },
            )
        };
        assert_eq!(
            diagnostics,
            vec![
                misconfigured(Mismatch::Scheme {
                    configured: "http".to_string(),
                    whitelisted: "https".to_string(),
                }),
                misconfigured(Mismatch::PlaceholderPosition),
            ]
        );
    }

    #[test]
    fn compare__should_emit_duplicate_when_two_providers_link_to_one_entry() {
        // Given
        let local = must_ethereum(&[
            (
                "quicknode-a",
                path_auth("https://slug-a.quiknode.pro/{api_key}"),
            ),
            (
                "quicknode-b",
                path_auth("https://slug-b.quiknode.pro/{api_key}"),
            ),
        ]);
        let whitelist = must_ethereum_whitelist(&[("quicknode", quicknode())]);

        // When
        let diagnostics = compare(&local, &whitelist);

        // Then
        let expected = DiagnosticKind::Duplicate {
            whitelist_id: ProviderId("quicknode".to_string()),
            first: RpcProviderName::from("quicknode-a".to_string()),
        };
        assert_eq!(diagnostics, vec![diagnostic("quicknode-b", expected)]);
    }

    /// Every configured value that must stay out of logs carries this marker.
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
        let local = must_ethereum(&[
            (
                "duplicate-a",
                path_auth("https://slug-zq7-a.quiknode.pro/{api_key}"),
            ),
            (
                "duplicate-b",
                path_auth("https://slug-zq7-b.quiknode.pro/key-zq7"),
            ),
            (
                "wrong-path",
                provider("https://eth-mainnet.g.alchemy.com/v3-zq7/key-zq7", header),
            ),
            (
                "unlisted",
                provider("https://own-node-zq7.internal/key-zq7", AuthConfig::None),
            ),
            (
                "query",
                provider("https://lb.drpc.org/ogrpc?network=zq7", query),
            ),
        ]);
        let drpc = whitelisted(
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
        let (whitelist_tx, whitelist_rx) = watch::channel(whitelist);
        drop(whitelist_tx);

        // When
        run(whitelist_rx, local).await;

        // Then
        assert!(logs_contain("provider differs from its whitelist entry"));
        assert!(logs_contain(
            "two providers link to the same whitelist entry"
        ));
        assert!(logs_contain("provider is not in the whitelist"));
        assert!(!logs_contain(SECRET_MARKER));
    }
}
