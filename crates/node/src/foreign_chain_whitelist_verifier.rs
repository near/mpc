//! Checks that the node's local foreign chain RPC config matches the on chain whitelist
//! (`allowed_foreign_chain_providers`) and logs every divergence. Nothing gates on the result.
//!
//! A configured provider links to a whitelist entry by its URL host, never by its config name, as
//! [`provider_identity`](mpc_node_config::foreign_chains::provider_identity) describes. A
//! provider whose host matches no entry, every way a provider differs from its entry, and two
//! providers linked to one entry are logged as warnings. Logs name the chain, the config provider
//! name, the whitelist id and the public whitelisted `base_url`, never the configured `rpc_url` or
//! a token.
//!
//! On a fresh deployment with an unvoted whitelist, the verifier emits one
//! [`ChainNotInWhitelist`](DiagnosticKind::ChainNotInWhitelist) info per configured chain. That is
//! expected during rollout and clears once the whitelist is populated and the watch channel
//! updates.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use mpc_node_config::{
    AuthConfig, ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig,
    foreign_chains::{
        RpcProviderName,
        provider_identity::{
            BaseUrlError, ChainWhitelist, ConfiguredAuth, ConfiguredUrl, Mismatch, WhitelistLink,
        },
    },
};
use near_mpc_contract_interface::types::{self as dtos, ChainEntry, ProviderId};
use tokio::sync::watch;

/// Subscribes to the contract's `allowed_foreign_chain_providers` whitelist (published by
/// `monitor_allowed_foreign_chain_providers` in [`crate::indexer::tee`]) and logs any divergence
/// from the local config. Processes the current value immediately, then reacts to each change.
///
/// `run` owns no I/O: the polling and retry live in the monitor adapter, so when the chain gateway
/// exposes a native subscription only the adapter changes, and `run` can be driven from an
/// in-memory [`watch::channel`] in tests.
pub(crate) async fn run(
    mut whitelist_rx: watch::Receiver<BTreeMap<dtos::ForeignChain, ChainEntry>>,
    local: ForeignChainsConfig,
) {
    loop {
        let diagnostics = {
            let whitelist = whitelist_rx.borrow_and_update();
            compare(&local, &whitelist)
        };
        if diagnostics.is_empty() {
            tracing::info!("foreign chain whitelist: local config matches the contract whitelist");
        } else {
            for d in &diagnostics {
                log_diagnostic(d);
            }
        }
        if whitelist_rx.changed().await.is_err() {
            // Sender dropped: the indexer is shutting down, nothing left to verify against.
            break;
        }
    }
}

/// Links a configured provider to the whitelist of its chain. Fails only on an `rpc_url` that does
/// not parse.
pub(crate) fn link_provider<'w>(
    whitelist: &ChainWhitelist<'w>,
    provider: &ForeignChainProviderConfig,
) -> Result<Option<WhitelistLink<'w>>, url::ParseError> {
    let url = ConfiguredUrl::parse(&provider.rpc_url)?;
    Ok(whitelist.link(&url, configured_auth(&provider.auth)))
}

fn configured_auth(auth: &AuthConfig) -> ConfiguredAuth<'_> {
    match auth {
        AuthConfig::None => ConfiguredAuth::None,
        AuthConfig::Header { name, scheme, .. } => ConfiguredAuth::Header {
            name: name.as_str(),
            scheme: scheme.as_deref(),
        },
        AuthConfig::Path { placeholder, .. } => ConfiguredAuth::Path { placeholder },
        AuthConfig::Query { name, .. } => ConfiguredAuth::Query { name },
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
    UnparseableWhitelistEntry {
        whitelist_id: ProviderId,
        base_url: String,
        error: BaseUrlError,
    },
    UnparseableRpcUrl(url::ParseError),
    ProviderNotInWhitelist,
    Misconfigured {
        whitelist_id: ProviderId,
        base_url: String,
        mismatch: Mismatch,
    },
    DuplicateProvider {
        whitelist_id: ProviderId,
        first: RpcProviderName,
    },
    /// The contract whitelist contains a variant this node binary doesn't recognize, so the
    /// operator should upgrade.
    UnknownContractVariant {
        whitelist_id: ProviderId,
        what: &'static str,
        value: String,
    },
}

fn compare(
    local: &ForeignChainsConfig,
    whitelist: &BTreeMap<dtos::ForeignChain, ChainEntry>,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    for (chain, local_cfg) in local.iter_chains() {
        let Some(whitelist_entry) = whitelist.get(&chain) else {
            diagnostics.push(Diagnostic {
                chain,
                provider: None,
                kind: DiagnosticKind::ChainNotInWhitelist,
            });
            continue;
        };
        compare_chain(chain, local_cfg, whitelist_entry, &mut diagnostics);
    }

    diagnostics
}

fn compare_chain(
    chain: dtos::ForeignChain,
    local: &ForeignChainConfig,
    entry: &ChainEntry,
    out: &mut Vec<Diagnostic>,
) {
    let whitelist = ChainWhitelist::parse(entry);
    out.extend(
        whitelist
            .unparseable()
            .iter()
            .map(|unparseable| Diagnostic {
                chain,
                provider: None,
                kind: DiagnosticKind::UnparseableWhitelistEntry {
                    whitelist_id: unparseable.id.clone(),
                    base_url: unparseable.config.base_url.clone(),
                    error: unparseable.error.clone(),
                },
            }),
    );

    let mut first_linked: BTreeMap<&ProviderId, &RpcProviderName> = BTreeMap::new();
    for (name, provider) in local.providers.iter() {
        let diagnostic = |kind| Diagnostic {
            chain,
            provider: Some(name.clone()),
            kind,
        };
        let link = match link_provider(&whitelist, provider) {
            Ok(Some(link)) => link,
            Ok(None) => {
                out.push(diagnostic(DiagnosticKind::ProviderNotInWhitelist));
                continue;
            }
            Err(error) => {
                out.push(diagnostic(DiagnosticKind::UnparseableRpcUrl(error)));
                continue;
            }
        };
        match first_linked.entry(link.id()) {
            Entry::Vacant(slot) => {
                slot.insert(name);
            }
            Entry::Occupied(first) => out.push(diagnostic(DiagnosticKind::DuplicateProvider {
                whitelist_id: link.id().clone(),
                first: (*first.get()).clone(),
            })),
        }
        out.extend(
            link.mismatches()
                .iter()
                .map(|mismatch| diagnostic(mismatch_kind(&link, mismatch))),
        );
    }
}

fn mismatch_kind(link: &WhitelistLink<'_>, mismatch: &Mismatch) -> DiagnosticKind {
    let whitelist_id = link.id().clone();
    let whitelisted = link.whitelisted();
    match mismatch {
        Mismatch::UnknownChainRouting => DiagnosticKind::UnknownContractVariant {
            whitelist_id,
            what: "chain_routing",
            value: format!("{:?}", whitelisted.chain_routing),
        },
        Mismatch::UnknownAuthScheme => DiagnosticKind::UnknownContractVariant {
            whitelist_id,
            what: "auth_scheme",
            value: format!("{:?}", whitelisted.auth_scheme),
        },
        mismatch => DiagnosticKind::Misconfigured {
            whitelist_id,
            base_url: whitelisted.base_url.clone(),
            mismatch: mismatch.clone(),
        },
    }
}

fn log_diagnostic(d: &Diagnostic) {
    let chain = d.chain;
    let provider = d.provider.as_ref().map(|name| name.as_str());
    match &d.kind {
        DiagnosticKind::ChainNotInWhitelist => {
            tracing::info!(
                ?chain,
                "foreign chain whitelist: chain is not whitelisted yet"
            );
        }
        DiagnosticKind::UnparseableWhitelistEntry {
            whitelist_id,
            base_url,
            error,
        } => {
            tracing::warn!(
                ?chain,
                %whitelist_id,
                %base_url,
                %error,
                "foreign chain whitelist: no provider can link to an entry whose base_url does not parse"
            );
        }
        DiagnosticKind::UnparseableRpcUrl(error) => {
            tracing::warn!(
                ?chain,
                provider,
                %error,
                "foreign chain whitelist: the configured rpc_url does not parse"
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
            base_url,
            mismatch,
        } => {
            tracing::warn!(
                ?chain,
                provider,
                %whitelist_id,
                %base_url,
                ?mismatch,
                "foreign chain whitelist: provider differs from its whitelist entry"
            );
        }
        DiagnosticKind::DuplicateProvider {
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
        DiagnosticKind::UnknownContractVariant {
            whitelist_id,
            what,
            value,
        } => {
            tracing::error!(
                ?chain,
                provider,
                %whitelist_id,
                what,
                %value,
                "foreign chain whitelist contains a variant this node binary does not recognize: upgrade the node"
            );
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use mpc_node_config::TokenConfig;
    use mpc_node_config::foreign_chains::provider_identity::AuthKind;
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use near_mpc_contract_interface::types::{AuthScheme, ChainRouting, ProviderConfig};
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

    fn path_auth(placeholder: &str) -> AuthConfig {
        AuthConfig::Path {
            placeholder: placeholder.to_string(),
            token: token("abc"),
        }
    }

    fn must_header_auth(name: &str, scheme: Option<&str>) -> AuthConfig {
        AuthConfig::Header {
            name: name.parse().expect("a test header name parses"),
            scheme: scheme.map(str::to_string),
            token: token("abc"),
        }
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

    fn whitelisted(
        base_url: &str,
        chain_routing: ChainRouting,
        auth_scheme: AuthScheme,
    ) -> ProviderConfig {
        ProviderConfig {
            base_url: base_url.to_string(),
            auth_scheme,
            chain_routing,
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
        whitelisted(
            "https://eth-mainnet.g.alchemy.com/v2/",
            ChainRouting::Embedded,
            AuthScheme::Path {
                placeholder: "{API_KEY}".to_string(),
            },
        )
    }

    fn quicknode() -> ProviderConfig {
        whitelisted(
            "https://{}.quiknode.pro",
            ChainRouting::Embedded,
            AuthScheme::Path {
                placeholder: "{api_key}".to_string(),
            },
        )
    }

    fn diagnostic(provider: &str, kind: DiagnosticKind) -> Diagnostic {
        Diagnostic {
            chain: dtos::ForeignChain::Ethereum,
            provider: Some(RpcProviderName::from(provider.to_string())),
            kind,
        }
    }

    #[test]
    fn compare__should_be_silent_when_a_provider_name_differs_from_its_whitelist_id() {
        // Given
        let local = must_ethereum(&[(
            "my-alchemy",
            provider(
                "https://eth-mainnet.g.alchemy.com/v2/{api_key}",
                path_auth("{api_key}"),
            ),
        )]);
        let whitelist = must_ethereum_whitelist(&[("alchemy", alchemy())]);

        // When
        let diags = compare(&local, &whitelist);

        // Then
        assert_eq!(diags, vec![]);
    }

    #[test]
    fn compare__should_link_providers_by_url_when_config_names_swap_whitelist_ids() {
        // Given
        let local = must_ethereum(&[
            (
                "alchemy",
                provider(
                    "https://my-slug.quiknode.pro/{api_key}",
                    path_auth("{api_key}"),
                ),
            ),
            (
                "quicknode",
                provider(
                    "https://eth-mainnet.g.alchemy.com/v2/{api_key}",
                    path_auth("{api_key}"),
                ),
            ),
        ]);
        let whitelist =
            must_ethereum_whitelist(&[("alchemy", alchemy()), ("quicknode", quicknode())]);

        // When
        let diags = compare(&local, &whitelist);

        // Then
        assert_eq!(diags, vec![]);
    }

    #[test]
    fn compare__should_emit_chain_not_in_whitelist_when_chain_missing_from_contract() {
        // Given
        let local = must_ethereum(&[(
            "alchemy",
            provider("https://eth-mainnet.example.com", AuthConfig::None),
        )]);
        let whitelist = BTreeMap::new();

        // When
        let diags = compare(&local, &whitelist);

        // Then
        assert_eq!(
            diags,
            vec![Diagnostic {
                chain: dtos::ForeignChain::Ethereum,
                provider: None,
                kind: DiagnosticKind::ChainNotInWhitelist,
            }]
        );
    }

    #[test]
    fn compare__should_be_silent_when_whitelist_has_chain_not_configured_locally() {
        // Given
        let local = ForeignChainsConfig::default();
        let whitelist = must_ethereum_whitelist(&[("alchemy", alchemy())]);

        // When
        let diags = compare(&local, &whitelist);

        // Then
        assert_eq!(diags, vec![]);
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
        let diags = compare(&local, &whitelist);

        // Then
        assert_eq!(
            diags,
            vec![diagnostic(name, DiagnosticKind::ProviderNotInWhitelist)]
        );
    }

    #[rstest]
    #[case::scheme(
        "http://eth-mainnet.g.alchemy.com/v2/{api_key}",
        path_auth("{api_key}"),
        alchemy(),
        Mismatch::Scheme { configured: "http".to_string(), whitelisted: "https".to_string() }
    )]
    #[case::path(
        "https://eth-mainnet.g.alchemy.com/v3/{api_key}",
        path_auth("{api_key}"),
        alchemy(),
        Mismatch::Path
    )]
    #[case::placeholder_position(
        "https://eth-mainnet.g.alchemy.com/v2/x/{api_key}",
        path_auth("{api_key}"),
        alchemy(),
        Mismatch::PlaceholderPosition
    )]
    #[case::auth_kind(
        "https://eth-mainnet.g.alchemy.com/v2/key",
        AuthConfig::None,
        alchemy(),
        Mismatch::AuthKind { configured: AuthKind::None, whitelisted: AuthKind::Path }
    )]
    #[case::routing_segment(
        "https://rpc.ankr.com/ethereum",
        AuthConfig::None,
        whitelisted(
            "https://rpc.ankr.com",
            ChainRouting::PathSegment { segment: "eth".to_string() },
            AuthScheme::None,
        ),
        Mismatch::ChainRouting
    )]
    #[case::routing_query(
        "https://lb.drpc.org/ogrpc?xnetwork=ethereum",
        AuthConfig::None,
        whitelisted(
            "https://lb.drpc.org/ogrpc",
            ChainRouting::QueryParam { name: "network".to_string(), value: "ethereum".to_string() },
            AuthScheme::None,
        ),
        Mismatch::ChainRouting
    )]
    #[case::header_name(
        "https://sui-mainnet.g.alchemy.com",
        must_header_auth("x-api-key", Some("Bearer")),
        whitelisted(
            "https://sui-mainnet.g.alchemy.com",
            ChainRouting::Embedded,
            AuthScheme::Header { name: "Authorization".to_string(), scheme: Some("Bearer".to_string()) },
        ),
        Mismatch::HeaderName { configured: "x-api-key".to_string(), whitelisted: "Authorization".to_string() }
    )]
    #[case::header_scheme(
        "https://sui-mainnet.g.alchemy.com",
        must_header_auth("authorization", None),
        whitelisted(
            "https://sui-mainnet.g.alchemy.com",
            ChainRouting::Embedded,
            AuthScheme::Header { name: "Authorization".to_string(), scheme: Some("Bearer".to_string()) },
        ),
        Mismatch::HeaderScheme { configured: None, whitelisted: Some("Bearer".to_string()) }
    )]
    #[case::query_name(
        "https://lb.drpc.org/ogrpc",
        AuthConfig::Query { name: "dkey".to_string(), token: token("abc") },
        whitelisted(
            "https://lb.drpc.org/ogrpc",
            ChainRouting::Embedded,
            AuthScheme::Query { name: "apikey".to_string() },
        ),
        Mismatch::QueryName { configured: "dkey".to_string(), whitelisted: "apikey".to_string() }
    )]
    fn compare__should_emit_misconfigured_for_the_part_that_differs(
        #[case] rpc_url: &str,
        #[case] auth: AuthConfig,
        #[case] whitelisted_provider: ProviderConfig,
        #[case] mismatch: Mismatch,
    ) {
        // Given
        let base_url = whitelisted_provider.base_url.clone();
        let local = must_ethereum(&[("configured", provider(rpc_url, auth))]);
        let whitelist = must_ethereum_whitelist(&[("whitelisted", whitelisted_provider)]);

        // When
        let diags = compare(&local, &whitelist);

        // Then
        let expected = DiagnosticKind::Misconfigured {
            whitelist_id: ProviderId("whitelisted".to_string()),
            base_url,
            mismatch,
        };
        assert_eq!(diags, vec![diagnostic("configured", expected)]);
    }

    #[test]
    fn compare__should_emit_duplicate_when_two_providers_link_to_one_entry() {
        // Given
        let local = must_ethereum(&[
            (
                "quicknode-a",
                provider(
                    "https://slug-a.quiknode.pro/{api_key}",
                    path_auth("{api_key}"),
                ),
            ),
            (
                "quicknode-b",
                provider(
                    "https://slug-b.quiknode.pro/{api_key}",
                    path_auth("{api_key}"),
                ),
            ),
        ]);
        let whitelist = must_ethereum_whitelist(&[("quicknode", quicknode())]);

        // When
        let diags = compare(&local, &whitelist);

        // Then
        let expected = DiagnosticKind::DuplicateProvider {
            whitelist_id: ProviderId("quicknode".to_string()),
            first: RpcProviderName::from("quicknode-a".to_string()),
        };
        assert_eq!(diags, vec![diagnostic("quicknode-b", expected)]);
    }

    #[test]
    fn compare__should_emit_unparseable_whitelist_entry_for_a_configured_chain() {
        // Given
        let local = must_ethereum(&[(
            "alchemy",
            provider(
                "https://eth-mainnet.g.alchemy.com/v2/{api_key}",
                path_auth("{api_key}"),
            ),
        )]);
        let broken = whitelisted("not a url", ChainRouting::Embedded, AuthScheme::None);
        let whitelist = must_ethereum_whitelist(&[("alchemy", alchemy()), ("broken", broken)]);

        // When
        let diags = compare(&local, &whitelist);

        // Then
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert_eq!(diags[0].provider, None);
        assert_matches!(
            &diags[0].kind,
            DiagnosticKind::UnparseableWhitelistEntry { whitelist_id, base_url, .. }
                if whitelist_id.0 == "broken" && base_url == "not a url"
        );
    }

    #[test]
    fn compare__should_emit_unparseable_rpc_url() {
        // Given
        let local = must_ethereum(&[("broken", provider("not a url", AuthConfig::None))]);
        let whitelist = must_ethereum_whitelist(&[("alchemy", alchemy())]);

        // When
        let diags = compare(&local, &whitelist);

        // Then
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert_matches!(&diags[0].kind, DiagnosticKind::UnparseableRpcUrl(_));
    }

    /// Every configured value that must stay out of logs carries this marker.
    const SECRET_MARKER: &str = "zq7";

    /// Triggers the provider warnings with an `rpc_url`, slug, path or token that carries
    /// [`SECRET_MARKER`].
    fn must_config_with_secrets_in_warnings() -> (
        ForeignChainsConfig,
        BTreeMap<dtos::ForeignChain, ChainEntry>,
    ) {
        let header = AuthConfig::Header {
            name: "x-token".parse().expect("a test header name parses"),
            scheme: None,
            token: token("token-zq7"),
        };
        let local = must_ethereum(&[
            (
                "duplicate-a",
                provider(
                    "https://slug-zq7-a.quiknode.pro/{api_key}",
                    path_auth("{api_key}"),
                ),
            ),
            (
                "duplicate-b",
                provider(
                    "https://slug-zq7-b.quiknode.pro/key-zq7",
                    AuthConfig::Path {
                        placeholder: "{api_key}".to_string(),
                        token: token("token-zq7"),
                    },
                ),
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
                provider(
                    "https://lb.drpc.org/ogrpc?network=zq7",
                    AuthConfig::Query {
                        name: "dkey".to_string(),
                        token: token("token-zq7"),
                    },
                ),
            ),
            (
                "unparseable",
                provider("https://zq7 key/", AuthConfig::None),
            ),
        ]);
        let drpc = whitelisted(
            "https://lb.drpc.org/ogrpc",
            ChainRouting::QueryParam {
                name: "network".to_string(),
                value: "ethereum".to_string(),
            },
            AuthScheme::Query {
                name: "apikey".to_string(),
            },
        );
        let whitelist = must_ethereum_whitelist(&[
            ("alchemy", alchemy()),
            ("drpc", drpc),
            ("quicknode", quicknode()),
        ]);
        (local, whitelist)
    }

    #[test]
    fn compare__should_keep_configured_urls_and_tokens_out_of_diagnostics() {
        // Given
        let (local, whitelist) = must_config_with_secrets_in_warnings();

        // When
        let diags = compare(&local, &whitelist);

        // Then
        let printed = format!("{diags:?}");
        assert!(diags.len() >= 6, "{printed}");
        assert!(!printed.contains(SECRET_MARKER), "{printed}");
    }

    #[tokio::test]
    #[traced_test]
    async fn run__should_keep_configured_urls_and_tokens_out_of_logs() {
        // Given
        let (local, whitelist) = must_config_with_secrets_in_warnings();
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
        assert!(logs_contain("rpc_url does not parse"));
        assert!(!logs_contain(SECRET_MARKER));
    }
}
