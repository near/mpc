//! Log-only check that the node's local foreign-chain RPC config matches the
//! on-chain whitelist (`allowed_foreign_chain_providers`).
//!
//! On a fresh deployment with an unvoted whitelist, the first tick emits one
//! `ChainNotInWhitelist` info per configured chain — expected during rollout,
//! clears once the whitelist is populated.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use mpc_node_config::{
    foreign_chains::RpcProviderName, AuthConfig, ForeignChainConfig, ForeignChainProviderConfig,
    ForeignChainsConfig,
};
use near_mpc_contract_interface::types::{
    self as dtos, AuthScheme, ChainEntry, ChainRouting, ProviderConfig, ProviderId,
};

use crate::indexer::IndexerState;

const VERIFY_INTERVAL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Diagnostic {
    chain: dtos::ForeignChain,
    provider: Option<RpcProviderName>,
    kind: DiagnosticKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DiagnosticKind {
    ChainNotInWhitelist,
    ProviderNotInWhitelist,
    BaseUrlMismatch {
        local_rpc_url: String,
        contract_base_url: String,
    },
    ChainRoutingMismatch {
        local_rpc_url: String,
        contract_chain_routing: ChainRouting,
    },
    AuthSchemeVariantMismatch {
        local: &'static str,
        contract: &'static str,
    },
    AuthSchemeNameMismatch {
        variant: &'static str,
        local_name: String,
        contract_name: String,
    },
    /// Header auth: the contract mandates a specific scheme tag (e.g. `Bearer`)
    /// that doesn't match local. We can't compare token values, but we can compare
    /// the scheme tag itself.
    AuthSchemeHeaderSchemeMismatch {
        local: Option<String>,
        contract: Option<String>,
    },
    /// The contract whitelist contains a variant this node binary doesn't
    /// recognize — operator should upgrade.
    UnknownContractVariant {
        what: &'static str,
        value: String,
    },
}

/// Advisory diagnostics (logged at info rather than warn). Only `ChainNotInWhitelist`
/// qualifies — it's the bootstrap case where a chain isn't yet voted in.
fn is_informational(kind: &DiagnosticKind) -> bool {
    matches!(kind, DiagnosticKind::ChainNotInWhitelist)
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
    whitelist: &ChainEntry,
    out: &mut Vec<Diagnostic>,
) {
    for (local_name, local_provider) in local.providers.iter() {
        let contract_id = ProviderId(local_name.as_str().to_string());
        let Some(contract_provider) = whitelist.providers.get(&contract_id) else {
            out.push(Diagnostic {
                chain,
                provider: Some(local_name.clone()),
                kind: DiagnosticKind::ProviderNotInWhitelist,
            });
            continue;
        };
        compare_provider(chain, local_name, local_provider, contract_provider, out);
    }
}

fn compare_provider(
    chain: dtos::ForeignChain,
    name: &RpcProviderName,
    local: &ForeignChainProviderConfig,
    contract: &ProviderConfig,
    out: &mut Vec<Diagnostic>,
) {
    let local_url = local.rpc_url.as_str();
    if !base_url_matches(local_url, &contract.base_url) {
        out.push(Diagnostic {
            chain,
            provider: Some(name.clone()),
            kind: DiagnosticKind::BaseUrlMismatch {
                local_rpc_url: local_url.to_string(),
                contract_base_url: contract.base_url.clone(),
            },
        });
    }

    match chain_routing_satisfied(local_url, &contract.chain_routing) {
        RoutingCheck::Ok => {}
        RoutingCheck::Mismatch => {
            out.push(Diagnostic {
                chain,
                provider: Some(name.clone()),
                kind: DiagnosticKind::ChainRoutingMismatch {
                    local_rpc_url: local_url.to_string(),
                    contract_chain_routing: contract.chain_routing.clone(),
                },
            });
        }
        RoutingCheck::Unknown => {
            out.push(Diagnostic {
                chain,
                provider: Some(name.clone()),
                kind: DiagnosticKind::UnknownContractVariant {
                    what: "chain_routing",
                    value: format!("{:?}", contract.chain_routing),
                },
            });
        }
    }

    compare_auth(chain, name, &local.auth, &contract.auth_scheme, out);
}

/// Path-boundary-aware prefix check. `https://api.example.com/v2` matches `/v2`,
/// `/v2/eth`, `/v2?key=x`, `/v2#frag` — but not `/v2-evil`.
fn base_url_matches(local: &str, base: &str) -> bool {
    let l = local.trim_end_matches('/');
    let b = base.trim_end_matches('/');
    if l == b {
        return true;
    }
    let Some(rest) = l.strip_prefix(b) else {
        return false;
    };
    rest.starts_with('/') || rest.starts_with('?') || rest.starts_with('#')
}

enum RoutingCheck {
    Ok,
    Mismatch,
    Unknown,
}

/// Substring-based (not a strict parse): `?xnetwork=ethereum` will satisfy
/// `QueryParam { name: "network", value: "ethereum" }`. Acceptable for advisory
/// diagnostics; tighten with `url::parse` if this ever drives enforcement.
fn chain_routing_satisfied(local_url: &str, routing: &ChainRouting) -> RoutingCheck {
    match routing {
        ChainRouting::Embedded => RoutingCheck::Ok,
        ChainRouting::PathSegment { segment } => {
            if local_url.contains(&format!("/{segment}")) {
                RoutingCheck::Ok
            } else {
                RoutingCheck::Mismatch
            }
        }
        ChainRouting::QueryParam { name, value } => {
            if local_url.contains(&format!("{name}={value}")) {
                RoutingCheck::Ok
            } else {
                RoutingCheck::Mismatch
            }
        }
        _ => RoutingCheck::Unknown,
    }
}

fn auth_scheme_variant_name(scheme: &AuthScheme) -> &'static str {
    match scheme {
        AuthScheme::None => "None",
        AuthScheme::Header { .. } => "Header",
        AuthScheme::Path { .. } => "Path",
        AuthScheme::Query { .. } => "Query",
        _ => "Unknown",
    }
}

fn auth_config_variant_name(auth: &AuthConfig) -> &'static str {
    match auth {
        AuthConfig::None => "None",
        AuthConfig::Header { .. } => "Header",
        AuthConfig::Path { .. } => "Path",
        AuthConfig::Query { .. } => "Query",
    }
}

fn compare_auth(
    chain: dtos::ForeignChain,
    name: &RpcProviderName,
    local: &AuthConfig,
    contract: &AuthScheme,
    out: &mut Vec<Diagnostic>,
) {
    match (local, contract) {
        (AuthConfig::None, AuthScheme::None) => {}
        (
            AuthConfig::Path {
                placeholder: local_p,
                ..
            },
            AuthScheme::Path {
                placeholder: contract_p,
            },
        ) => {
            if local_p != contract_p {
                out.push(Diagnostic {
                    chain,
                    provider: Some(name.clone()),
                    kind: DiagnosticKind::AuthSchemeNameMismatch {
                        variant: "Path",
                        local_name: local_p.clone(),
                        contract_name: contract_p.clone(),
                    },
                });
            }
        }
        (
            AuthConfig::Header {
                name: local_h,
                scheme: local_scheme,
                ..
            },
            AuthScheme::Header {
                name: contract_h,
                scheme: contract_scheme,
            },
        ) => {
            if local_h.as_str() != contract_h {
                out.push(Diagnostic {
                    chain,
                    provider: Some(name.clone()),
                    kind: DiagnosticKind::AuthSchemeNameMismatch {
                        variant: "Header",
                        local_name: local_h.as_str().to_string(),
                        contract_name: contract_h.clone(),
                    },
                });
            }
            if local_scheme != contract_scheme {
                out.push(Diagnostic {
                    chain,
                    provider: Some(name.clone()),
                    kind: DiagnosticKind::AuthSchemeHeaderSchemeMismatch {
                        local: local_scheme.clone(),
                        contract: contract_scheme.clone(),
                    },
                });
            }
        }
        (AuthConfig::Query { name: local_q, .. }, AuthScheme::Query { name: contract_q }) => {
            if local_q != contract_q {
                out.push(Diagnostic {
                    chain,
                    provider: Some(name.clone()),
                    kind: DiagnosticKind::AuthSchemeNameMismatch {
                        variant: "Query",
                        local_name: local_q.clone(),
                        contract_name: contract_q.clone(),
                    },
                });
            }
        }
        (local, contract) => {
            out.push(Diagnostic {
                chain,
                provider: Some(name.clone()),
                kind: DiagnosticKind::AuthSchemeVariantMismatch {
                    local: auth_config_variant_name(local),
                    contract: auth_scheme_variant_name(contract),
                },
            });
        }
    }
}

fn log_diagnostic(d: &Diagnostic) {
    let chain = d.chain;
    let provider = d.provider.as_ref().map(|p| p.as_str());
    match &d.kind {
        DiagnosticKind::UnknownContractVariant { .. } => {
            tracing::error!(?chain, provider, kind = ?d.kind, "foreign-chain whitelist contains a variant this node binary doesn't recognize; upgrade the node");
        }
        kind if is_informational(kind) => {
            tracing::info!(?chain, provider, kind = ?d.kind, "foreign-chain whitelist verifier");
        }
        _ => {
            tracing::warn!(?chain, provider, kind = ?d.kind, "foreign-chain whitelist mismatch");
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum DedupOutcome {
    /// Same diagnostics as the previous tick — quiet (debug).
    Unchanged,
    /// Diagnostics set is empty (first tick or transition from non-empty).
    Matching,
    /// Diagnostics changed since previous tick.
    Changed(Vec<Diagnostic>),
}

/// Per-tick dedup state. Extracted from `run` so it can be unit-tested.
struct Dedup {
    previous: Option<Vec<Diagnostic>>,
}

impl Dedup {
    fn new() -> Self {
        Self { previous: None }
    }

    fn observe(&mut self, current: Vec<Diagnostic>) -> DedupOutcome {
        let action = if self.previous.as_ref() == Some(&current) {
            DedupOutcome::Unchanged
        } else if current.is_empty() {
            DedupOutcome::Matching
        } else {
            DedupOutcome::Changed(current.clone())
        };
        self.previous = Some(current);
        action
    }
}

pub(crate) async fn run(indexer_state: Arc<IndexerState>, local: ForeignChainsConfig) {
    let mut ticker = tokio::time::interval(VERIFY_INTERVAL);
    let mut dedup = Dedup::new();
    loop {
        ticker.tick().await;
        let whitelist = match indexer_state
            .view_client()
            .get_allowed_foreign_chain_providers(indexer_state.mpc_contract_id().clone())
            .await
        {
            Ok(w) => w,
            Err(e) => {
                tracing::warn!(error = ?e, "could not query allowed_foreign_chain_providers; skipping this verification round");
                continue;
            }
        };
        match dedup.observe(compare(&local, &whitelist)) {
            DedupOutcome::Unchanged => {
                tracing::debug!("foreign-chain whitelist verifier: no change since last tick");
            }
            DedupOutcome::Matching => {
                tracing::info!(
                    "foreign-chain whitelist verifier: local config matches contract whitelist"
                );
            }
            DedupOutcome::Changed(diagnostics) => {
                for d in &diagnostics {
                    log_diagnostic(d);
                }
            }
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use mpc_node_config::TokenConfig;
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use std::collections::BTreeMap;

    fn local_provider(rpc_url: &str, auth: AuthConfig) -> ForeignChainProviderConfig {
        ForeignChainProviderConfig {
            rpc_url: rpc_url.to_string(),
            auth,
        }
    }

    fn local_chain(providers: &[(&str, ForeignChainProviderConfig)]) -> ForeignChainConfig {
        let map: BTreeMap<RpcProviderName, ForeignChainProviderConfig> = providers
            .iter()
            .map(|(name, cfg)| (RpcProviderName::from(name.to_string()), cfg.clone()))
            .collect();
        ForeignChainConfig {
            timeout_sec: std::num::NonZeroU64::new(30).unwrap(),
            max_retries: std::num::NonZeroU64::new(3).unwrap(),
            providers: NonEmptyBTreeMap::try_from(map)
                .expect("test setup: providers must be non-empty"),
        }
    }

    fn contract_provider(
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

    fn contract_chain_entry(providers: &[(&str, ProviderConfig)], quorum: u64) -> ChainEntry {
        let map: BTreeMap<ProviderId, ProviderConfig> = providers
            .iter()
            .map(|(id, cfg)| (ProviderId(id.to_string()), cfg.clone()))
            .collect();
        ChainEntry {
            providers: NonEmptyBTreeMap::try_from(map)
                .expect("test setup: providers must be non-empty"),
            quorum,
        }
    }

    #[test]
    fn compare__should_be_empty_when_local_and_whitelist_match() {
        // Given
        let local = ForeignChainsConfig {
            ethereum: Some(local_chain(&[(
                "alchemy",
                local_provider(
                    "https://eth-mainnet.g.alchemy.com/v2/test",
                    AuthConfig::None,
                ),
            )])),
            ..Default::default()
        };
        let whitelist: BTreeMap<dtos::ForeignChain, ChainEntry> = [(
            dtos::ForeignChain::Ethereum,
            contract_chain_entry(
                &[(
                    "alchemy",
                    contract_provider(
                        "https://eth-mainnet.g.alchemy.com/v2/",
                        ChainRouting::Embedded,
                        AuthScheme::None,
                    ),
                )],
                1,
            ),
        )]
        .into_iter()
        .collect();

        // When
        let diags = compare(&local, &whitelist);

        // Then
        assert!(diags.is_empty(), "expected no diagnostics, got: {diags:?}");
    }

    #[test]
    fn compare__should_emit_chain_not_in_whitelist_when_chain_missing_from_contract() {
        // Given: local configures Ethereum, contract has no whitelist entry yet.
        let local = ForeignChainsConfig {
            ethereum: Some(local_chain(&[(
                "alchemy",
                local_provider("https://eth-mainnet.example.com", AuthConfig::None),
            )])),
            ..Default::default()
        };
        let whitelist = BTreeMap::new();

        // When
        let diags = compare(&local, &whitelist);

        // Then
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].chain, dtos::ForeignChain::Ethereum);
        assert_eq!(diags[0].kind, DiagnosticKind::ChainNotInWhitelist);
    }

    #[test]
    fn compare__should_emit_provider_not_in_whitelist_when_local_has_extra_provider() {
        // Given: contract has alchemy, local has alchemy + ankr.
        let local = ForeignChainsConfig {
            ethereum: Some(local_chain(&[
                (
                    "alchemy",
                    local_provider("https://eth.alchemy.com/v2/x", AuthConfig::None),
                ),
                (
                    "ankr",
                    local_provider("https://rpc.ankr.com/eth", AuthConfig::None),
                ),
            ])),
            ..Default::default()
        };
        let whitelist: BTreeMap<dtos::ForeignChain, ChainEntry> = [(
            dtos::ForeignChain::Ethereum,
            contract_chain_entry(
                &[(
                    "alchemy",
                    contract_provider(
                        "https://eth.alchemy.com/v2/",
                        ChainRouting::Embedded,
                        AuthScheme::None,
                    ),
                )],
                1,
            ),
        )]
        .into_iter()
        .collect();

        // When
        let diags = compare(&local, &whitelist);

        // Then
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].kind, DiagnosticKind::ProviderNotInWhitelist,);
        assert_eq!(
            diags[0].provider,
            Some(RpcProviderName::from("ankr".to_string()))
        );
    }

    #[test]
    fn compare__should_emit_base_url_mismatch_when_local_rpc_url_has_wrong_prefix() {
        // Given: contract says base_url is alchemy.com, local points at infura.io.
        let local = ForeignChainsConfig {
            ethereum: Some(local_chain(&[(
                "alchemy",
                local_provider("https://eth.infura.io/v3/key", AuthConfig::None),
            )])),
            ..Default::default()
        };
        let whitelist: BTreeMap<dtos::ForeignChain, ChainEntry> = [(
            dtos::ForeignChain::Ethereum,
            contract_chain_entry(
                &[(
                    "alchemy",
                    contract_provider(
                        "https://eth-mainnet.g.alchemy.com/v2/",
                        ChainRouting::Embedded,
                        AuthScheme::None,
                    ),
                )],
                1,
            ),
        )]
        .into_iter()
        .collect();

        // When
        let diags = compare(&local, &whitelist);

        // Then
        assert_eq!(diags.len(), 1);
        assert_matches!(diags[0].kind, DiagnosticKind::BaseUrlMismatch { .. });
    }

    #[test]
    fn compare__should_emit_chain_routing_mismatch_when_path_segment_missing() {
        // Given: contract says PathSegment "eth", local rpc_url doesn't contain it.
        let local = ForeignChainsConfig {
            ethereum: Some(local_chain(&[(
                "ankr",
                local_provider("https://rpc.ankr.com/something_else", AuthConfig::None),
            )])),
            ..Default::default()
        };
        let whitelist: BTreeMap<dtos::ForeignChain, ChainEntry> = [(
            dtos::ForeignChain::Ethereum,
            contract_chain_entry(
                &[(
                    "ankr",
                    contract_provider(
                        "https://rpc.ankr.com",
                        ChainRouting::PathSegment {
                            segment: "eth".to_string(),
                        },
                        AuthScheme::None,
                    ),
                )],
                1,
            ),
        )]
        .into_iter()
        .collect();

        // When
        let diags = compare(&local, &whitelist);

        // Then
        assert_eq!(diags.len(), 1);
        assert_matches!(diags[0].kind, DiagnosticKind::ChainRoutingMismatch { .. });
    }

    #[test]
    fn compare__should_emit_chain_routing_mismatch_when_query_param_missing() {
        // Given: contract says QueryParam{name: "network", value: "ethereum"}, local rpc_url
        // doesn't carry it.
        let local = ForeignChainsConfig {
            ethereum: Some(local_chain(&[(
                "drpc",
                local_provider("https://lb.drpc.org/ogrpc?dkey=K", AuthConfig::None),
            )])),
            ..Default::default()
        };
        let whitelist: BTreeMap<dtos::ForeignChain, ChainEntry> = [(
            dtos::ForeignChain::Ethereum,
            contract_chain_entry(
                &[(
                    "drpc",
                    contract_provider(
                        "https://lb.drpc.org/ogrpc",
                        ChainRouting::QueryParam {
                            name: "network".to_string(),
                            value: "ethereum".to_string(),
                        },
                        AuthScheme::None,
                    ),
                )],
                1,
            ),
        )]
        .into_iter()
        .collect();

        // When
        let diags = compare(&local, &whitelist);

        // Then
        assert_eq!(diags.len(), 1);
        assert_matches!(diags[0].kind, DiagnosticKind::ChainRoutingMismatch { .. });
    }

    #[test]
    fn compare__should_emit_auth_variant_mismatch_when_local_uses_none_and_contract_uses_header() {
        // Given
        let local = ForeignChainsConfig {
            ethereum: Some(local_chain(&[(
                "alchemy",
                local_provider("https://eth.alchemy.com/v2/k", AuthConfig::None),
            )])),
            ..Default::default()
        };
        let whitelist: BTreeMap<dtos::ForeignChain, ChainEntry> = [(
            dtos::ForeignChain::Ethereum,
            contract_chain_entry(
                &[(
                    "alchemy",
                    contract_provider(
                        "https://eth.alchemy.com/v2/",
                        ChainRouting::Embedded,
                        AuthScheme::Header {
                            name: "x-api-key".to_string(),
                            scheme: None,
                        },
                    ),
                )],
                1,
            ),
        )]
        .into_iter()
        .collect();

        // When
        let diags = compare(&local, &whitelist);

        // Then
        assert_eq!(diags.len(), 1);
        assert_matches!(
            diags[0].kind,
            DiagnosticKind::AuthSchemeVariantMismatch {
                local: "None",
                contract: "Header",
            }
        );
    }

    #[test]
    fn compare__should_emit_auth_name_mismatch_when_query_param_names_differ() {
        // Given
        let local = ForeignChainsConfig {
            ethereum: Some(local_chain(&[(
                "drpc",
                local_provider(
                    "https://lb.drpc.org/?dkey=foo",
                    AuthConfig::Query {
                        name: "dkey".to_string(),
                        token: TokenConfig::Val {
                            val: "foo".to_string(),
                        },
                    },
                ),
            )])),
            ..Default::default()
        };
        let whitelist: BTreeMap<dtos::ForeignChain, ChainEntry> = [(
            dtos::ForeignChain::Ethereum,
            contract_chain_entry(
                &[(
                    "drpc",
                    contract_provider(
                        "https://lb.drpc.org/",
                        ChainRouting::Embedded,
                        AuthScheme::Query {
                            name: "apikey".to_string(),
                        },
                    ),
                )],
                1,
            ),
        )]
        .into_iter()
        .collect();

        // When
        let diags = compare(&local, &whitelist);

        // Then
        assert_eq!(diags.len(), 1);
        assert_matches!(
            diags[0].kind,
            DiagnosticKind::AuthSchemeNameMismatch {
                variant: "Query",
                ..
            }
        );
    }

    /// Build a single-ethereum-chain `ForeignChainsConfig` with one alchemy
    /// provider whose `auth` is a Header with the given (name, scheme).
    fn local_header_eth(header_name: &str, scheme: Option<&str>) -> ForeignChainsConfig {
        ForeignChainsConfig {
            ethereum: Some(local_chain(&[(
                "alchemy",
                local_provider(
                    "https://eth.alchemy.com/v2/",
                    AuthConfig::Header {
                        name: header_name.parse().unwrap(),
                        scheme: scheme.map(str::to_string),
                        token: TokenConfig::Val {
                            val: "abc".to_string(),
                        },
                    },
                ),
            )])),
            ..Default::default()
        }
    }

    /// Build a matching contract whitelist entry with one alchemy provider whose
    /// `auth_scheme` is a Header with the given (name, scheme).
    fn contract_header_eth(
        header_name: &str,
        scheme: Option<&str>,
    ) -> BTreeMap<dtos::ForeignChain, ChainEntry> {
        [(
            dtos::ForeignChain::Ethereum,
            contract_chain_entry(
                &[(
                    "alchemy",
                    contract_provider(
                        "https://eth.alchemy.com/v2/",
                        ChainRouting::Embedded,
                        AuthScheme::Header {
                            name: header_name.to_string(),
                            scheme: scheme.map(str::to_string),
                        },
                    ),
                )],
                1,
            ),
        )]
        .into_iter()
        .collect()
    }

    #[test]
    fn compare__should_emit_header_scheme_mismatch_when_schemes_differ() {
        // Given: same Header name, different scheme tag.
        let local = local_header_eth("authorization", Some("Bearer"));
        let whitelist = contract_header_eth("authorization", Some("Basic"));

        // When
        let diags = compare(&local, &whitelist);

        // Then
        assert_eq!(diags.len(), 1);
        assert_matches!(
            &diags[0].kind,
            DiagnosticKind::AuthSchemeHeaderSchemeMismatch { local, contract }
                if local.as_deref() == Some("Bearer") && contract.as_deref() == Some("Basic")
        );
    }

    #[test]
    fn compare__should_emit_header_scheme_mismatch_when_one_side_is_none() {
        // Given: local omits the scheme tag, contract requires one.
        let local = local_header_eth("authorization", None);
        let whitelist = contract_header_eth("authorization", Some("Bearer"));

        // When
        let diags = compare(&local, &whitelist);

        // Then
        assert_eq!(diags.len(), 1);
        assert_matches!(
            &diags[0].kind,
            DiagnosticKind::AuthSchemeHeaderSchemeMismatch { local, contract }
                if local.is_none() && contract.as_deref() == Some("Bearer")
        );
    }

    #[test]
    fn compare__should_emit_both_header_name_and_scheme_mismatch_when_both_differ() {
        // Given: header name AND scheme both differ.
        let local = local_header_eth("authorization", Some("Bearer"));
        let whitelist = contract_header_eth("x-api-key", Some("Basic"));

        // When
        let diags = compare(&local, &whitelist);

        // Then: two independent diagnostics for the same provider.
        assert_eq!(diags.len(), 2);
        assert!(diags.iter().any(|d| matches!(
            &d.kind,
            DiagnosticKind::AuthSchemeNameMismatch {
                variant: "Header",
                ..
            }
        )));
        assert!(diags.iter().any(|d| matches!(
            &d.kind,
            DiagnosticKind::AuthSchemeHeaderSchemeMismatch { .. }
        )));
    }

    #[test]
    fn compare__should_accept_matching_header_name_and_scheme() {
        // Given: header name AND scheme both match.
        let local = local_header_eth("authorization", Some("Bearer"));
        let whitelist = contract_header_eth("authorization", Some("Bearer"));

        // When
        let diags = compare(&local, &whitelist);

        // Then
        assert!(diags.is_empty(), "expected no diagnostics, got: {diags:?}");
    }

    #[test]
    fn compare__should_emit_path_placeholder_mismatch_when_placeholders_differ() {
        // Given: local Path placeholder is "{KEY}", contract Path placeholder is "{TOKEN}".
        let local = ForeignChainsConfig {
            ethereum: Some(local_chain(&[(
                "alchemy",
                local_provider(
                    "https://api.example.com/v2/{KEY}",
                    AuthConfig::Path {
                        placeholder: "{KEY}".to_string(),
                        token: TokenConfig::Val {
                            val: "abc".to_string(),
                        },
                    },
                ),
            )])),
            ..Default::default()
        };
        let whitelist: BTreeMap<dtos::ForeignChain, ChainEntry> = [(
            dtos::ForeignChain::Ethereum,
            contract_chain_entry(
                &[(
                    "alchemy",
                    contract_provider(
                        "https://api.example.com/v2/",
                        ChainRouting::Embedded,
                        AuthScheme::Path {
                            placeholder: "{TOKEN}".to_string(),
                        },
                    ),
                )],
                1,
            ),
        )]
        .into_iter()
        .collect();

        // When
        let diags = compare(&local, &whitelist);

        // Then
        assert_eq!(diags.len(), 1);
        assert_matches!(
            diags[0].kind,
            DiagnosticKind::AuthSchemeNameMismatch {
                variant: "Path",
                ..
            }
        );
    }

    #[test]
    fn compare__should_accept_matching_path_placeholders() {
        // Given: both local and contract use the placeholder "{KEY}".
        let local = ForeignChainsConfig {
            ethereum: Some(local_chain(&[(
                "alchemy",
                local_provider(
                    "https://api.example.com/v2/{KEY}",
                    AuthConfig::Path {
                        placeholder: "{KEY}".to_string(),
                        token: TokenConfig::Val {
                            val: "abc".to_string(),
                        },
                    },
                ),
            )])),
            ..Default::default()
        };
        let whitelist: BTreeMap<dtos::ForeignChain, ChainEntry> = [(
            dtos::ForeignChain::Ethereum,
            contract_chain_entry(
                &[(
                    "alchemy",
                    contract_provider(
                        "https://api.example.com/v2/",
                        ChainRouting::Embedded,
                        AuthScheme::Path {
                            placeholder: "{KEY}".to_string(),
                        },
                    ),
                )],
                1,
            ),
        )]
        .into_iter()
        .collect();

        // When
        let diags = compare(&local, &whitelist);

        // Then
        assert!(diags.is_empty(), "expected no diagnostics, got: {diags:?}");
    }

    #[test]
    fn compare__should_be_silent_when_whitelist_has_chain_not_configured_locally() {
        // Given: local has no chains; whitelist has Ethereum with one provider.
        // The verifier doesn't warn when the whitelist is a superset — operators
        // intentionally run on subsets.
        let local = ForeignChainsConfig::default();
        let whitelist: BTreeMap<dtos::ForeignChain, ChainEntry> = [(
            dtos::ForeignChain::Ethereum,
            contract_chain_entry(
                &[(
                    "alchemy",
                    contract_provider(
                        "https://eth.alchemy.com/v2/",
                        ChainRouting::Embedded,
                        AuthScheme::None,
                    ),
                )],
                1,
            ),
        )]
        .into_iter()
        .collect();

        // When
        let diags = compare(&local, &whitelist);

        // Then
        assert!(diags.is_empty(), "expected no diagnostics, got: {diags:?}");
    }

    #[test]
    fn base_url_matches__should_accept_exact_match_and_segment_aligned_prefix() {
        assert!(base_url_matches(
            "https://api.example.com/v2",
            "https://api.example.com/v2"
        ));
        assert!(base_url_matches(
            "https://api.example.com/v2/eth",
            "https://api.example.com/v2"
        ));
        assert!(base_url_matches(
            "https://api.example.com/v2/",
            "https://api.example.com/v2"
        ));
        // Query string / fragment immediately after the base count as boundaries.
        assert!(base_url_matches(
            "https://api.example.com/v2?key=foo",
            "https://api.example.com/v2"
        ));
        assert!(base_url_matches(
            "https://api.example.com/v2#frag",
            "https://api.example.com/v2"
        ));
    }

    #[test]
    fn base_url_matches__should_reject_path_boundary_violations() {
        // The case the reviewer flagged: a path that *starts with* the base
        // but isn't segment-aligned must be rejected.
        assert!(!base_url_matches(
            "https://api.example.com/v2-evil/x",
            "https://api.example.com/v2"
        ));
        assert!(!base_url_matches(
            "https://api.example.com/v2foo",
            "https://api.example.com/v2"
        ));
        assert!(!base_url_matches(
            "https://eth.alchemy.com/v2foo.attacker.example/",
            "https://eth.alchemy.com/v2"
        ));
    }

    fn fake_diag() -> Diagnostic {
        Diagnostic {
            chain: dtos::ForeignChain::Ethereum,
            provider: None,
            kind: DiagnosticKind::ChainNotInWhitelist,
        }
    }

    fn fake_diag_provider_missing() -> Diagnostic {
        Diagnostic {
            chain: dtos::ForeignChain::Ethereum,
            provider: Some(RpcProviderName::from("alchemy".to_string())),
            kind: DiagnosticKind::ProviderNotInWhitelist,
        }
    }

    #[test]
    fn dedup_observe__should_return_matching_when_first_tick_is_empty() {
        // Given
        let mut d = Dedup::new();

        // When / Then
        assert_eq!(d.observe(vec![]), DedupOutcome::Matching);
    }

    #[test]
    fn dedup_observe__should_return_changed_when_first_tick_has_diagnostics() {
        // Given
        let mut d = Dedup::new();
        let diags = vec![fake_diag()];

        // When
        let action = d.observe(diags.clone());

        // Then
        assert_eq!(action, DedupOutcome::Changed(diags));
    }

    #[test]
    fn dedup_observe__should_return_unchanged_when_two_consecutive_ticks_match() {
        // Given
        let mut d = Dedup::new();
        let diags = vec![fake_diag()];
        d.observe(diags.clone());

        // When / Then
        assert_eq!(d.observe(diags), DedupOutcome::Unchanged);
    }

    #[test]
    fn dedup_observe__should_return_changed_when_diagnostics_change() {
        // Given
        let mut d = Dedup::new();
        d.observe(vec![fake_diag()]);
        let new_diags = vec![fake_diag(), fake_diag_provider_missing()];

        // When
        let action = d.observe(new_diags.clone());

        // Then
        assert_eq!(action, DedupOutcome::Changed(new_diags));
    }

    #[test]
    fn dedup_observe__should_return_matching_when_diagnostics_transition_to_empty() {
        // Given
        let mut d = Dedup::new();
        d.observe(vec![fake_diag()]);

        // When / Then
        assert_eq!(d.observe(vec![]), DedupOutcome::Matching);
    }

    #[test]
    fn dedup_observe__should_return_changed_when_empty_transitions_to_diagnostics() {
        // Given
        let mut d = Dedup::new();
        d.observe(vec![]);
        let diags = vec![fake_diag()];

        // When
        let action = d.observe(diags.clone());

        // Then
        assert_eq!(action, DedupOutcome::Changed(diags));
    }
}
