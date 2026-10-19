//! Resolves the on-chain RPC whitelist (`allowed_foreign_chain_providers`) against the node's
//! local foreign-chain config into the per-chain [`RpcQuorum`] verification enforces.
//!
//! On a fresh deployment with an unvoted whitelist, every configured chain reports
//! [`ChainNotInWhitelist`](DiagnosticKind::ChainNotInWhitelist) at info and no chain is eligible.
//! That clears once the whitelist is populated and the watch channel updates.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;

use foreign_chain_inspector::RpcQuorum;
use mpc_node_config::{
    AuthConfig, ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig,
    foreign_chains::RpcProviderName,
};
use near_mpc_contract_interface::types::{
    self as dtos, AuthScheme, ChainEntry, ChainRouting, ProviderConfig, ProviderId,
};
use tokio::sync::watch;

use crate::indexer::foreign_chain::ForeignChainRpcWhitelist;
use crate::metrics;
use crate::tracking::{self, AutoAbortTask};

/// The chains this node may verify, each with the quorum its whitelisted providers must reach.
pub(crate) type RpcQuorumsByChain = BTreeMap<dtos::ForeignChain, RpcQuorum>;

/// Resolves the whitelist against `local` now and again on every change, logging the
/// diagnostics of each resolution. Must be called from a tracked task; dropping the returned
/// [`AutoAbortTask`] stops the resolver.
pub(crate) fn spawn_rpc_quorums_resolver(
    mut whitelist_rx: watch::Receiver<ForeignChainRpcWhitelist>,
    local: ForeignChainsConfig,
) -> (watch::Receiver<RpcQuorumsByChain>, AutoAbortTask<()>) {
    let initial = resolve_and_report(&local, &whitelist_rx.borrow_and_update());
    let (sender, receiver) = watch::channel(initial);

    let task = tracking::spawn("foreign-chain RPC quorums resolver", async move {
        loop {
            tokio::select! {
                changed = whitelist_rx.changed() => {
                    if changed.is_err() {
                        tracing::info!("whitelist sender dropped, stopping foreign-chain RPC quorums resolver");
                        break;
                    }
                }
                _ = sender.closed() => {
                    tracing::debug!("all receivers dropped, stopping foreign-chain RPC quorums resolver");
                    break;
                }
            }
            let quorums = resolve_and_report(&local, &whitelist_rx.borrow_and_update());
            sender.send_if_modified(|existing| {
                if *existing != quorums {
                    *existing = quorums;
                    true
                } else {
                    false
                }
            });
        }
    });
    (receiver, task)
}

fn resolve_and_report(
    local: &ForeignChainsConfig,
    whitelist: &ForeignChainRpcWhitelist,
) -> RpcQuorumsByChain {
    let resolution = resolve_rpc_quorums(local, whitelist);
    if resolution.diagnostics.is_empty() {
        tracing::info!("foreign-chain RPC policy: local config matches contract whitelist");
    }
    for diagnostic in &resolution.diagnostics {
        log_diagnostic(diagnostic);
    }
    let eligible = resolution.eligible();
    for (chain, quorum) in &eligible {
        tracing::info!(
            ?chain,
            required = quorum.required,
            whitelisted = ?quorum.whitelisted,
            "foreign chain is eligible for verification"
        );
    }
    publish_metrics(local, &resolution.quorums);
    eligible
}

/// Gauges cover every locally configured chain, so a chain that drops out of the whitelist
/// reads as zero instead of keeping its last value.
fn publish_metrics(local: &ForeignChainsConfig, quorums: &BTreeMap<dtos::ForeignChain, RpcQuorum>) {
    for (chain, _) in local.iter_chains() {
        let (required, whitelisted) = quorums.get(&chain).map_or((0, 0), |quorum| {
            (quorum.required.get(), quorum.whitelisted.len())
        });
        metrics::FOREIGN_CHAIN_RPC_QUORUM_REQUIRED
            .with_label_values(&[chain.label()])
            .set(i64::try_from(required).unwrap_or(i64::MAX));
        metrics::FOREIGN_CHAIN_RPC_PROVIDERS_WHITELISTED
            .with_label_values(&[chain.label()])
            .set(i64::try_from(whitelisted).unwrap_or(i64::MAX));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Resolution {
    /// Every locally configured chain the whitelist covers, reachable quorum or not.
    quorums: BTreeMap<dtos::ForeignChain, RpcQuorum>,
    diagnostics: Vec<Diagnostic>,
}

impl Resolution {
    fn eligible(&self) -> RpcQuorumsByChain {
        self.quorums
            .iter()
            .filter(|(_, quorum)| quorum.is_reachable())
            .map(|(chain, quorum)| (*chain, quorum.clone()))
            .collect()
    }
}

fn resolve_rpc_quorums(
    local: &ForeignChainsConfig,
    whitelist: &ForeignChainRpcWhitelist,
) -> Resolution {
    let mut quorums = BTreeMap::new();
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
        let Some(required) = usize::try_from(whitelist_entry.quorum)
            .ok()
            .and_then(NonZeroUsize::new)
        else {
            diagnostics.push(Diagnostic {
                chain,
                provider: None,
                kind: DiagnosticKind::UnusableQuorum {
                    quorum: whitelist_entry.quorum,
                },
            });
            continue;
        };
        let whitelisted =
            whitelisted_providers(chain, local_cfg, whitelist_entry, &mut diagnostics);
        let quorum = RpcQuorum {
            required,
            whitelisted,
        };
        if !quorum.is_reachable() {
            diagnostics.push(Diagnostic {
                chain,
                provider: None,
                kind: DiagnosticKind::BelowQuorum {
                    whitelisted: quorum.whitelisted.len(),
                    required,
                },
            });
        }
        quorums.insert(chain, quorum);
    }

    Resolution {
        quorums,
        diagnostics,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Diagnostic {
    chain: dtos::ForeignChain,
    provider: Option<RpcProviderName>,
    kind: DiagnosticKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DiagnosticKind {
    ChainNotInWhitelist,
    /// The contract never stores a zero quorum, nor one beyond this target's address space.
    UnusableQuorum {
        quorum: u64,
    },
    /// Fewer local providers match the whitelist than the voted quorum needs.
    BelowQuorum {
        whitelisted: usize,
        required: NonZeroUsize,
    },
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

/// Advisory diagnostics (logged at info rather than warn). Only [`ChainNotInWhitelist`](DiagnosticKind::ChainNotInWhitelist)
/// qualifies — it's the bootstrap case where a chain isn't yet voted in.
fn is_informational(kind: &DiagnosticKind) -> bool {
    matches!(kind, DiagnosticKind::ChainNotInWhitelist)
}

/// The local providers that match their whitelist entry; every mismatch is reported in `out`.
fn whitelisted_providers(
    chain: dtos::ForeignChain,
    local: &ForeignChainConfig,
    whitelist: &ChainEntry,
    out: &mut Vec<Diagnostic>,
) -> BTreeSet<ProviderId> {
    let mut whitelisted = BTreeSet::new();
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
        let mismatches = compare_provider(chain, local_name, local_provider, contract_provider);
        if mismatches.is_empty() {
            whitelisted.insert(contract_id);
        }
        out.extend(mismatches);
    }
    whitelisted
}

fn compare_provider(
    chain: dtos::ForeignChain,
    name: &RpcProviderName,
    local: &ForeignChainProviderConfig,
    contract: &ProviderConfig,
) -> Vec<Diagnostic> {
    let mut out = Vec::new();
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

    compare_auth(chain, name, &local.auth, &contract.auth_scheme, &mut out);
    out
}

/// Path-boundary-aware prefix check. `https://api.example.com/v2` matches `/v2`,
/// `/v2/eth`, `/v2?key=x`, `/v2#frag` — but not `/v2-evil`.
///
/// The first `{}` in `base` matches one non-empty run of `[A-Za-z0-9-]` — a single host
/// label in the bases we use, where a provider puts a per-operator slug in the hostname
/// (e.g. QuickNode's `https://{}.sui-testnet.quiknode.pro`).
/// The character after `{}` must not itself be a label character:
/// a base like `https://api-{}-v2.example.com` never matches.
fn base_url_matches(local: &str, base: &str) -> bool {
    let l = local.trim_end_matches('/');
    let b = base.trim_end_matches('/');

    let Some((prefix, suffix)) = b.split_once("{}") else {
        return starts_with_at_boundary(l, b);
    };
    let Some(rest) = l.strip_prefix(prefix) else {
        return false;
    };
    let label_len = rest
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '-')
        .unwrap_or(rest.len());
    let (_, rest) = rest.split_at(label_len);
    label_len > 0 && starts_with_at_boundary(rest, suffix)
}

/// Like [`str::starts_with`], but `prefix` must end where a URL component does.
fn starts_with_at_boundary(s: &str, prefix: &str) -> bool {
    if s == prefix {
        return true;
    }
    s.strip_prefix(prefix)
        .is_some_and(|rest| rest.starts_with('/') || rest.starts_with('?') || rest.starts_with('#'))
}

#[derive(Debug)]
enum RoutingCheck {
    Ok,
    Mismatch,
    Unknown,
}

fn chain_routing_satisfied(local_url: &str, routing: &ChainRouting) -> RoutingCheck {
    let found = match routing {
        ChainRouting::Embedded => return RoutingCheck::Ok,
        ChainRouting::PathSegment { segment } => url::Url::parse(local_url).is_ok_and(|url| {
            url.path_segments()
                .is_some_and(|mut segments| segments.any(|found| found == segment))
        }),
        ChainRouting::QueryParam { name, value } => url::Url::parse(local_url).is_ok_and(|url| {
            url.query_pairs()
                .any(|(found_name, found_value)| found_name == *name && found_value == *value)
        }),
        _ => return RoutingCheck::Unknown,
    };
    if found {
        RoutingCheck::Ok
    } else {
        RoutingCheck::Mismatch
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
            if !header_name_matches(local_h, contract_h) {
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

/// Header names are case insensitive: local is lowercased when [`AuthConfig::Header`] parses it
/// into an [`http::HeaderName`], while the contract keeps the casing the vote carried.
fn header_name_matches(local: &http::HeaderName, contract: &str) -> bool {
    local.as_str().eq_ignore_ascii_case(contract)
}

fn log_diagnostic(d: &Diagnostic) {
    let chain = d.chain;
    let provider = d.provider.as_ref().map(|p| p.as_str());
    match &d.kind {
        DiagnosticKind::UnknownContractVariant { .. } => {
            tracing::error!(?chain, provider, kind = ?d.kind, "foreign-chain whitelist contains a variant this node binary doesn't recognize; upgrade the node");
        }
        kind if is_informational(kind) => {
            tracing::info!(?chain, provider, kind = ?d.kind, "foreign-chain RPC policy");
        }
        _ => {
            tracing::warn!(?chain, provider, kind = ?d.kind, "foreign-chain RPC policy: whitelist mismatch");
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use mpc_node_config::TokenConfig;
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use std::{assert_matches, collections::BTreeMap};

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
            expected_network_fingerprint: None,
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

    /// The per-provider diagnostics, without the per-chain quorum verdict they imply.
    fn provider_mismatches(
        local: &ForeignChainsConfig,
        whitelist: &BTreeMap<dtos::ForeignChain, ChainEntry>,
    ) -> Vec<Diagnostic> {
        resolve_rpc_quorums(local, whitelist)
            .diagnostics
            .into_iter()
            .filter(|diagnostic| !matches!(diagnostic.kind, DiagnosticKind::BelowQuorum { .. }))
            .collect()
    }

    #[test]
    fn resolve_rpc_quorums__should_be_empty_when_local_and_whitelist_match() {
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
        let diags = provider_mismatches(&local, &whitelist);

        // Then
        assert!(diags.is_empty(), "expected no diagnostics, got: {diags:?}");
    }

    #[test]
    fn resolve_rpc_quorums__should_emit_chain_not_in_whitelist_when_chain_missing_from_contract() {
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
        let diags = provider_mismatches(&local, &whitelist);

        // Then
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].chain, dtos::ForeignChain::Ethereum);
        assert_eq!(diags[0].kind, DiagnosticKind::ChainNotInWhitelist);
    }

    #[test]
    fn resolve_rpc_quorums__should_emit_provider_not_in_whitelist_when_local_has_extra_provider() {
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
        let diags = provider_mismatches(&local, &whitelist);

        // Then
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].kind, DiagnosticKind::ProviderNotInWhitelist,);
        assert_eq!(
            diags[0].provider,
            Some(RpcProviderName::from("ankr".to_string()))
        );
    }

    #[test]
    fn resolve_rpc_quorums__should_emit_base_url_mismatch_when_local_rpc_url_has_wrong_prefix() {
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
        let diags = provider_mismatches(&local, &whitelist);

        // Then
        assert_eq!(diags.len(), 1);
        assert_matches!(diags[0].kind, DiagnosticKind::BaseUrlMismatch { .. });
    }

    #[test]
    fn resolve_rpc_quorums__should_emit_chain_routing_mismatch_when_path_segment_missing() {
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
        let diags = provider_mismatches(&local, &whitelist);

        // Then
        assert_eq!(diags.len(), 1);
        assert_matches!(diags[0].kind, DiagnosticKind::ChainRoutingMismatch { .. });
    }

    #[test]
    fn resolve_rpc_quorums__should_emit_chain_routing_mismatch_when_query_param_missing() {
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
        let diags = provider_mismatches(&local, &whitelist);

        // Then
        assert_eq!(diags.len(), 1);
        assert_matches!(diags[0].kind, DiagnosticKind::ChainRoutingMismatch { .. });
    }

    #[test]
    fn resolve_rpc_quorums__should_emit_auth_variant_mismatch_when_local_uses_none_and_contract_uses_header()
     {
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
        let diags = provider_mismatches(&local, &whitelist);

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
    fn resolve_rpc_quorums__should_emit_auth_name_mismatch_when_query_param_names_differ() {
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
        let diags = provider_mismatches(&local, &whitelist);

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

    /// Build a single-ethereum-chain [`ForeignChainsConfig`] with one alchemy
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
    fn resolve_rpc_quorums__should_emit_header_scheme_mismatch_when_schemes_differ() {
        // Given: same Header name, different scheme tag.
        let local = local_header_eth("authorization", Some("Bearer"));
        let whitelist = contract_header_eth("authorization", Some("Basic"));

        // When
        let diags = provider_mismatches(&local, &whitelist);

        // Then
        assert_eq!(diags.len(), 1);
        assert_matches!(
            &diags[0].kind,
            DiagnosticKind::AuthSchemeHeaderSchemeMismatch { local, contract }
                if local.as_deref() == Some("Bearer") && contract.as_deref() == Some("Basic")
        );
    }

    #[test]
    fn resolve_rpc_quorums__should_emit_header_scheme_mismatch_when_one_side_is_none() {
        // Given: local omits the scheme tag, contract requires one.
        let local = local_header_eth("authorization", None);
        let whitelist = contract_header_eth("authorization", Some("Bearer"));

        // When
        let diags = provider_mismatches(&local, &whitelist);

        // Then
        assert_eq!(diags.len(), 1);
        assert_matches!(
            &diags[0].kind,
            DiagnosticKind::AuthSchemeHeaderSchemeMismatch { local, contract }
                if local.is_none() && contract.as_deref() == Some("Bearer")
        );
    }

    #[test]
    fn resolve_rpc_quorums__should_emit_both_header_name_and_scheme_mismatch_when_both_differ() {
        // Given: header name AND scheme both differ.
        let local = local_header_eth("authorization", Some("Bearer"));
        let whitelist = contract_header_eth("x-api-key", Some("Basic"));

        // When
        let diags = provider_mismatches(&local, &whitelist);

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
    fn resolve_rpc_quorums__should_accept_matching_header_name_and_scheme() {
        // Given: header name AND scheme both match.
        let local = local_header_eth("authorization", Some("Bearer"));
        let whitelist = contract_header_eth("authorization", Some("Bearer"));

        // When
        let diags = provider_mismatches(&local, &whitelist);

        // Then
        assert!(diags.is_empty(), "expected no diagnostics, got: {diags:?}");
    }

    #[test]
    fn resolve_rpc_quorums__should_accept_header_names_differing_only_in_case() {
        // Given: the same header, voted in capitalised and configured lowercase.
        let local = local_header_eth("authorization", Some("Bearer"));
        let whitelist = contract_header_eth("Authorization", Some("Bearer"));

        // When
        let diags = provider_mismatches(&local, &whitelist);

        // Then
        assert!(diags.is_empty(), "expected no diagnostics, got: {diags:?}");
    }

    #[test]
    fn resolve_rpc_quorums__should_emit_header_name_mismatch_when_names_differ_beyond_case() {
        // Given
        let local = local_header_eth("authorization", Some("Bearer"));
        let whitelist = contract_header_eth("X-Api-Key", Some("Bearer"));

        // When
        let diags = provider_mismatches(&local, &whitelist);

        // Then
        assert_eq!(diags.len(), 1);
        assert_matches!(
            diags[0].kind,
            DiagnosticKind::AuthSchemeNameMismatch {
                variant: "Header",
                ..
            }
        );
    }

    #[test]
    fn resolve_rpc_quorums__should_emit_path_placeholder_mismatch_when_placeholders_differ() {
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
        let diags = provider_mismatches(&local, &whitelist);

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
    fn resolve_rpc_quorums__should_accept_matching_path_placeholders() {
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
        let diags = provider_mismatches(&local, &whitelist);

        // Then
        assert!(diags.is_empty(), "expected no diagnostics, got: {diags:?}");
    }

    #[test]
    fn resolve_rpc_quorums__should_be_silent_when_whitelist_has_chain_not_configured_locally() {
        // Given: local has no chains; whitelist has Ethereum with one provider.
        // The resolver doesn't warn when the whitelist is a superset — operators
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
        let diags = provider_mismatches(&local, &whitelist);

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

    const WILDCARD: &str = "https://{}.abstract-testnet.quiknode.pro";

    #[test]
    fn base_url_matches__should_accept_any_single_host_label_for_a_wildcard_base() {
        assert!(base_url_matches(
            "https://misty-fabled-sunset.abstract-testnet.quiknode.pro/abc123",
            WILDCARD
        ));
        assert!(base_url_matches(
            "https://acme7.abstract-testnet.quiknode.pro/{api_key}",
            WILDCARD
        ));
        assert!(base_url_matches(
            "https://acme7.abstract-testnet.quiknode.pro",
            WILDCARD
        ));
    }

    #[test]
    fn base_url_matches__should_reject_wildcard_spanning_a_label_boundary() {
        // The wildcard must not swallow `/`, `.`, or `?` — each would let the pinned domain
        // suffix land somewhere other than the host.
        assert!(!base_url_matches(
            "https://evil.example.com/.abstract-testnet.quiknode.pro/",
            WILDCARD
        ));
        assert!(!base_url_matches(
            "https://a.b.abstract-testnet.quiknode.pro/",
            WILDCARD
        ));
        assert!(!base_url_matches(
            "https://evil.com?x=.abstract-testnet.quiknode.pro",
            WILDCARD
        ));
        assert!(!base_url_matches(
            "https://.abstract-testnet.quiknode.pro/",
            WILDCARD
        ));
        assert!(!base_url_matches(
            "https://acme7.abstract-testnet.quiknode.pro.evil.io/",
            WILDCARD
        ));
        assert!(!base_url_matches(
            "https://acme7.abstract-testnet.quiknode.proevil/",
            WILDCARD
        ));
        // Userinfo trick: the whole whitelisted host as `user@` of an attacker host.
        assert!(!base_url_matches(
            "https://acme7.abstract-testnet.quiknode.pro@evil.com/",
            WILDCARD
        ));
    }

    fn matching_eth_provider(name: &str) -> (ForeignChainProviderConfig, ProviderConfig) {
        let base_url = format!("https://{name}.example.com/v2/");
        (
            local_provider(&base_url, AuthConfig::None),
            contract_provider(&base_url, ChainRouting::Embedded, AuthScheme::None),
        )
    }

    /// Ethereum with `names` configured locally and whitelisted with `quorum`.
    fn eth_resolution(
        names: &[&str],
        quorum: u64,
    ) -> (
        ForeignChainsConfig,
        BTreeMap<dtos::ForeignChain, ChainEntry>,
    ) {
        let providers: Vec<_> = names
            .iter()
            .map(|name| (*name, matching_eth_provider(name)))
            .collect();
        let local = ForeignChainsConfig {
            ethereum: Some(local_chain(
                &providers
                    .iter()
                    .map(|(name, (local, _))| (*name, local.clone()))
                    .collect::<Vec<_>>(),
            )),
            ..Default::default()
        };
        let whitelist = BTreeMap::from([(
            dtos::ForeignChain::Ethereum,
            contract_chain_entry(
                &providers
                    .iter()
                    .map(|(name, (_, contract))| (*name, contract.clone()))
                    .collect::<Vec<_>>(),
                quorum,
            ),
        )]);
        (local, whitelist)
    }

    fn provider_ids(names: &[&str]) -> BTreeSet<ProviderId> {
        names
            .iter()
            .map(|name| ProviderId(name.to_string()))
            .collect()
    }

    #[test]
    fn resolve_rpc_quorums__should_make_a_chain_eligible_when_the_quorum_is_reachable() {
        // Given
        let (local, whitelist) = eth_resolution(&["alchemy", "quicknode"], 2);

        // When
        let resolution = resolve_rpc_quorums(&local, &whitelist);

        // Then
        assert_eq!(
            resolution.eligible(),
            BTreeMap::from([(
                dtos::ForeignChain::Ethereum,
                RpcQuorum {
                    required: NonZeroUsize::new(2).unwrap(),
                    whitelisted: provider_ids(&["alchemy", "quicknode"]),
                },
            )])
        );
        assert!(resolution.diagnostics.is_empty());
    }

    #[test]
    fn resolve_rpc_quorums__should_omit_a_chain_with_fewer_whitelisted_providers_than_the_quorum() {
        // Given
        let (local, whitelist) = eth_resolution(&["alchemy"], 2);

        // When
        let resolution = resolve_rpc_quorums(&local, &whitelist);

        // Then
        assert!(resolution.eligible().is_empty());
        assert_eq!(
            resolution.quorums[&dtos::ForeignChain::Ethereum].whitelisted,
            provider_ids(&["alchemy"])
        );
        assert_eq!(
            resolution.diagnostics,
            vec![Diagnostic {
                chain: dtos::ForeignChain::Ethereum,
                provider: None,
                kind: DiagnosticKind::BelowQuorum {
                    whitelisted: 1,
                    required: NonZeroUsize::new(2).unwrap(),
                },
            }]
        );
    }

    #[test]
    fn resolve_rpc_quorums__should_not_count_a_mismatching_provider_towards_the_quorum() {
        // Given: two whitelisted providers, but the local quicknode URL is on another host.
        let (_, whitelist) = eth_resolution(&["alchemy", "quicknode"], 1);
        let local = ForeignChainsConfig {
            ethereum: Some(local_chain(&[
                ("alchemy", matching_eth_provider("alchemy").0),
                (
                    "quicknode",
                    local_provider("https://elsewhere.example.com/v2/", AuthConfig::None),
                ),
            ])),
            ..Default::default()
        };

        // When
        let resolution = resolve_rpc_quorums(&local, &whitelist);

        // Then
        assert_eq!(
            resolution.quorums[&dtos::ForeignChain::Ethereum].whitelisted,
            provider_ids(&["alchemy"])
        );
        assert_matches!(
            resolution.diagnostics.as_slice(),
            [Diagnostic {
                kind: DiagnosticKind::BaseUrlMismatch { .. },
                ..
            }]
        );
    }

    #[test]
    fn resolve_rpc_quorums__should_skip_a_chain_with_an_unusable_quorum() {
        // Given
        let (local, whitelist) = eth_resolution(&["alchemy"], 0);

        // When
        let resolution = resolve_rpc_quorums(&local, &whitelist);

        // Then
        assert!(resolution.quorums.is_empty());
        assert_eq!(
            resolution.diagnostics,
            vec![Diagnostic {
                chain: dtos::ForeignChain::Ethereum,
                provider: None,
                kind: DiagnosticKind::UnusableQuorum { quorum: 0 },
            }]
        );
    }

    #[test]
    fn chain_routing_satisfied__should_match_a_whole_path_segment_only() {
        // Given
        let routing = ChainRouting::PathSegment {
            segment: "eth".to_string(),
        };

        // When, then
        assert_matches!(
            chain_routing_satisfied("https://rpc.ankr.com/eth", &routing),
            RoutingCheck::Ok
        );
        assert_matches!(
            chain_routing_satisfied("https://rpc.ankr.com/ethereum", &routing),
            RoutingCheck::Mismatch
        );
    }

    #[test]
    fn chain_routing_satisfied__should_match_a_whole_query_parameter_only() {
        // Given
        let routing = ChainRouting::QueryParam {
            name: "network".to_string(),
            value: "ethereum".to_string(),
        };

        // When, then
        assert_matches!(
            chain_routing_satisfied("https://lb.drpc.org/ogrpc?network=ethereum", &routing),
            RoutingCheck::Ok
        );
        assert_matches!(
            chain_routing_satisfied("https://lb.drpc.org/ogrpc?xnetwork=ethereum", &routing),
            RoutingCheck::Mismatch
        );
    }

    const REPUBLISH_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

    #[tokio::test]
    async fn spawn_rpc_quorums_resolver__should_republish_when_the_whitelist_changes() {
        let (root, _root_handle) = crate::tracking::start_root_task("test-root", async move {
            // Given: Ethereum configured locally but not whitelisted yet.
            let (local, whitelist) = eth_resolution(&["alchemy"], 1);
            let (whitelist_sender, whitelist_receiver) = watch::channel(BTreeMap::new());
            let (mut quorums, _task) = spawn_rpc_quorums_resolver(whitelist_receiver, local);
            assert!(quorums.borrow().is_empty());

            // When
            whitelist_sender.send(whitelist).unwrap();
            tokio::time::timeout(REPUBLISH_WAIT, quorums.changed())
                .await
                .unwrap()
                .unwrap();

            // Then
            assert!(quorums.borrow().contains_key(&dtos::ForeignChain::Ethereum));
        });
        root.await;
    }
}
