//! Log-only check that the node's local foreign-chain RPC config matches the
//! on-chain whitelist (`allowed_foreign_chain_providers`).

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

#[derive(Debug, PartialEq, Eq)]
struct Diagnostic {
    chain: dtos::ForeignChain,
    provider: Option<RpcProviderName>,
    kind: DiagnosticKind,
}

#[derive(Debug, PartialEq, Eq)]
enum DiagnosticKind {
    ChainNotInWhitelist,
    ChainNotInLocalConfig,
    ProviderNotInWhitelist,
    ProviderNotInLocalConfig,
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
}

/// Variants that reflect "local is a subset of whitelist" rather than a likely
/// misconfiguration; logged at info rather than warn.
fn is_informational(kind: &DiagnosticKind) -> bool {
    matches!(
        kind,
        DiagnosticKind::ChainNotInWhitelist
            | DiagnosticKind::ChainNotInLocalConfig
            | DiagnosticKind::ProviderNotInLocalConfig
    )
}

fn compare(
    local: &ForeignChainsConfig,
    whitelist: &BTreeMap<dtos::ForeignChain, ChainEntry>,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let local_chains: BTreeMap<dtos::ForeignChain, &ForeignChainConfig> =
        local.iter_chains().collect();

    for (chain, local_cfg) in &local_chains {
        let Some(whitelist_entry) = whitelist.get(chain) else {
            diagnostics.push(Diagnostic {
                chain: *chain,
                provider: None,
                kind: DiagnosticKind::ChainNotInWhitelist,
            });
            continue;
        };
        compare_chain(*chain, local_cfg, whitelist_entry, &mut diagnostics);
    }

    for (chain, whitelist_entry) in whitelist {
        if local_chains.contains_key(chain) {
            continue;
        }
        diagnostics.push(Diagnostic {
            chain: *chain,
            provider: None,
            kind: DiagnosticKind::ChainNotInLocalConfig,
        });
        for whitelisted_id in whitelist_entry.providers.keys() {
            diagnostics.push(Diagnostic {
                chain: *chain,
                provider: Some(RpcProviderName::from(whitelisted_id.0.clone())),
                kind: DiagnosticKind::ProviderNotInLocalConfig,
            });
        }
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

    for whitelisted_id in whitelist.providers.keys() {
        let local_name = RpcProviderName::from(whitelisted_id.0.clone());
        if local.providers.contains_key(&local_name) {
            continue;
        }
        out.push(Diagnostic {
            chain,
            provider: Some(local_name),
            kind: DiagnosticKind::ProviderNotInLocalConfig,
        });
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
    let base = contract.base_url.trim_end_matches('/');
    let local_trimmed = local_url.trim_end_matches('/');
    if !local_trimmed.starts_with(base) {
        out.push(Diagnostic {
            chain,
            provider: Some(name.clone()),
            kind: DiagnosticKind::BaseUrlMismatch {
                local_rpc_url: local_url.to_string(),
                contract_base_url: contract.base_url.clone(),
            },
        });
    }

    if !chain_routing_satisfied(local_url, &contract.chain_routing) {
        out.push(Diagnostic {
            chain,
            provider: Some(name.clone()),
            kind: DiagnosticKind::ChainRoutingMismatch {
                local_rpc_url: local_url.to_string(),
                contract_chain_routing: contract.chain_routing.clone(),
            },
        });
    }

    compare_auth(chain, name, &local.auth, &contract.auth_scheme, out);
}

fn chain_routing_satisfied(local_url: &str, routing: &ChainRouting) -> bool {
    match routing {
        ChainRouting::Embedded => true,
        ChainRouting::PathSegment { segment } => local_url.contains(&format!("/{segment}")),
        ChainRouting::QueryParam { name, value } => local_url.contains(&format!("{name}={value}")),
        // Non-exhaustive: unknown variants conservatively pass.
        _ => true,
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
        (AuthConfig::Path { .. }, AuthScheme::Path { .. }) => {}
        (
            AuthConfig::Header { name: local_h, .. },
            AuthScheme::Header {
                name: contract_h, ..
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
    if is_informational(&d.kind) {
        tracing::info!(?chain, provider, kind = ?d.kind, "foreign-chain whitelist verifier");
    } else {
        tracing::warn!(?chain, provider, kind = ?d.kind, "foreign-chain whitelist mismatch");
    }
}

pub(crate) async fn run(indexer_state: Arc<IndexerState>, local: ForeignChainsConfig) {
    let mut ticker = tokio::time::interval(VERIFY_INTERVAL);
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
        let diagnostics = compare(&local, &whitelist);
        if diagnostics.is_empty() {
            tracing::debug!(
                "foreign-chain whitelist verifier: local config matches contract whitelist"
            );
            continue;
        }
        for d in &diagnostics {
            log_diagnostic(d);
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
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
        assert!(matches!(
            diags[0].kind,
            DiagnosticKind::BaseUrlMismatch { .. }
        ));
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
        assert!(matches!(
            diags[0].kind,
            DiagnosticKind::ChainRoutingMismatch { .. }
        ));
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
        assert!(matches!(
            diags[0].kind,
            DiagnosticKind::ChainRoutingMismatch { .. }
        ));
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
        assert!(matches!(
            diags[0].kind,
            DiagnosticKind::AuthSchemeVariantMismatch {
                local: "None",
                contract: "Header",
            }
        ));
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
        assert!(matches!(
            diags[0].kind,
            DiagnosticKind::AuthSchemeNameMismatch {
                variant: "Query",
                ..
            }
        ));
    }

    #[test]
    fn compare__should_emit_subset_informational_when_whitelist_has_unconfigured_chain() {
        // Given: local has no chains; whitelist has Ethereum with one provider.
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

        // Then: one per missing chain + one per missing provider.
        assert_eq!(diags.len(), 2);
        assert!(diags
            .iter()
            .any(|d| d.kind == DiagnosticKind::ChainNotInLocalConfig));
        assert!(diags
            .iter()
            .any(|d| d.kind == DiagnosticKind::ProviderNotInLocalConfig));
    }
}
