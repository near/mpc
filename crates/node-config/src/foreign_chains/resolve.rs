use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types as dtos;

use super::{
    AuthConfig, ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig,
    ProviderCredentials, RpcPreset, RpcProviderName, SLUG_PLACEHOLDER, embedded_foreign_chains,
};

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("failed to parse the embedded {0} foreign chain config")]
    EmbeddedPreset(RpcPreset, #[source] toml::de::Error),
    #[error("the foreign chain config resolved with the embedded config is invalid")]
    InvalidResolvedConfig(#[source] anyhow::Error),
}

#[derive(Clone, Debug)]
pub struct ResolvedForeignChains {
    pub config: ForeignChainsConfig,
    pub diagnostics: Vec<ResolutionDiagnostic>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolutionDiagnostic {
    Included {
        chain: dtos::ForeignChain,
        provider: RpcProviderName,
        source: PairSource,
    },
    EmbeddedSkipped {
        chain: dtos::ForeignChain,
        provider: RpcProviderName,
        reason: SkipReason,
    },
    /// A node config pair replaced an embedded pair that would otherwise be enabled.
    Overridden {
        chain: dtos::ForeignChain,
        provider: RpcProviderName,
        rpc_url_differs: bool,
    },
}

impl ResolutionDiagnostic {
    pub fn is_warning(&self) -> bool {
        match self {
            Self::Included { .. } => false,
            Self::EmbeddedSkipped { .. } => true,
            Self::Overridden {
                rpc_url_differs, ..
            } => *rpc_url_differs,
        }
    }
}

impl fmt::Display for ResolutionDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Included {
                chain,
                provider,
                source,
            } => {
                let source = match source {
                    PairSource::Embedded => "embedded preset",
                    PairSource::NodeConfig => "node config",
                };
                write!(
                    f,
                    "{}/{}: from the {source}",
                    chain.label(),
                    provider.as_str()
                )
            }
            Self::EmbeddedSkipped {
                chain,
                provider,
                reason,
            } => {
                let reason = match reason {
                    SkipReason::MissingCredentials => "no credentials for the provider",
                    SkipReason::MissingSlug => "the provider's credentials have no slug",
                    SkipReason::DuplicateRpcUrl => "a node config provider uses the same RPC URL",
                };
                write!(
                    f,
                    "{}/{}: embedded provider skipped, {reason}",
                    chain.label(),
                    provider.as_str()
                )
            }
            Self::Overridden {
                chain,
                provider,
                rpc_url_differs,
            } => {
                let detail = if *rpc_url_differs {
                    "with a different RPC URL"
                } else {
                    "with the same RPC URL"
                };
                write!(
                    f,
                    "{}/{}: node config overrides the embedded provider {detail}",
                    chain.label(),
                    provider.as_str()
                )
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairSource {
    Embedded,
    NodeConfig,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    MissingCredentials,
    MissingSlug,
    DuplicateRpcUrl,
}

/// Resolves against the embedded config [`ForeignChainsConfig::rpc_preset`] selects.
pub fn resolve_with_embedded(
    node_config: &ForeignChainsConfig,
) -> Result<ResolvedForeignChains, ResolveError> {
    let embedded = node_config
        .rpc_preset
        .map(|preset| {
            embedded_foreign_chains(preset).map_err(|e| ResolveError::EmbeddedPreset(preset, e))
        })
        .transpose()?;
    resolve_foreign_chains(node_config, embedded.as_ref())
}

/// Adds the embedded (chain, provider) pairs the node config's credentials enable to the node
/// config. A pair the node config defines is kept whole, as are its chain-level fields.
pub(super) fn resolve_foreign_chains(
    node_config: &ForeignChainsConfig,
    embedded: Option<&ForeignChainsConfig>,
) -> Result<ResolvedForeignChains, ResolveError> {
    let mut config = node_config.clone();
    let mut diagnostics = Vec::new();
    let node_config_rpc_urls: BTreeSet<&str> = node_config
        .iter_chains()
        .flat_map(|(_, chain)| chain.providers.values())
        .map(|provider| provider.rpc_url.as_str())
        .collect();

    for (chain, embedded_chain) in embedded
        .into_iter()
        .flat_map(ForeignChainsConfig::iter_chains)
    {
        let node_chain = find_chain(node_config, chain);
        let mut providers: BTreeMap<_, _> = node_chain
            .map(|c| c.providers.clone().into())
            .unwrap_or_default();

        for (name, embedded_provider) in embedded_chain.providers.iter() {
            let node_provider = node_chain.and_then(|c| c.providers.get(name));
            match (
                node_provider,
                enable(embedded_provider, node_config.credentials.get(name)),
            ) {
                // Node config defines the pair: keep it, report the embedded one it replaces.
                (Some(node_provider), Ok(enabled)) => {
                    diagnostics.push(ResolutionDiagnostic::Overridden {
                        chain,
                        provider: name.clone(),
                        rpc_url_differs: enabled.rpc_url != node_provider.rpc_url,
                    })
                }
                // Node config defines the pair, embedded one couldn't be enabled anyway.
                (Some(_), Err(_)) => {}
                // Same endpoint under another name in node config: skip, URLs must be unique.
                (None, Ok(enabled)) if node_config_rpc_urls.contains(enabled.rpc_url.as_str()) => {
                    diagnostics.push(skipped(chain, name, SkipReason::DuplicateRpcUrl))
                }
                // Node config lacks the pair: fill it in from the embedded config.
                (None, Ok(enabled)) => {
                    providers.insert(name.clone(), enabled);
                }
                // Node config lacks the pair and credentials don't enable it.
                (None, Err(reason)) => diagnostics.push(skipped(chain, name, reason)),
            }
        }

        let chain_fields = node_chain.unwrap_or(embedded_chain);
        if let (Some(slot), Ok(providers)) = (
            config.chain_slot_mut(chain),
            NonEmptyBTreeMap::try_from(providers),
        ) {
            *slot = Some(ForeignChainConfig {
                timeout_sec: chain_fields.timeout_sec,
                max_retries: chain_fields.max_retries,
                expected_network_fingerprint: chain_fields.expected_network_fingerprint.clone(),
                providers,
            });
        }
    }

    diagnostics.extend(included(node_config, &config));
    config
        .validate()
        .map_err(ResolveError::InvalidResolvedConfig)?;
    Ok(ResolvedForeignChains {
        config,
        diagnostics,
    })
}

fn skipped(
    chain: dtos::ForeignChain,
    provider: &RpcProviderName,
    reason: SkipReason,
) -> ResolutionDiagnostic {
    ResolutionDiagnostic::EmbeddedSkipped {
        chain,
        provider: provider.clone(),
        reason,
    }
}

/// Where each pair of the resolved config came from.
fn included<'a>(
    node_config: &'a ForeignChainsConfig,
    resolved: &'a ForeignChainsConfig,
) -> impl Iterator<Item = ResolutionDiagnostic> + 'a {
    resolved
        .iter_chains()
        .flat_map(move |(chain, chain_config)| {
            let node_chain = find_chain(node_config, chain);
            chain_config.providers.keys().map(move |name| {
                let source = if node_chain.is_some_and(|c| c.providers.contains_key(name)) {
                    PairSource::NodeConfig
                } else {
                    PairSource::Embedded
                };
                ResolutionDiagnostic::Included {
                    chain,
                    provider: name.clone(),
                    source,
                }
            })
        })
}

fn find_chain(
    config: &ForeignChainsConfig,
    chain: dtos::ForeignChain,
) -> Option<&ForeignChainConfig> {
    config
        .chain_slots()
        .find_map(|(slot_chain, slot)| (slot_chain == chain).then_some(slot).flatten())
}

/// The embedded provider with the operator's credentials filled in.
fn enable(
    provider: &ForeignChainProviderConfig,
    credentials: Option<&ProviderCredentials>,
) -> Result<ForeignChainProviderConfig, SkipReason> {
    let auth = match (&provider.auth, credentials) {
        (AuthConfig::None, _) => AuthConfig::None,
        (_, None) => return Err(SkipReason::MissingCredentials),
        (AuthConfig::Header { name, scheme, .. }, Some(credentials)) => AuthConfig::Header {
            name: name.clone(),
            scheme: scheme.clone(),
            token: credentials.api_key.clone(),
        },
        (AuthConfig::Path { placeholder, .. }, Some(credentials)) => AuthConfig::Path {
            placeholder: placeholder.clone(),
            token: credentials.api_key.clone(),
        },
        (AuthConfig::Query { name, .. }, Some(credentials)) => AuthConfig::Query {
            name: name.clone(),
            token: credentials.api_key.clone(),
        },
    };
    let rpc_url = if provider.rpc_url.contains(SLUG_PLACEHOLDER) {
        let credentials = credentials.ok_or(SkipReason::MissingCredentials)?;
        let slug = credentials.slug.as_deref().ok_or(SkipReason::MissingSlug)?;
        provider.rpc_url.replace(SLUG_PLACEHOLDER, slug)
    } else {
        provider.rpc_url.clone()
    };
    Ok(ForeignChainProviderConfig { rpc_url, auth })
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::num::NonZeroU64;

    use assert_matches::assert_matches;
    use rstest::rstest;

    use super::*;
    use crate::foreign_chains::TokenConfig;

    const ALCHEMY_URL: &str = "https://eth-mainnet.g.alchemy.com/v2/{api_key}";
    const QUICKNODE_URL: &str = "https://{slug}.quiknode.pro/{api_key}";
    const PUBLIC_URL: &str = "https://ethereum-rpc.publicnode.com";

    #[rstest]
    #[case::included(
        ResolutionDiagnostic::Included {
            chain: dtos::ForeignChain::Ethereum,
            provider: name("public"),
            source: PairSource::Embedded,
        },
        false
    )]
    #[case::skipped(
        ResolutionDiagnostic::EmbeddedSkipped {
            chain: dtos::ForeignChain::Ethereum,
            provider: name("alchemy"),
            reason: SkipReason::MissingCredentials,
        },
        true
    )]
    #[case::overridden_differs(
        ResolutionDiagnostic::Overridden {
            chain: dtos::ForeignChain::Ethereum,
            provider: name("alchemy"),
            rpc_url_differs: true,
        },
        true
    )]
    #[case::overridden_same(
        ResolutionDiagnostic::Overridden {
            chain: dtos::ForeignChain::Ethereum,
            provider: name("alchemy"),
            rpc_url_differs: false,
        },
        false
    )]
    fn resolution_diagnostic_is_warning__should_flag_skips_and_differing_overrides(
        #[case] diagnostic: ResolutionDiagnostic,
        #[case] expected: bool,
    ) {
        // When
        let is_warning = diagnostic.is_warning();

        // Then
        assert_eq!(is_warning, expected);
    }

    fn name(name: &str) -> RpcProviderName {
        name.to_string().into()
    }

    fn token(val: &str) -> TokenConfig {
        TokenConfig::Val {
            val: val.to_string(),
        }
    }

    fn path_auth(val: &str) -> AuthConfig {
        AuthConfig::Path {
            placeholder: "{api_key}".to_string(),
            token: token(val),
        }
    }

    fn header_auth(val: &str) -> AuthConfig {
        AuthConfig::Header {
            name: http::HeaderName::from_static("x-api-key"),
            scheme: Some("Bearer".to_string()),
            token: token(val),
        }
    }

    fn query_auth(val: &str) -> AuthConfig {
        AuthConfig::Query {
            name: "key".to_string(),
            token: token(val),
        }
    }

    fn provider(rpc_url: &str, auth: AuthConfig) -> ForeignChainProviderConfig {
        ForeignChainProviderConfig {
            rpc_url: rpc_url.to_string(),
            auth,
        }
    }

    fn chain(
        timeout_sec: u64,
        providers: impl IntoIterator<Item = (&'static str, ForeignChainProviderConfig)>,
    ) -> ForeignChainConfig {
        let providers: BTreeMap<_, _> = providers
            .into_iter()
            .map(|(provider_name, provider)| (name(provider_name), provider))
            .collect();
        ForeignChainConfig {
            timeout_sec: NonZeroU64::new(timeout_sec).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            expected_network_fingerprint: Some("1".to_string()),
            providers: providers.try_into().unwrap(),
        }
    }

    /// Ethereum with a public, an API-key and a slug provider, as in the embedded files.
    fn embedded() -> ForeignChainsConfig {
        ForeignChainsConfig {
            ethereum: Some(chain(
                30,
                [
                    ("public", provider(PUBLIC_URL, AuthConfig::None)),
                    ("alchemy", provider(ALCHEMY_URL, path_auth(""))),
                    ("quicknode", provider(QUICKNODE_URL, path_auth(""))),
                ],
            )),
            ..Default::default()
        }
    }

    fn credentials(
        entries: impl IntoIterator<Item = (&'static str, &'static str, Option<&'static str>)>,
    ) -> BTreeMap<RpcProviderName, ProviderCredentials> {
        entries
            .into_iter()
            .map(|(provider_name, api_key, slug)| {
                let credentials = ProviderCredentials {
                    api_key: token(api_key),
                    slug: slug.map(str::to_string),
                };
                (name(provider_name), credentials)
            })
            .collect()
    }

    fn resolve(node_config: &ForeignChainsConfig) -> ResolvedForeignChains {
        resolve_foreign_chains(node_config, Some(&embedded())).expect("config should resolve")
    }

    fn ethereum(resolved: &ResolvedForeignChains) -> &ForeignChainConfig {
        resolved
            .config
            .ethereum
            .as_ref()
            .expect("ethereum should be resolved")
    }

    #[test]
    fn resolve_foreign_chains__should_return_node_config_when_nothing_is_embedded() {
        // Given
        let node_config = ForeignChainsConfig {
            ethereum: Some(chain(
                10,
                [("mine", provider(PUBLIC_URL, AuthConfig::None))],
            )),
            ..Default::default()
        };

        // When
        let resolved = resolve_foreign_chains(&node_config, None).expect("config should resolve");

        // Then
        assert_eq!(resolved.config, node_config);
        assert_eq!(
            resolved.diagnostics,
            vec![ResolutionDiagnostic::Included {
                chain: dtos::ForeignChain::Ethereum,
                provider: name("mine"),
                source: PairSource::NodeConfig,
            }]
        );
    }

    #[test]
    fn resolve_foreign_chains__should_enable_only_no_auth_providers_without_credentials() {
        // Given
        let node_config = ForeignChainsConfig::default();

        // When
        let resolved = resolve(&node_config);

        // Then
        let ethereum = ethereum(&resolved);
        assert_eq!(
            ethereum.providers.keys().collect::<Vec<_>>(),
            vec![&name("public")]
        );
        assert_eq!(ethereum.timeout_sec.get(), 30);
        assert!(
            resolved
                .diagnostics
                .contains(&ResolutionDiagnostic::Included {
                    chain: dtos::ForeignChain::Ethereum,
                    provider: name("public"),
                    source: PairSource::Embedded,
                })
        );
        for skipped in ["alchemy", "quicknode"] {
            assert!(
                resolved
                    .diagnostics
                    .contains(&ResolutionDiagnostic::EmbeddedSkipped {
                        chain: dtos::ForeignChain::Ethereum,
                        provider: name(skipped),
                        reason: SkipReason::MissingCredentials,
                    })
            );
        }
    }

    #[test]
    fn resolve_foreign_chains__should_fill_in_api_key_and_slug_from_credentials() {
        // Given
        let node_config = ForeignChainsConfig {
            credentials: credentials([
                ("alchemy", "alchemy-key", None),
                ("quicknode", "quicknode-key", Some("my-endpoint")),
            ]),
            ..Default::default()
        };

        // When
        let resolved = resolve(&node_config);

        // Then
        let providers = &ethereum(&resolved).providers;
        assert_eq!(
            providers.get(&name("alchemy")),
            Some(&provider(ALCHEMY_URL, path_auth("alchemy-key")))
        );
        assert_eq!(
            providers.get(&name("quicknode")),
            Some(&provider(
                "https://my-endpoint.quiknode.pro/{api_key}",
                path_auth("quicknode-key")
            ))
        );
        assert!(
            !resolved.diagnostics.iter().any(|diagnostic| matches!(
                diagnostic,
                ResolutionDiagnostic::EmbeddedSkipped { .. }
            ))
        );
    }

    #[test]
    fn resolve_foreign_chains__should_skip_slug_provider_when_credentials_have_no_slug() {
        // Given
        let node_config = ForeignChainsConfig {
            credentials: credentials([("quicknode", "quicknode-key", None)]),
            ..Default::default()
        };

        // When
        let resolved = resolve(&node_config);

        // Then
        assert!(
            !ethereum(&resolved)
                .providers
                .contains_key(&name("quicknode"))
        );
        assert!(
            resolved
                .diagnostics
                .contains(&ResolutionDiagnostic::EmbeddedSkipped {
                    chain: dtos::ForeignChain::Ethereum,
                    provider: name("quicknode"),
                    reason: SkipReason::MissingSlug,
                })
        );
    }

    #[test]
    fn resolve_foreign_chains__should_keep_node_config_pair_and_chain_fields_over_embedded() {
        // Given
        let own_alchemy = provider(
            "https://eth-mainnet.g.alchemy.com/v2/{api_key}/custom",
            path_auth("own-key"),
        );
        let node_config = ForeignChainsConfig {
            ethereum: Some(chain(10, [("alchemy", own_alchemy.clone())])),
            credentials: credentials([("alchemy", "shared-key", None)]),
            ..Default::default()
        };

        // When
        let resolved = resolve(&node_config);

        // Then
        let ethereum = ethereum(&resolved);
        assert_eq!(ethereum.timeout_sec.get(), 10);
        assert_eq!(ethereum.providers.get(&name("alchemy")), Some(&own_alchemy));
        assert!(ethereum.providers.contains_key(&name("public")));
        assert!(
            resolved
                .diagnostics
                .contains(&ResolutionDiagnostic::Overridden {
                    chain: dtos::ForeignChain::Ethereum,
                    provider: name("alchemy"),
                    rpc_url_differs: true,
                })
        );
        assert!(
            resolved
                .diagnostics
                .contains(&ResolutionDiagnostic::Included {
                    chain: dtos::ForeignChain::Ethereum,
                    provider: name("alchemy"),
                    source: PairSource::NodeConfig,
                })
        );
    }

    #[test]
    fn resolve_foreign_chains__should_report_node_config_pair_identical_to_embedded() {
        // Given
        let node_config = ForeignChainsConfig {
            ethereum: Some(chain(
                30,
                [("public", provider(PUBLIC_URL, AuthConfig::None))],
            )),
            ..Default::default()
        };

        // When
        let resolved = resolve(&node_config);

        // Then
        assert!(
            resolved
                .diagnostics
                .contains(&ResolutionDiagnostic::Overridden {
                    chain: dtos::ForeignChain::Ethereum,
                    provider: name("public"),
                    rpc_url_differs: false,
                })
        );
    }

    #[test]
    fn resolve_foreign_chains__should_skip_embedded_pair_whose_url_the_node_config_uses() {
        // Given: a legacy config naming the embedded public endpoint differently.
        let node_config = ForeignChainsConfig {
            ethereum: Some(chain(
                30,
                [("publicnode", provider(PUBLIC_URL, AuthConfig::None))],
            )),
            ..Default::default()
        };

        // When
        let resolved = resolve(&node_config);

        // Then
        assert_eq!(
            ethereum(&resolved).providers.keys().collect::<Vec<_>>(),
            vec![&name("publicnode")]
        );
        assert!(
            resolved
                .diagnostics
                .contains(&ResolutionDiagnostic::EmbeddedSkipped {
                    chain: dtos::ForeignChain::Ethereum,
                    provider: name("public"),
                    reason: SkipReason::DuplicateRpcUrl,
                })
        );
    }

    #[test]
    fn resolve_foreign_chains__should_leave_out_chain_without_enabled_providers() {
        // Given
        let embedded = ForeignChainsConfig {
            bnb: Some(chain(
                30,
                [("alchemy", provider(ALCHEMY_URL, path_auth("")))],
            )),
            ..Default::default()
        };

        // When
        let resolved = resolve_foreign_chains(&ForeignChainsConfig::default(), Some(&embedded))
            .expect("config should resolve");

        // Then
        assert!(resolved.config.is_empty());
    }

    #[test]
    fn resolve_with_embedded__should_ignore_credentials_without_rpc_preset() {
        // Given
        let node_config = ForeignChainsConfig {
            ethereum: Some(chain(
                10,
                [("mine", provider(PUBLIC_URL, AuthConfig::None))],
            )),
            credentials: credentials([("alchemy", "alchemy-key", None)]),
            ..Default::default()
        };

        // When
        let resolved = resolve_with_embedded(&node_config).expect("config should resolve");

        // Then
        assert_eq!(resolved.config, node_config);
    }

    #[test]
    fn resolve_foreign_chains__should_return_node_config_when_credentials_enable_nothing() {
        // Given: a preset with only keyed providers and a node config without credentials.
        let embedded = ForeignChainsConfig {
            ethereum: Some(chain(
                30,
                [("alchemy", provider(ALCHEMY_URL, path_auth("")))],
            )),
            bnb: Some(chain(
                30,
                [("quicknode", provider(QUICKNODE_URL, path_auth("")))],
            )),
            ..Default::default()
        };
        let node_config = ForeignChainsConfig {
            ethereum: Some(chain(
                10,
                [("mine", provider(PUBLIC_URL, AuthConfig::None))],
            )),
            ..Default::default()
        };

        // When
        let resolved =
            resolve_foreign_chains(&node_config, Some(&embedded)).expect("config should resolve");

        // Then
        assert_eq!(resolved.config, node_config);
    }

    #[test]
    fn resolve_foreign_chains__should_merge_each_chain_independently() {
        // Given: the node config defines ethereum (overlapping the preset) and adi (not in it);
        // the preset alone defines bnb.
        let embedded = ForeignChainsConfig {
            ethereum: Some(chain(
                30,
                [
                    ("public", provider(PUBLIC_URL, AuthConfig::None)),
                    ("alchemy", provider(ALCHEMY_URL, path_auth(""))),
                ],
            )),
            bnb: Some(chain(
                40,
                [(
                    "public",
                    provider("https://bsc-rpc.publicnode.com", AuthConfig::None),
                )],
            )),
            ..Default::default()
        };
        let own_alchemy = provider(
            "https://eth-mainnet.g.alchemy.com/v2/{api_key}/custom",
            path_auth("own-key"),
        );
        let adi = chain(
            20,
            [(
                "public",
                provider("https://rpc.adifoundation.ai", AuthConfig::None),
            )],
        );
        let node_config = ForeignChainsConfig {
            ethereum: Some(chain(10, [("alchemy", own_alchemy.clone())])),
            adi: Some(adi.clone()),
            ..Default::default()
        };

        // When
        let resolved =
            resolve_foreign_chains(&node_config, Some(&embedded)).expect("config should resolve");

        // Then
        let ethereum = ethereum(&resolved);
        assert_eq!(ethereum.timeout_sec.get(), 10);
        assert_eq!(ethereum.providers.get(&name("alchemy")), Some(&own_alchemy));
        assert!(ethereum.providers.contains_key(&name("public")));

        let bnb = resolved
            .config
            .bnb
            .as_ref()
            .expect("bnb should come from the preset");
        assert_eq!(bnb.timeout_sec.get(), 40);

        assert_eq!(resolved.config.adi.as_ref(), Some(&adi));
    }

    #[rstest]
    #[case::header(header_auth(""), header_auth("alchemy-key"))]
    #[case::path(path_auth(""), path_auth("alchemy-key"))]
    #[case::query(query_auth(""), query_auth("alchemy-key"))]
    fn resolve_foreign_chains__should_put_the_api_key_into_each_auth_kind(
        #[case] embedded_auth: AuthConfig,
        #[case] expected_auth: AuthConfig,
    ) {
        // Given
        let embedded = ForeignChainsConfig {
            ethereum: Some(chain(
                30,
                [("alchemy", provider(ALCHEMY_URL, embedded_auth))],
            )),
            ..Default::default()
        };
        let node_config = ForeignChainsConfig {
            credentials: credentials([("alchemy", "alchemy-key", None)]),
            ..Default::default()
        };

        // When
        let resolved =
            resolve_foreign_chains(&node_config, Some(&embedded)).expect("config should resolve");

        // Then
        assert_eq!(
            ethereum(&resolved).providers.get(&name("alchemy")),
            Some(&provider(ALCHEMY_URL, expected_auth))
        );
    }

    #[test]
    fn resolve_foreign_chains__should_not_report_overriding_an_embedded_pair_that_is_not_enabled() {
        // Given: the node config defines alchemy, the preset's alchemy has no credentials.
        let own_alchemy = provider(
            "https://eth-mainnet.g.alchemy.com/v2/{api_key}/custom",
            path_auth("own-key"),
        );
        let node_config = ForeignChainsConfig {
            ethereum: Some(chain(10, [("alchemy", own_alchemy.clone())])),
            ..Default::default()
        };

        // When
        let resolved = resolve(&node_config);

        // Then
        assert_eq!(
            ethereum(&resolved).providers.get(&name("alchemy")),
            Some(&own_alchemy)
        );
        assert!(
            !resolved
                .diagnostics
                .iter()
                .any(|diagnostic| matches!(diagnostic, ResolutionDiagnostic::Overridden { .. }))
        );
    }

    #[test]
    fn resolve_foreign_chains__should_fail_on_invalid_slug() {
        // Given
        let node_config = ForeignChainsConfig {
            credentials: credentials([("quicknode", "quicknode-key", Some("evil.com/x"))]),
            ..Default::default()
        };

        // When
        let result = resolve_foreign_chains(&node_config, Some(&embedded()));

        // Then
        assert_matches!(
            result,
            Err(ResolveError::InvalidResolvedConfig(_)),
            "a slug must be a single host label"
        );
    }
}
