//! Builds the `vote_update_foreign_chain_providers` argument from a declarative TOML config.
//!
//! ```toml
//! [chains.Bitcoin]
//! quorum = 1
//!
//! [chains.Bitcoin.providers.public]
//! base_url = "https://bitcoin-testnet-rpc.publicnode.com"
//! auth_scheme = "None"
//! chain_routing = "Embedded"
//! ```
//!
//! Keys and values use the contract's serde shapes verbatim: chain keys are
//! [`ForeignChain`] variant names, chain tables are [`ChainEntry`].

use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types::{
    AuthScheme, ChainEntry, ChainRouting, ForeignChain, ProviderId,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalConfig {
    pub chains: NonEmptyBTreeMap<ForeignChain, ChainEntry>,
}

/// Mirrors the `ChainEntry` validation the contract runs on a vote; a batch failing any of
/// these is rejected on chain with `InvalidParameters::MalformedPayload`.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("chain {chain:?}: quorum {quorum} must be between 1 and {providers} (provider count)")]
    InvalidQuorum {
        chain: ForeignChain,
        quorum: u64,
        providers: u64,
    },
    #[error("chain {chain:?}, provider {provider_id}: chain_routing segment must not contain '/'")]
    PathSegmentContainsSlash {
        chain: ForeignChain,
        provider_id: ProviderId,
    },
    #[error(
        "chain {chain:?}, provider {provider_id}: chain_routing query param {name:?} collides with the auth scheme's"
    )]
    QueryParamCollidesWithAuth {
        chain: ForeignChain,
        provider_id: ProviderId,
        name: String,
    },
    #[error("chain {chain:?}: {providers} providers do not fit in u64")]
    ProvidersLenOverflow {
        chain: ForeignChain,
        providers: usize,
    },
}

pub fn build_batch(
    config: ProposalConfig,
) -> Result<NonEmptyBTreeMap<ForeignChain, ChainEntry>, ConfigError> {
    for (chain, entry) in config.chains.iter() {
        validate_entry(*chain, entry)?;
    }
    Ok(config.chains)
}

fn validate_entry(chain: ForeignChain, entry: &ChainEntry) -> Result<(), ConfigError> {
    let providers =
        u64::try_from(entry.providers.len()).map_err(|_| ConfigError::ProvidersLenOverflow {
            chain,
            providers: entry.providers.len(),
        })?;
    if entry.quorum == 0 || entry.quorum > providers {
        return Err(ConfigError::InvalidQuorum {
            chain,
            quorum: entry.quorum,
            providers,
        });
    }

    for (provider_id, config) in entry.providers.iter() {
        if let ChainRouting::PathSegment { segment } = &config.chain_routing
            && segment.contains('/')
        {
            return Err(ConfigError::PathSegmentContainsSlash {
                chain,
                provider_id: provider_id.clone(),
            });
        }
        if let (
            ChainRouting::QueryParam {
                name: routing_name, ..
            },
            AuthScheme::Query { name: auth_name },
        ) = (&config.chain_routing, &config.auth_scheme)
            && routing_name == auth_name
        {
            return Err(ConfigError::QueryParamCollidesWithAuth {
                chain,
                provider_id: provider_id.clone(),
                name: auth_name.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use near_mpc_contract_interface::types::ProviderConfig;
    use rstest::rstest;

    fn parse(toml: &str) -> ProposalConfig {
        toml::from_str(toml).unwrap()
    }

    #[test]
    fn build_batch__should_map_config_to_chain_entries() {
        // Given
        let config = parse(
            r#"
            [chains.Aptos]
            quorum = 2

            [chains.Aptos.providers.alchemy]
            base_url = "https://aptos-testnet.g.alchemy.com/v2/"
            auth_scheme = { Path = { placeholder = "{API_KEY}" } }
            chain_routing = "Embedded"

            [chains.Aptos.providers.geomi]
            base_url = "https://api.testnet.aptoslabs.com/v1"
            auth_scheme = { Header = { name = "Authorization", scheme = "Bearer" } }
            chain_routing = "Embedded"

            [chains.Bitcoin]
            quorum = 1

            [chains.Bitcoin.providers.public]
            base_url = "https://bitcoin-testnet-rpc.publicnode.com"
            auth_scheme = "None"
            chain_routing = { PathSegment = { segment = "btc" } }
            "#,
        );

        // When
        let batch = build_batch(config).unwrap();

        // Then
        assert_eq!(
            batch.keys().collect::<Vec<_>>(),
            vec![&ForeignChain::Bitcoin, &ForeignChain::Aptos]
        );
        let aptos = &batch[&ForeignChain::Aptos];
        assert_eq!(aptos.quorum, 2);
        assert_eq!(
            aptos.providers[&ProviderId("alchemy".into())],
            ProviderConfig {
                base_url: "https://aptos-testnet.g.alchemy.com/v2/".into(),
                auth_scheme: AuthScheme::Path {
                    placeholder: "{API_KEY}".into(),
                },
                chain_routing: ChainRouting::Embedded,
            }
        );
        assert_eq!(
            aptos.providers[&ProviderId("geomi".into())].auth_scheme,
            AuthScheme::Header {
                name: "Authorization".into(),
                scheme: Some("Bearer".into()),
            }
        );
        let bitcoin = &batch[&ForeignChain::Bitcoin];
        assert_eq!(bitcoin.quorum, 1);
        assert_eq!(
            bitcoin.providers[&ProviderId("public".into())].chain_routing,
            ChainRouting::PathSegment {
                segment: "btc".into(),
            }
        );
    }

    #[test]
    fn proposal_config__should_reject_config_without_chains() {
        // Given
        let toml = "[chains]";

        // When
        let result = toml::from_str::<ProposalConfig>(toml);

        // Then
        assert_matches!(result, Err(_));
    }

    #[test]
    fn proposal_config__should_reject_chain_without_providers() {
        // Given
        let toml = r#"
            [chains.Bitcoin]
            quorum = 1
            providers = {}
            "#;

        // When
        let result = toml::from_str::<ProposalConfig>(toml);

        // Then
        assert_matches!(result, Err(_));
    }

    #[test]
    fn proposal_config__should_reject_unknown_chain_name() {
        // Given
        let toml = r#"
            [chains.Dogecoin]
            quorum = 1
            "#;

        // When
        let result = toml::from_str::<ProposalConfig>(toml);

        // Then
        assert_matches!(result, Err(_));
    }

    #[rstest]
    #[case(0)]
    #[case(2)]
    fn build_batch__should_reject_quorum_outside_provider_count(#[case] quorum: u64) {
        // Given
        let config = parse(&format!(
            r#"
            [chains.Bitcoin]
            quorum = {quorum}

            [chains.Bitcoin.providers.public]
            base_url = "https://bitcoin-testnet-rpc.publicnode.com"
            auth_scheme = "None"
            chain_routing = "Embedded"
            "#
        ));

        // When
        let result = build_batch(config);

        // Then
        assert_matches!(
            result,
            Err(ConfigError::InvalidQuorum {
                chain: ForeignChain::Bitcoin,
                providers: 1,
                ..
            })
        );
    }

    #[test]
    fn build_batch__should_reject_path_segment_containing_slash() {
        // Given
        let config = parse(
            r#"
            [chains.Ethereum]
            quorum = 1

            [chains.Ethereum.providers.ankr]
            base_url = "https://rpc.ankr.com"
            auth_scheme = "None"
            chain_routing = { PathSegment = { segment = "eth/mainnet" } }
            "#,
        );

        // When
        let result = build_batch(config);

        // Then
        assert_matches!(
            result,
            Err(ConfigError::PathSegmentContainsSlash {
                chain: ForeignChain::Ethereum,
                ..
            })
        );
    }

    #[test]
    fn build_batch__should_reject_query_param_colliding_with_auth() {
        // Given
        let config = parse(
            r#"
            [chains.Ethereum]
            quorum = 1

            [chains.Ethereum.providers.drpc]
            base_url = "https://lb.drpc.org/ogrpc"
            auth_scheme = { Query = { name = "network" } }
            chain_routing = { QueryParam = { name = "network", value = "ethereum" } }
            "#,
        );

        // When
        let result = build_batch(config);

        // Then
        assert_matches!(
            result,
            Err(ConfigError::QueryParamCollidesWithAuth {
                chain: ForeignChain::Ethereum,
                ..
            })
        );
    }
}
