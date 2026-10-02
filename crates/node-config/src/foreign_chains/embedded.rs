use std::fmt;

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

use super::ForeignChainsConfig;
use crate::ChainId;

const MAINNET: &str = include_str!("../../foreign_chains/mainnet.toml");
const TESTNET: &str = include_str!("../../foreign_chains/testnet.toml");

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RpcNetwork {
    Mainnet,
    Testnet,
}

impl RpcNetwork {
    pub fn chain_id(self) -> ChainId {
        match self {
            Self::Mainnet => ChainId::Mainnet,
            Self::Testnet => ChainId::Testnet,
        }
    }
}

impl fmt::Display for RpcNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.chain_id().fmt(f)
    }
}

pub(super) fn embedded_foreign_chains(network: RpcNetwork) -> anyhow::Result<ForeignChainsConfig> {
    let source = match network {
        RpcNetwork::Mainnet => MAINNET,
        RpcNetwork::Testnet => TESTNET,
    };
    toml::from_str(source)
        .with_context(|| format!("failed to parse the embedded {network} foreign chain config"))
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::collections::BTreeSet;

    use rstest::rstest;

    use super::*;
    use crate::foreign_chains::{
        AuthConfig, ProviderCredentials, SLUG_PLACEHOLDER, TokenConfig,
        resolve::resolve_foreign_chains,
    };

    fn embedded(network: RpcNetwork) -> ForeignChainsConfig {
        embedded_foreign_chains(network).expect("embedded config should parse")
    }

    #[rstest]
    #[case::mainnet(RpcNetwork::Mainnet, MAINNET)]
    #[case::testnet(RpcNetwork::Testnet, TESTNET)]
    fn embedded_foreign_chains__should_key_only_known_chains(
        #[case] network: RpcNetwork,
        #[case] source: &str,
    ) {
        // Given
        let raw: toml::Table = toml::from_str(source).expect("embedded config should be TOML");

        // When
        let config = embedded(network);

        // Then: an unknown or misspelled chain key would be silently dropped by serde.
        let raw_keys: BTreeSet<&str> = raw.keys().map(String::as_str).collect();
        let parsed_keys: BTreeSet<&str> = config
            .iter_chains()
            .map(|(chain, _)| chain.label())
            .collect();
        assert_eq!(raw_keys, parsed_keys);
    }

    #[rstest]
    #[case::mainnet(RpcNetwork::Mainnet)]
    #[case::testnet(RpcNetwork::Testnet)]
    fn embedded_foreign_chains__should_carry_no_secrets(#[case] network: RpcNetwork) {
        // Given
        let config = embedded(network);

        // When
        let tokens: Vec<_> = config
            .iter_chains()
            .flat_map(|(_, chain)| chain.providers.values())
            .filter_map(|provider| match &provider.auth {
                AuthConfig::None => None,
                AuthConfig::Header { token, .. }
                | AuthConfig::Path { token, .. }
                | AuthConfig::Query { token, .. } => Some(token),
            })
            .collect();

        // Then
        assert!(!tokens.is_empty());
        for token in tokens {
            assert_eq!(token, &TokenConfig::Val { val: String::new() });
        }
        assert!(config.credentials.is_empty());
        assert_eq!(config.rpc_network, None);
    }

    #[rstest]
    #[case::mainnet(RpcNetwork::Mainnet)]
    #[case::testnet(RpcNetwork::Testnet)]
    fn embedded_foreign_chains__should_resolve_to_a_valid_config_with_every_provider_enabled(
        #[case] network: RpcNetwork,
    ) {
        // Given
        let embedded = embedded(network);
        let provider_names: BTreeSet<_> = embedded
            .iter_chains()
            .flat_map(|(_, chain)| chain.providers.keys().cloned())
            .collect();
        let node_config = ForeignChainsConfig {
            credentials: provider_names
                .into_iter()
                .map(|name| {
                    let credentials = ProviderCredentials {
                        api_key: TokenConfig::Val {
                            val: "dummy-key".to_string(),
                        },
                        slug: Some("dummy-slug".to_string()),
                    };
                    (name, credentials)
                })
                .collect(),
            ..Default::default()
        };

        // When
        let resolved = resolve_foreign_chains(&node_config, Some(&embedded))
            .expect("embedded config should resolve");

        // Then
        assert_eq!(
            resolved.config.iter_chains().count(),
            embedded.iter_chains().count()
        );
        for (chain, resolved_chain) in resolved.config.iter_chains() {
            let embedded_chain = embedded
                .iter_chains()
                .find_map(|(c, config)| (c == chain).then_some(config))
                .expect("resolved chain should be embedded");
            assert_eq!(
                resolved_chain.providers.len(),
                embedded_chain.providers.len()
            );
            for provider in resolved_chain.providers.values() {
                assert!(!provider.rpc_url.contains(SLUG_PLACEHOLDER));
            }
        }
    }
}
