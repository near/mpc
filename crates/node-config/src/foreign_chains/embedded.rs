use std::fmt;

use serde::{Deserialize, Serialize};

use super::ForeignChainsConfig;
use crate::ChainId;

const MAINNET: &str = include_str!("../../foreign_chains/mainnet.toml");
const TESTNET: &str = include_str!("../../foreign_chains/testnet.toml");

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RpcPreset {
    Mainnet,
    Testnet,
}

impl RpcPreset {
    /// Whether a node on `chain_id` may use this preset. Development networks accept any preset.
    pub fn supports(self, chain_id: &ChainId) -> bool {
        match (self, chain_id) {
            (Self::Mainnet, ChainId::Mainnet) | (Self::Testnet, ChainId::Testnet) => true,
            (Self::Mainnet, ChainId::Testnet) | (Self::Testnet, ChainId::Mainnet) => false,
            (_, ChainId::Localnet | ChainId::Sandbox | ChainId::Custom(_)) => true,
        }
    }
}

impl fmt::Display for RpcPreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RpcPreset::Mainnet => "mainnet",
            RpcPreset::Testnet => "testnet",
        })
    }
}

pub(super) fn embedded_foreign_chains(
    rpc_preset: RpcPreset,
) -> Result<ForeignChainsConfig, toml::de::Error> {
    let source = match rpc_preset {
        RpcPreset::Mainnet => MAINNET,
        RpcPreset::Testnet => TESTNET,
    };
    toml::from_str(source)
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::collections::BTreeSet;

    use rstest::rstest;

    use super::*;
    use crate::foreign_chains::{
        AuthConfig, ProviderCredentials, SLUG_PLACEHOLDER, TokenConfig, resolve_with_embedded,
    };

    #[rstest]
    #[case::mainnet(RpcPreset::Mainnet)]
    #[case::testnet(RpcPreset::Testnet)]
    fn rpc_preset_display__should_match_its_config_name(#[case] rpc_preset: RpcPreset) {
        // When
        let config_name = toml::Value::try_from(rpc_preset).expect("preset should serialize");

        // Then
        assert_eq!(config_name.as_str(), Some(rpc_preset.to_string().as_str()));
    }

    #[rstest]
    #[case::mainnet_on_mainnet(RpcPreset::Mainnet, ChainId::Mainnet, true)]
    #[case::testnet_on_testnet(RpcPreset::Testnet, ChainId::Testnet, true)]
    #[case::mainnet_on_testnet(RpcPreset::Mainnet, ChainId::Testnet, false)]
    #[case::testnet_on_mainnet(RpcPreset::Testnet, ChainId::Mainnet, false)]
    #[case::mainnet_on_localnet(RpcPreset::Mainnet, ChainId::Localnet, true)]
    #[case::testnet_on_localnet(RpcPreset::Testnet, ChainId::Localnet, true)]
    #[case::mainnet_on_sandbox(RpcPreset::Mainnet, ChainId::Sandbox, true)]
    #[case::testnet_on_custom(RpcPreset::Testnet, ChainId::Custom("my-chain".to_string()), true)]
    fn rpc_preset_supports__should_accept_own_production_network_and_any_development_network(
        #[case] rpc_preset: RpcPreset,
        #[case] chain_id: ChainId,
        #[case] expected: bool,
    ) {
        // When
        let supported = rpc_preset.supports(&chain_id);

        // Then
        assert_eq!(supported, expected);
    }

    fn embedded(rpc_preset: RpcPreset) -> ForeignChainsConfig {
        embedded_foreign_chains(rpc_preset).expect("embedded config parsing should succeed")
    }

    #[rstest]
    #[case::mainnet(RpcPreset::Mainnet, MAINNET)]
    #[case::testnet(RpcPreset::Testnet, TESTNET)]
    fn embedded_foreign_chains__should_key_only_known_chains(
        #[case] rpc_preset: RpcPreset,
        #[case] source: &str,
    ) {
        // Given
        let raw: toml::Table =
            toml::from_str(source).expect("embedded config should be a valid TOML");

        // When
        let config = embedded(rpc_preset);

        // Then
        let raw_keys: BTreeSet<&str> = raw.keys().map(String::as_str).collect();
        let chains: BTreeSet<&str> = config.iter_chains().map(|(c, _)| c.label()).collect();
        assert_eq!(raw_keys, chains);
    }

    #[rstest]
    #[case::mainnet(RpcPreset::Mainnet)]
    #[case::testnet(RpcPreset::Testnet)]
    fn embedded_foreign_chains__should_carry_no_secrets(#[case] rpc_preset: RpcPreset) {
        // Given
        let config = embedded(rpc_preset);

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
        assert_eq!(config.rpc_preset, None);
    }

    #[rstest]
    #[case::mainnet(RpcPreset::Mainnet)]
    #[case::testnet(RpcPreset::Testnet)]
    fn resolve_with_embedded__should_enable_every_preset_provider_given_credentials(
        #[case] rpc_preset: RpcPreset,
    ) {
        // Given
        let embedded = embedded(rpc_preset);
        let provider_names: BTreeSet<_> = embedded
            .iter_chains()
            .flat_map(|(_, chain)| chain.providers.keys().cloned())
            .collect();
        let node_config = ForeignChainsConfig {
            rpc_preset: Some(rpc_preset),
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
        let resolved = resolve_with_embedded(&node_config).expect("preset should resolve");

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
