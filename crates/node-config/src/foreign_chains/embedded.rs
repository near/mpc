use std::fmt;

use anyhow::Context as _;
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
    pub fn chain_id(self) -> ChainId {
        match self {
            RpcPreset::Mainnet => ChainId::Mainnet,
            RpcPreset::Testnet => ChainId::Testnet,
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

pub fn embedded_foreign_chains(rpc_preset: RpcPreset) -> anyhow::Result<ForeignChainsConfig> {
    let source = match rpc_preset {
        RpcPreset::Mainnet => MAINNET,
        RpcPreset::Testnet => TESTNET,
    };
    toml::from_str(source)
        .with_context(|| format!("failed to parse the embedded {rpc_preset} foreign chain config"))
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::collections::BTreeSet;

    use rstest::rstest;

    use super::*;
    use crate::foreign_chains::{AuthConfig, TokenConfig};

    #[rstest]
    #[case::mainnet(RpcPreset::Mainnet)]
    #[case::testnet(RpcPreset::Testnet)]
    fn rpc_preset_display__should_match_its_config_name(#[case] rpc_preset: RpcPreset) {
        // When
        let config_name = toml::Value::try_from(rpc_preset).expect("preset should serialize");

        // Then
        assert_eq!(config_name.as_str(), Some(rpc_preset.to_string().as_str()));
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
}
