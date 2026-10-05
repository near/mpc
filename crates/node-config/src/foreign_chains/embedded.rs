use anyhow::Context as _;

use super::ForeignChainsConfig;

const MAINNET: &str = include_str!("../../foreign_chains/mainnet.toml");
const TESTNET: &str = include_str!("../../foreign_chains/testnet.toml");

#[derive(Clone, Copy, Debug)]
pub enum RpcNetwork {
    Mainnet,
    Testnet,
}

pub fn embedded_foreign_chains(network: RpcNetwork) -> anyhow::Result<ForeignChainsConfig> {
    let source = match network {
        RpcNetwork::Mainnet => MAINNET,
        RpcNetwork::Testnet => TESTNET,
    };
    toml::from_str(source)
        .with_context(|| format!("failed to parse the embedded {network:?} foreign chain config"))
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::collections::BTreeSet;

    use rstest::rstest;

    use super::*;
    use crate::foreign_chains::{AuthConfig, TokenConfig};

    fn embedded(network: RpcNetwork) -> ForeignChainsConfig {
        embedded_foreign_chains(network).expect("embedded config parsing should succeed")
    }

    #[rstest]
    #[case::mainnet(RpcNetwork::Mainnet, MAINNET)]
    #[case::testnet(RpcNetwork::Testnet, TESTNET)]
    fn embedded_foreign_chains__should_key_only_known_chains(
        #[case] network: RpcNetwork,
        #[case] source: &str,
    ) {
        // Given
        let raw: toml::Table =
            toml::from_str(source).expect("embedded config should be a valid TOML");

        // When
        let config = embedded(network);

        // Then
        let raw_keys: BTreeSet<&str> = raw.keys().map(String::as_str).collect();
        let chains: BTreeSet<&str> = config.iter_chains().map(|(c, _)| c.label()).collect();
        assert_eq!(raw_keys, chains);
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
    }
}
