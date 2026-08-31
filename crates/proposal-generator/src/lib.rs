//! Builds the foreign chain whitelist payload from TOML file.

use anyhow::Context as _;
use mpc_contract::errors::ChainEntryValidationError;
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types::{ChainEntry, ForeignChain};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ProposalConfig {
    pub chains: NonEmptyBTreeMap<ForeignChain, ChainEntry>,
}

/// A [`ChainEntryValidationError`] tagged with the chain it occurred on.
#[derive(Debug, thiserror::Error)]
#[error("chain {chain:?}: {source}")]
pub struct ConfigError {
    pub chain: ForeignChain,
    pub source: ChainEntryValidationError,
}

/// Validates each entry with the contract's own rules
/// ([`mpc_contract::foreign_chain_rpc::ChainEntry`]), then borsh-encodes the
/// `vote_update_foreign_chain_providers` argument.
pub fn build_payload(config: ProposalConfig) -> anyhow::Result<Vec<u8>> {
    for (chain, entry) in config.chains.iter() {
        mpc_contract::foreign_chain_rpc::ChainEntry::try_from(entry.clone()).map_err(|source| {
            ConfigError {
                chain: *chain,
                source,
            }
        })?;
    }
    borsh::to_vec(&config.chains)
        .with_context(|| format!("failed to serialize chains {:?}", config.chains))
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use near_mpc_contract_interface::types::{
        AuthScheme, ChainRouting, ProviderConfig, ProviderId,
    };
    use rstest::rstest;

    fn parse(toml: &str) -> ProposalConfig {
        toml::from_str(toml).unwrap()
    }

    #[test]
    fn build_payload__should_map_config_to_chain_entries() {
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
        let payload = build_payload(config).unwrap();

        // Then
        let votes: NonEmptyBTreeMap<ForeignChain, ChainEntry> =
            borsh::from_slice(&payload).unwrap();
        assert_eq!(
            votes.keys().collect::<Vec<_>>(),
            vec![&ForeignChain::Bitcoin, &ForeignChain::Aptos]
        );
        let aptos = &votes[&ForeignChain::Aptos];
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
        let bitcoin = &votes[&ForeignChain::Bitcoin];
        assert_eq!(bitcoin.quorum, 1);
        assert_eq!(
            bitcoin.providers[&ProviderId("public".into())].chain_routing,
            ChainRouting::PathSegment {
                segment: "btc".into(),
            }
        );
    }

    #[rstest]
    #[case::testnet(include_str!("../proposals/testnet-rpc-whitelist.toml"))]
    #[case::mainnet(include_str!("../proposals/mainnet-rpc-whitelist.toml"))]
    fn rpc_whitelist_proposals__should_be_valid(#[case] fixture: &str) {
        // Given
        let config: ProposalConfig = toml::from_str(fixture).unwrap();

        // When
        let payload = build_payload(config).unwrap();

        // Then
        let votes: NonEmptyBTreeMap<ForeignChain, ChainEntry> =
            borsh::from_slice(&payload).unwrap();
        assert_eq!(
            votes.keys().copied().collect::<Vec<_>>(),
            vec![
                ForeignChain::Bitcoin,
                ForeignChain::Abstract,
                ForeignChain::Starknet,
                ForeignChain::Aptos,
                ForeignChain::Sui,
            ]
        );
    }

    #[rstest]
    #[case::no_chains("[chains]")]
    #[case::chain_without_providers(
        r#"
        [chains.Bitcoin]
        quorum = 1
        providers = {}
        "#
    )]
    #[case::unknown_chain_name(
        r#"
        [chains.Dogecoin]
        quorum = 1
        "#
    )]
    fn proposal_config__should_reject_malformed_config(#[case] toml: &str) {
        // When
        let result = toml::from_str::<ProposalConfig>(toml);

        // Then
        assert_matches!(result, Err(_));
    }

    #[rstest]
    #[case::zero_quorum(
        r#"
        [chains.Bitcoin]
        quorum = 0

        [chains.Bitcoin.providers.public]
        base_url = "https://bitcoin-testnet-rpc.publicnode.com"
        auth_scheme = "None"
        chain_routing = "Embedded"
        "#,
        ForeignChain::Bitcoin,
        ChainEntryValidationError::ZeroQuorum
    )]
    #[case::quorum_exceeds_providers(
        r#"
        [chains.Bitcoin]
        quorum = 2

        [chains.Bitcoin.providers.public]
        base_url = "https://bitcoin-testnet-rpc.publicnode.com"
        auth_scheme = "None"
        chain_routing = "Embedded"
        "#,
        ForeignChain::Bitcoin,
        ChainEntryValidationError::QuorumExceedsProviders { quorum: 2, providers_len: 1 }
    )]
    #[case::path_segment_containing_slash(
        r#"
        [chains.Ethereum]
        quorum = 1

        [chains.Ethereum.providers.ankr]
        base_url = "https://rpc.ankr.com"
        auth_scheme = "None"
        chain_routing = { PathSegment = { segment = "eth/mainnet" } }
        "#,
        ForeignChain::Ethereum,
        ChainEntryValidationError::PathSegmentContainsSlash { provider_id: "ankr".into() }
    )]
    #[case::query_param_colliding_with_auth(
        r#"
        [chains.Ethereum]
        quorum = 1

        [chains.Ethereum.providers.drpc]
        base_url = "https://lb.drpc.org/ogrpc"
        auth_scheme = { Query = { name = "network" } }
        chain_routing = { QueryParam = { name = "network", value = "ethereum" } }
        "#,
        ForeignChain::Ethereum,
        ChainEntryValidationError::QueryParamCollidesWithAuth {
            provider_id: "drpc".into(),
            name: "network".into(),
        }
    )]
    fn build_payload__should_reject_entry_violating_contract_rules(
        #[case] toml: &str,
        #[case] chain: ForeignChain,
        #[case] expected: ChainEntryValidationError,
    ) {
        // Given
        let config = parse(toml);

        // When
        let result = build_payload(config);

        // Then
        let err = result.unwrap_err().downcast::<ConfigError>().unwrap();
        assert_eq!(err.chain, chain);
        assert_eq!(err.source, expected);
    }
}
