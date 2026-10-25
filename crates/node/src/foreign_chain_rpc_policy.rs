//! Turns a chain's voted whitelist entry into the [`RpcQuorum`] this node's fan-out must meet.

use std::collections::BTreeSet;
use std::num::NonZeroUsize;

use foreign_chain_inspector::RpcQuorum;
use mpc_node_config::ForeignChainConfig;
use mpc_node_config::foreign_chains::provider_identity::ProviderWhitelistMatches;
use near_mpc_contract_interface::types::{ChainEntry, ProviderId};

/// `None` when the conforming local providers cannot reach the voted quorum. Local providers that
/// match the same whitelist provider count once: only the first conforming one by name is
/// whitelisted, the others can still veto a verdict but never stand in for it.
pub(crate) fn rpc_quorum(
    local_chain: &ForeignChainConfig,
    entry: &ChainEntry,
) -> Option<RpcQuorum> {
    let required = usize::try_from(entry.quorum)
        .ok()
        .and_then(NonZeroUsize::new)?;
    let conforming =
        ProviderWhitelistMatches::for_chain(local_chain, entry).whitelist_conforming_providers();
    if !conforming.meets_quorum(required) {
        return None;
    }
    let mut seen_whitelist_ids = BTreeSet::new();
    let whitelisted = conforming
        .iter()
        .filter(|(_, whitelist_id)| seen_whitelist_ids.insert(*whitelist_id))
        .map(|(local_name, _)| ProviderId(local_name.as_str().to_owned()))
        .collect();
    Some(RpcQuorum {
        required,
        whitelisted,
    })
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;

    use mpc_node_config::foreign_chains::RpcProviderName;
    use mpc_node_config::{AuthConfig, ForeignChainProviderConfig};
    use near_mpc_contract_interface::types::{AuthScheme, ChainRouting, ProviderConfig};

    use super::*;

    const WHITELIST: [(&str, &str); 2] = [
        ("alchemy", "https://eth.alchemy.com/"),
        ("infura", "https://eth.infura.io/"),
    ];

    fn local(providers: &[(&str, &str)]) -> ForeignChainConfig {
        let providers: BTreeMap<RpcProviderName, ForeignChainProviderConfig> = providers
            .iter()
            .map(|(name, rpc_url)| {
                (
                    RpcProviderName::from(name.to_string()),
                    ForeignChainProviderConfig {
                        rpc_url: rpc_url.to_string(),
                        auth: AuthConfig::None,
                    },
                )
            })
            .collect();
        ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers: providers.try_into().unwrap(),
            expected_network_fingerprint: None,
        }
    }

    fn entry(providers: &[(&str, &str)], quorum: u64) -> ChainEntry {
        let providers: BTreeMap<ProviderId, ProviderConfig> = providers
            .iter()
            .map(|(id, base_url)| {
                (
                    ProviderId(id.to_string()),
                    ProviderConfig {
                        base_url: base_url.to_string(),
                        auth_scheme: AuthScheme::None,
                        chain_routing: ChainRouting::Embedded,
                    },
                )
            })
            .collect();
        ChainEntry {
            providers: providers.try_into().unwrap(),
            quorum,
        }
    }

    fn ids(names: &[&str]) -> BTreeSet<ProviderId> {
        names
            .iter()
            .map(|name| ProviderId(name.to_string()))
            .collect()
    }

    #[test]
    fn rpc_quorum__should_whitelist_the_local_names_of_the_conforming_providers() {
        // Given: two conforming providers and one whose host is not whitelisted.
        let local = local(&[
            ("my-alchemy", "https://eth.alchemy.com/"),
            ("my-infura", "https://eth.infura.io/"),
            ("my-own-node", "https://rpc.example.org/"),
        ]);

        // When
        let quorum = rpc_quorum(&local, &entry(&WHITELIST, 2));

        // Then
        assert_eq!(
            quorum,
            Some(RpcQuorum {
                required: NonZeroUsize::new(2).unwrap(),
                whitelisted: ids(&["my-alchemy", "my-infura"]),
            })
        );
    }

    #[test]
    fn rpc_quorum__should_be_none_when_the_conforming_providers_are_below_the_quorum() {
        // Given
        let local = local(&[("my-alchemy", "https://eth.alchemy.com/")]);

        // When
        let quorum = rpc_quorum(&local, &entry(&WHITELIST, 2));

        // Then
        assert_eq!(quorum, None);
    }

    #[test]
    fn rpc_quorum__should_count_providers_matching_the_same_whitelist_provider_once() {
        // Given: two local providers behind one whitelisted host, quorum two.
        let local = local(&[
            ("alchemy-a", "https://eth.alchemy.com/"),
            ("alchemy-b", "https://eth.alchemy.com/"),
        ]);

        // When
        let quorum = rpc_quorum(&local, &entry(&WHITELIST, 2));

        // Then
        assert_eq!(quorum, None);
    }

    #[test]
    fn rpc_quorum__should_whitelist_only_the_first_of_the_providers_matching_one_whitelist_provider()
     {
        // Given
        let local = local(&[
            ("alchemy-a", "https://eth.alchemy.com/"),
            ("alchemy-b", "https://eth.alchemy.com/"),
        ]);

        // When
        let quorum = rpc_quorum(&local, &entry(&WHITELIST, 1));

        // Then
        assert_eq!(
            quorum.map(|quorum| quorum.whitelisted),
            Some(ids(&["alchemy-a"]))
        );
    }

    #[test]
    fn rpc_quorum__should_not_count_a_misconfigured_provider() {
        // Given: the whitelisted host on a port the whitelist does not name.
        let local = local(&[("my-alchemy", "https://eth.alchemy.com:8545/")]);

        // When
        let quorum = rpc_quorum(&local, &entry(&WHITELIST, 1));

        // Then
        assert_eq!(quorum, None);
    }

    #[test]
    fn rpc_quorum__should_be_none_for_a_zero_quorum() {
        // Given
        let local = local(&[("my-alchemy", "https://eth.alchemy.com/")]);

        // When
        let quorum = rpc_quorum(&local, &entry(&WHITELIST, 0));

        // Then
        assert_eq!(quorum, None);
    }
}
