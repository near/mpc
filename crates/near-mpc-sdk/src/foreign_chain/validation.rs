//! Validation of foreign-chain RPC whitelist proposals, shared by the contract
//! and off-chain tooling so both sides enforce the same rules.

use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types::{
    self as dtos, AuthScheme, ChainRouting, ProviderConfig, ProviderId,
};

/// Reasons a [`dtos::ChainEntry`] proposal fails [`validate_chain_entry`].
/// [`NonEmptyBTreeMap`] already enforces non-empty + unique-[`ProviderId`] at
/// deserialize time, so those cases are absent here.
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum ChainEntryValidationError {
    #[error("ChainEntry.quorum must be >= 1")]
    ZeroQuorum,
    #[error(
        "ChainEntry.quorum ({quorum}) exceeds providers.len() ({providers_len}) — RPC response quorum is unreachable"
    )]
    QuorumExceedsProviders { quorum: u64, providers_len: u64 },
    #[error(
        "ChainRouting::PathSegment.segment for provider_id {provider_id:?} must not contain '/'"
    )]
    PathSegmentContainsSlash { provider_id: String },
    #[error(
        "ChainRouting::QueryParam.name collides with AuthScheme::Query.name {name:?} for provider_id {provider_id:?}"
    )]
    QueryParamCollidesWithAuth { provider_id: String, name: String },
}

/// Witness that a [`dtos::ChainEntry`] passed [`validate_chain_entry`]; convert
/// back via [`From<ValidatedChainEntry>`] to reach the fields.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ValidatedChainEntry {
    providers: NonEmptyBTreeMap<ProviderId, ProviderConfig>,
    quorum: u64,
}

impl From<ValidatedChainEntry> for dtos::ChainEntry {
    fn from(entry: ValidatedChainEntry) -> Self {
        dtos::ChainEntry {
            providers: entry.providers,
            quorum: entry.quorum,
        }
    }
}

/// Checks the rules the contract enforces before a proposed [`dtos::ChainEntry`]
/// can apply; see [`ChainEntryValidationError`].
pub fn validate_chain_entry(
    entry: dtos::ChainEntry,
) -> Result<ValidatedChainEntry, ChainEntryValidationError> {
    let dtos::ChainEntry { providers, quorum } = entry;
    if quorum == 0 {
        return Err(ChainEntryValidationError::ZeroQuorum);
    }
    let providers_len =
        u64::try_from(providers.len()).expect("usize is at most 64 bits on all supported targets");
    if quorum > providers_len {
        return Err(ChainEntryValidationError::QuorumExceedsProviders {
            quorum,
            providers_len,
        });
    }
    for (id, config) in providers.iter() {
        if let ChainRouting::PathSegment { segment } = &config.chain_routing
            && segment.contains('/')
        {
            return Err(ChainEntryValidationError::PathSegmentContainsSlash {
                provider_id: id.0.clone(),
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
            return Err(ChainEntryValidationError::QueryParamCollidesWithAuth {
                provider_id: id.0.clone(),
                name: auth_name.clone(),
            });
        }
    }
    Ok(ValidatedChainEntry { providers, quorum })
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use std::collections::BTreeMap;

    fn provider(id: &str) -> (ProviderId, ProviderConfig) {
        (
            ProviderId(id.to_string()),
            ProviderConfig {
                base_url: format!("https://{id}.example.com"),
                auth_scheme: AuthScheme::None,
                chain_routing: ChainRouting::Embedded,
            },
        )
    }

    /// Build a [`dtos::ChainEntry`] from a list of provider id stubs and a quorum.
    fn chain_entry(ids: &[&str], quorum: u64) -> dtos::ChainEntry {
        let providers: BTreeMap<ProviderId, ProviderConfig> =
            ids.iter().map(|id| provider(id)).collect();
        dtos::ChainEntry {
            providers: NonEmptyBTreeMap::try_from(providers)
                .expect("test setup: providers must be non-empty"),
            quorum,
        }
    }

    #[test]
    fn validate_chain_entry__should_reject_zero_quorum() {
        // Given
        let entry = chain_entry(&["alchemy"], 0);

        // When
        let err = validate_chain_entry(entry).unwrap_err();

        // Then
        assert_matches!(err, ChainEntryValidationError::ZeroQuorum);
    }

    #[test]
    fn validate_chain_entry__should_reject_quorum_exceeding_providers_count() {
        // Given
        let entry = chain_entry(&["alchemy"], 2);

        // When
        let err = validate_chain_entry(entry).unwrap_err();

        // Then
        assert_matches!(
            err,
            ChainEntryValidationError::QuorumExceedsProviders {
                quorum: 2,
                providers_len: 1,
            }
        );
    }

    #[test]
    fn validate_chain_entry__should_reject_path_segment_containing_slash() {
        // Given
        let entry = dtos::ChainEntry {
            providers: NonEmptyBTreeMap::new(
                ProviderId("ankr".to_string()),
                ProviderConfig {
                    base_url: "https://rpc.ankr.com".to_string(),
                    auth_scheme: AuthScheme::None,
                    chain_routing: ChainRouting::PathSegment {
                        segment: "eth/sepolia".to_string(),
                    },
                },
            ),
            quorum: 1,
        };

        // When
        let err = validate_chain_entry(entry).unwrap_err();

        // Then
        assert_matches!(
            err,
            ChainEntryValidationError::PathSegmentContainsSlash { provider_id } if provider_id == "ankr"
        );
    }

    #[test]
    fn validate_chain_entry__should_reject_query_param_colliding_with_auth_query() {
        // Given
        let entry = dtos::ChainEntry {
            providers: NonEmptyBTreeMap::new(
                ProviderId("drpc".to_string()),
                ProviderConfig {
                    base_url: "https://lb.drpc.org/ogrpc".to_string(),
                    auth_scheme: AuthScheme::Query {
                        name: "key".to_string(),
                    },
                    chain_routing: ChainRouting::QueryParam {
                        name: "key".to_string(),
                        value: "ethereum".to_string(),
                    },
                },
            ),
            quorum: 1,
        };

        // When
        let err = validate_chain_entry(entry).unwrap_err();

        // Then
        assert_matches!(
            err,
            ChainEntryValidationError::QueryParamCollidesWithAuth { provider_id, name }
                if provider_id == "drpc" && name == "key"
        );
    }

    #[test]
    fn validate_chain_entry__should_accept_well_formed_entry() {
        // Given
        let entry = chain_entry(&["alchemy", "ankr"], 2);

        // When
        let validated = validate_chain_entry(entry.clone()).unwrap();

        // Then
        assert_eq!(dtos::ChainEntry::from(validated), entry);
    }
}
