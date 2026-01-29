//! Foreign chain policy voting module.
//!
//! This module handles automatic voting for foreign chain policy changes.
//! When the node starts, it compares its local configuration to the current
//! contract policy. If different, it votes for the policy derived from
//! its local config.
//!
//! Voting requires unanimous agreement from all participants to update the policy.

use crate::config::ForeignChainConfig;
use crate::indexer::tx_sender::TransactionSender;
use crate::indexer::types::{ChainSendTransactionRequest, ChainVoteForeignChainPolicyArgs};
use mpc_contract::primitives::foreign_chain::ForeignChainPolicy;
use tracing::{info, warn};

/// Validates the local foreign chain configuration against the contract policy.
///
/// Returns Ok(()) if the local config satisfies all requirements of the policy.
/// Returns Err with a descriptive message if validation fails.
///
/// Note: If the policy is empty (no chains configured), validation always passes
/// to allow nodes to start and vote for an initial policy.
pub fn validate_config_against_policy(
    config: &ForeignChainConfig,
    policy: &ForeignChainPolicy,
) -> Result<(), String> {
    // If policy is empty, validation passes (allows nodes to start and vote for initial policy)
    if policy.is_empty() {
        info!("Foreign chain policy is empty, skipping startup validation");
        return Ok(());
    }

    config.validate_against_policy(policy)
}

/// Checks if voting is needed and submits a vote if the local config differs from the contract policy.
///
/// This function:
/// 1. Converts local config to a ForeignChainPolicy
/// 2. Compares it to the current contract policy
/// 3. If different, submits a vote for the local policy
///
/// Returns true if a vote was submitted, false otherwise.
pub async fn vote_if_needed<T: TransactionSender>(
    config: &ForeignChainConfig,
    current_policy: &ForeignChainPolicy,
    tx_sender: &T,
) -> anyhow::Result<bool> {
    let local_policy = config.to_policy();

    // If the policies match, no vote needed
    if &local_policy == current_policy {
        info!("Local foreign chain config matches contract policy, no vote needed");
        return Ok(false);
    }

    // Validate that the local policy is well-formed
    if let Err(e) = local_policy.validate() {
        warn!("Local foreign chain config produces invalid policy: {}", e);
        return Err(anyhow::anyhow!(
            "Local foreign chain config produces invalid policy: {}",
            e
        ));
    }

    info!(
        "Local foreign chain config differs from contract policy, submitting vote. \
         Local policy: {:?}, Contract policy: {:?}",
        local_policy, current_policy
    );

    // Submit the vote
    let args = ChainVoteForeignChainPolicyArgs {
        proposal: local_policy,
    };
    let request = ChainSendTransactionRequest::VoteForeignChainPolicy(args);

    match tx_sender.send(request).await {
        Ok(()) => {
            info!("Submitted foreign chain policy vote");
            Ok(true)
        }
        Err(e) => {
            warn!("Failed to submit foreign chain policy vote: {}", e);
            Err(anyhow::anyhow!("Failed to submit foreign chain policy vote: {}", e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SolanaProviderConfig, SolanaRpcEndpoint};
    use mpc_contract::primitives::foreign_chain::{
        ForeignChain, ForeignChainEntry, RpcProviderName,
    };
    use std::collections::HashMap;

    fn create_config_with_providers(providers: Vec<&str>) -> ForeignChainConfig {
        let mut provider_map = HashMap::new();
        for provider in providers {
            provider_map.insert(
                provider.to_string(),
                SolanaRpcEndpoint {
                    rpc_url: format!("https://{}.example.com", provider),
                    backup_urls: vec![],
                },
            );
        }
        ForeignChainConfig {
            solana: Some(SolanaProviderConfig {
                providers: provider_map,
                timeout_sec: 30,
                max_retries: 3,
            }),
        }
    }

    fn create_policy_with_providers(providers: Vec<&str>) -> ForeignChainPolicy {
        ForeignChainPolicy::new(vec![ForeignChainEntry::new(
            ForeignChain::Solana,
            providers.into_iter().map(RpcProviderName::new).collect(),
        )])
    }

    #[test]
    fn test_validate_empty_policy_passes() {
        let config = create_config_with_providers(vec!["alchemy"]);
        let policy = ForeignChainPolicy::default();

        let result = validate_config_against_policy(&config, &policy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_matching_config_passes() {
        let config = create_config_with_providers(vec!["alchemy"]);
        let policy = create_policy_with_providers(vec!["alchemy"]);

        let result = validate_config_against_policy(&config, &policy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_superset_config_passes() {
        // Config has more providers than required by policy
        let config = create_config_with_providers(vec!["alchemy", "quicknode"]);
        let policy = create_policy_with_providers(vec!["alchemy"]);

        let result = validate_config_against_policy(&config, &policy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_missing_provider_fails() {
        let config = create_config_with_providers(vec!["alchemy"]);
        let policy = create_policy_with_providers(vec!["alchemy", "quicknode"]);

        let result = validate_config_against_policy(&config, &policy);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("quicknode"));
    }

    #[test]
    fn test_validate_missing_chain_config_fails() {
        let config = ForeignChainConfig::default(); // No solana config
        let policy = create_policy_with_providers(vec!["alchemy"]);

        let result = validate_config_against_policy(&config, &policy);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Solana"));
    }
}
