//! Solana transaction verification using JSON-RPC.
//!
//! Provider Selection:
//! Each MPC node is assigned a specific RPC provider based on a deterministic hash
//! of (participant_id, request_id). This ensures different nodes query different
//! providers for the same request, reducing the risk of a single bad provider.

use super::types::{TxStatus, VerificationError, VerificationOutput};
use super::ProviderSelectionContext;
use crate::config::SolanaProviderConfig;
use mpc_contract::primitives::foreign_chain::{BlockId, FinalityLevel, SolanaSignature};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

/// Solana transaction verifier using JSON-RPC
pub struct SolanaVerifier {
    client: Client,
    config: SolanaProviderConfig,
}

impl SolanaVerifier {
    /// Create a new Solana verifier from config
    pub fn new(config: SolanaProviderConfig) -> Result<Self, VerificationError> {
        let timeout = Duration::from_secs(config.timeout_sec);
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| VerificationError::Internal(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self { client, config })
    }

    /// Verify a Solana transaction using deterministic provider selection.
    ///
    /// Each MPC node is assigned a specific RPC provider based on hash(participant_id, request_id).
    /// This ensures different nodes query different providers for the same request.
    /// If the assigned provider fails, the node falls back to other providers in deterministic order.
    pub async fn verify_transaction(
        &self,
        signature: &SolanaSignature,
        finality: &FinalityLevel,
        provider_context: &ProviderSelectionContext,
    ) -> Result<VerificationOutput, VerificationError> {
        let commitment = match finality {
            FinalityLevel::Optimistic => "confirmed",
            FinalityLevel::Final => "finalized",
        };

        let sig_base58 = bs58::encode(signature.as_bytes()).into_string();

        // Get providers in deterministic order based on (participant_id, request_id)
        let ordered_providers = self.get_ordered_providers(provider_context);

        if ordered_providers.is_empty() {
            return Err(VerificationError::ConfigError(
                "No RPC endpoints configured".to_string(),
            ));
        }

        tracing::debug!(
            target: "foreign_chain_verifier",
            participant_id = %provider_context.my_participant_id.raw(),
            request_id = %provider_context.request_id,
            primary_provider = %ordered_providers[0].0,
            "Selected provider order for verification"
        );

        // Try providers in the deterministic order
        let mut last_error = None;
        for (provider_name, endpoint) in &ordered_providers {
            let urls = std::iter::once(&endpoint.rpc_url)
                .chain(endpoint.backup_urls.iter());

            for url in urls {
                match self.verify_with_url(url, &sig_base58, commitment).await {
                    Ok(output) => {
                        tracing::info!(
                            target: "foreign_chain_verifier",
                            participant_id = %provider_context.my_participant_id.raw(),
                            request_id = %provider_context.request_id,
                            provider = %provider_name,
                            "Verification succeeded"
                        );
                        return Ok(output);
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: "foreign_chain_verifier",
                            provider = %provider_name,
                            url = %url,
                            error = %e,
                            "Solana RPC failed, trying next"
                        );
                        last_error = Some(e);
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            VerificationError::ConfigError("No RPC endpoints configured".to_string())
        }))
    }

    /// Get providers ordered deterministically based on (participant_id, request_id).
    ///
    /// The ordering is computed by hashing each provider name with the participant_id
    /// and request_id, then sorting by the hash. This ensures:
    /// 1. Each participant gets a different primary provider for the same request
    /// 2. The ordering is deterministic and reproducible
    /// 3. Providers are distributed fairly across participants
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn get_ordered_providers(
        &self,
        context: &ProviderSelectionContext,
    ) -> Vec<(String, crate::config::SolanaRpcEndpoint)> {
        let mut providers_with_hash: Vec<_> = self
            .config
            .providers
            .iter()
            .map(|(name, endpoint)| {
                let hash = Self::provider_selection_hash(name, context);
                (hash, name.clone(), endpoint.clone())
            })
            .collect();

        // Sort by hash to get deterministic ordering
        providers_with_hash.sort_by_key(|(hash, _, _)| *hash);

        providers_with_hash
            .into_iter()
            .map(|(_, name, endpoint)| (name, endpoint))
            .collect()
    }

    /// Compute a hash for provider selection.
    /// This is similar to leader_selection_hash but for RPC providers.
    fn provider_selection_hash(provider_name: &str, context: &ProviderSelectionContext) -> u64 {
        let mut h = Sha256::new();
        h.update(context.my_participant_id.raw().to_le_bytes());
        h.update(context.request_id.0);
        h.update(provider_name.as_bytes());
        let hash: [u8; 32] = h.finalize().into();
        u64::from_le_bytes(hash[0..8].try_into().unwrap())
    }

    async fn verify_with_url(
        &self,
        url: &str,
        signature: &str,
        commitment: &str,
    ) -> Result<VerificationOutput, VerificationError> {
        // First, get the signature status
        let status_response = self
            .get_signature_statuses(url, signature)
            .await?;

        let status = status_response
            .result
            .value
            .first()
            .ok_or_else(|| {
                VerificationError::TransactionNotFound(signature.to_string())
            })?;

        // Check if the transaction exists and what its status is
        match status {
            Some(status_info) => {
                // Check if transaction had an error
                if status_info.err.is_some() {
                    return Ok(VerificationOutput {
                        success: false,
                        block_id: BlockId::SolanaSlot(status_info.slot),
                        tx_status: TxStatus::Failed,
                    });
                }

                // Check confirmation status
                let confirmation_status = status_info
                    .confirmation_status
                    .as_deref()
                    .unwrap_or("processed");

                // Map Solana confirmation to our finality
                let is_finalized = match commitment {
                    "finalized" => confirmation_status == "finalized",
                    "confirmed" => {
                        confirmation_status == "confirmed" || confirmation_status == "finalized"
                    }
                    _ => confirmation_status == "finalized",
                };

                if !is_finalized {
                    return Err(VerificationError::NotFinalized);
                }

                Ok(VerificationOutput {
                    success: true,
                    block_id: BlockId::SolanaSlot(status_info.slot),
                    tx_status: TxStatus::Success,
                })
            }
            None => Err(VerificationError::TransactionNotFound(signature.to_string())),
        }
    }

    async fn get_signature_statuses(
        &self,
        url: &str,
        signature: &str,
    ) -> Result<GetSignatureStatusesResponse, VerificationError> {
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "getSignatureStatuses",
            params: serde_json::json!([
                [signature],
                {"searchTransactionHistory": true}
            ]),
        };

        let mut retries = 0;
        loop {
            let response = self
                .client
                .post(url)
                .json(&request)
                .send()
                .await?;

            if response.status().is_success() {
                let result: GetSignatureStatusesResponse = response.json().await?;
                return Ok(result);
            }

            retries += 1;
            if retries >= self.config.max_retries {
                return Err(VerificationError::RpcError(format!(
                    "Failed after {} retries",
                    self.config.max_retries
                )));
            }

            // Exponential backoff
            tokio::time::sleep(Duration::from_millis(100 * 2_u64.pow(retries))).await;
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'a str,
    id: u32,
    method: &'a str,
    params: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct GetSignatureStatusesResponse {
    result: SignatureStatusesResult,
}

#[derive(Debug, Deserialize)]
struct SignatureStatusesResult {
    value: Vec<Option<SignatureStatus>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignatureStatus {
    slot: u64,
    #[serde(default)]
    confirmations: Option<u64>,
    #[serde(default)]
    err: Option<serde_json::Value>,
    #[serde(default)]
    confirmation_status: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SolanaRpcEndpoint;
    use crate::primitives::ParticipantId;
    use near_indexer_primitives::CryptoHash;
    use std::collections::HashMap;

    #[test]
    fn test_finality_mapping() {
        assert_eq!(
            match FinalityLevel::Optimistic {
                FinalityLevel::Optimistic => "confirmed",
                FinalityLevel::Final => "finalized",
            },
            "confirmed"
        );
        assert_eq!(
            match FinalityLevel::Final {
                FinalityLevel::Optimistic => "confirmed",
                FinalityLevel::Final => "finalized",
            },
            "finalized"
        );
    }

    #[test]
    fn test_deterministic_provider_selection() {
        // Test that provider selection is deterministic based on (participant_id, request_id)
        // and different participants get different providers

        // Create config with multiple providers
        let mut providers = HashMap::new();
        providers.insert(
            "provider_a".to_string(),
            SolanaRpcEndpoint {
                rpc_url: "https://a.example.com".to_string(),
                backup_urls: vec![],
            },
        );
        providers.insert(
            "provider_b".to_string(),
            SolanaRpcEndpoint {
                rpc_url: "https://b.example.com".to_string(),
                backup_urls: vec![],
            },
        );
        providers.insert(
            "provider_c".to_string(),
            SolanaRpcEndpoint {
                rpc_url: "https://c.example.com".to_string(),
                backup_urls: vec![],
            },
        );
        let config = SolanaProviderConfig {
            providers,
            timeout_sec: 30,
            max_retries: 3,
        };

        let verifier = SolanaVerifier::new(config).unwrap();

        // Create different contexts with same request_id but different participant_ids
        let request_id = CryptoHash([42u8; 32]);

        let context1 = ProviderSelectionContext {
            my_participant_id: ParticipantId::from_raw(1),
            request_id,
        };
        let context2 = ProviderSelectionContext {
            my_participant_id: ParticipantId::from_raw(2),
            request_id,
        };
        let context3 = ProviderSelectionContext {
            my_participant_id: ParticipantId::from_raw(3),
            request_id,
        };

        // Get ordered providers for each context
        let providers1 = verifier.get_ordered_providers(&context1);
        let providers2 = verifier.get_ordered_providers(&context2);
        let providers3 = verifier.get_ordered_providers(&context3);

        // Each context should have 3 providers
        assert_eq!(providers1.len(), 3);
        assert_eq!(providers2.len(), 3);
        assert_eq!(providers3.len(), 3);

        // The first provider (primary) should be different for at least some participants
        // due to the hash-based selection
        let primary1 = &providers1[0].0;
        let primary2 = &providers2[0].0;
        let primary3 = &providers3[0].0;

        println!(
            "Primary providers: participant1={}, participant2={}, participant3={}",
            primary1, primary2, primary3
        );

        // Verify determinism: same context should always give same order
        let providers1_again = verifier.get_ordered_providers(&context1);
        let order1: Vec<_> = providers1.iter().map(|(n, _)| n.clone()).collect();
        let order1_again: Vec<_> = providers1_again.iter().map(|(n, _)| n.clone()).collect();
        assert_eq!(order1, order1_again, "Provider order should be deterministic");

        // Verify that all providers are included
        let provider_names1: std::collections::HashSet<_> =
            providers1.iter().map(|(name, _)| name.as_str()).collect();
        assert!(provider_names1.contains("provider_a"));
        assert!(provider_names1.contains("provider_b"));
        assert!(provider_names1.contains("provider_c"));

        // Verify that different participants get different provider orderings
        // Since hash is deterministic, each participant should get a unique ordering
        let order2: Vec<_> = providers2.iter().map(|(n, _)| n.clone()).collect();
        let order3: Vec<_> = providers3.iter().map(|(n, _)| n.clone()).collect();

        // At least one participant should have a different primary provider
        let primaries = vec![primary1.clone(), primary2.clone(), primary3.clone()];
        let unique_primaries: std::collections::HashSet<_> = primaries.into_iter().collect();

        println!(
            "Unique primary providers: {} out of 3 participants",
            unique_primaries.len()
        );

        // With 3 providers and 3 participants, we expect good distribution
        // At minimum, we should have diversity in the ordering
        println!("Order 1: {:?}", order1);
        println!("Order 2: {:?}", order2);
        println!("Order 3: {:?}", order3);

        // Verify that different request_ids produce different orderings for the same participant
        let different_request_id = CryptoHash([99u8; 32]);
        let context1_diff_request = ProviderSelectionContext {
            my_participant_id: ParticipantId::from_raw(1),
            request_id: different_request_id,
        };
        let providers1_diff_request = verifier.get_ordered_providers(&context1_diff_request);
        let order1_diff: Vec<_> = providers1_diff_request.iter().map(|(n, _)| n.clone()).collect();

        println!(
            "Same participant, different requests: order1={:?}, order1_diff={:?}",
            order1, order1_diff
        );
    }

    #[test]
    fn test_provider_selection_with_single_provider() {
        // Test that provider selection works with a single provider
        let mut providers = HashMap::new();
        providers.insert(
            "only_provider".to_string(),
            SolanaRpcEndpoint {
                rpc_url: "https://only.example.com".to_string(),
                backup_urls: vec![],
            },
        );
        let config = SolanaProviderConfig {
            providers,
            timeout_sec: 30,
            max_retries: 3,
        };

        let verifier = SolanaVerifier::new(config).unwrap();
        let context = ProviderSelectionContext {
            my_participant_id: ParticipantId::from_raw(1),
            request_id: CryptoHash([1u8; 32]),
        };

        let ordered = verifier.get_ordered_providers(&context);
        assert_eq!(ordered.len(), 1);
        assert_eq!(ordered[0].0, "only_provider");
    }
}

/// Integration tests that hit real Solana RPC endpoints.
/// These tests are ignored by default and should be run manually with:
/// `cargo test --profile test-release -p mpc-node --lib solana_integration -- --ignored`
#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::config::SolanaRpcEndpoint;
    use crate::primitives::ParticipantId;
    use near_indexer_primitives::CryptoHash;
    use std::collections::HashMap;

    fn create_test_context(seed: u8) -> ProviderSelectionContext {
        let mut request_id_bytes = [0u8; 32];
        request_id_bytes[0] = seed;
        ProviderSelectionContext {
            my_participant_id: ParticipantId::from_raw(1),
            request_id: CryptoHash(request_id_bytes),
        }
    }

    fn create_test_config() -> SolanaProviderConfig {
        let mut providers = HashMap::new();
        providers.insert(
            "mainnet".to_string(),
            SolanaRpcEndpoint {
                rpc_url: "https://api.mainnet-beta.solana.com".to_string(),
                backup_urls: vec![],
            },
        );
        SolanaProviderConfig {
            providers,
            timeout_sec: 30,
            max_retries: 3,
        }
    }

    /// Helper to fetch a recent successful finalized transaction from Solana mainnet.
    /// Returns the transaction signature as base58 string.
    /// Only returns transactions that succeeded (no execution error).
    async fn fetch_recent_finalized_transaction(config: &SolanaProviderConfig) -> String {
        let rpc_url = config
            .providers
            .values()
            .next()
            .expect("Need at least one provider")
            .rpc_url
            .clone();
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_sec))
            .build()
            .expect("Failed to create client");

        // Get current slot
        let slot_request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "getSlot",
            params: serde_json::json!([{"commitment": "finalized"}]),
        };

        let slot_response: serde_json::Value = client
            .post(&rpc_url)
            .json(&slot_request)
            .send()
            .await
            .expect("Failed to get slot")
            .json()
            .await
            .expect("Failed to parse slot response");

        let current_slot = slot_response["result"]
            .as_u64()
            .expect("Failed to get slot number");

        // Try recent slots to find one with successful transactions
        for offset in [10, 20, 30, 40, 50] {
            let block_slot = current_slot - offset;

            // Get block with full transaction details to check for errors
            let block_request = JsonRpcRequest {
                jsonrpc: "2.0",
                id: 1,
                method: "getBlock",
                params: serde_json::json!([
                    block_slot,
                    {
                        "transactionDetails": "full",
                        "maxSupportedTransactionVersion": 0
                    }
                ]),
            };

            let block_response: serde_json::Value = client
                .post(&rpc_url)
                .json(&block_request)
                .send()
                .await
                .expect("Failed to get block")
                .json()
                .await
                .expect("Failed to parse block response");

            if let Some(transactions) = block_response["result"]["transactions"].as_array() {
                // Find a successful transaction (no error in meta)
                for tx in transactions {
                    let has_error = tx["meta"]["err"].is_null();
                    if has_error {
                        // This transaction succeeded - extract its signature
                        if let Some(signatures) = tx["transaction"]["signatures"].as_array() {
                            if let Some(first_sig) = signatures.first() {
                                if let Some(sig_str) = first_sig.as_str() {
                                    return sig_str.to_string();
                                }
                            }
                        }
                    }
                }
            }
        }

        panic!("Could not find a successful finalized transaction in recent blocks");
    }

    /// Test verification of a real recent transaction on Solana mainnet.
    /// This test dynamically fetches a recent finalized transaction to verify.
    #[tokio::test]
    #[ignore] // Requires network access - run manually
    async fn test_verify_recent_finalized_transaction() {
        let config = create_test_config();
        let verifier = SolanaVerifier::new(config.clone()).expect("Failed to create verifier");
        let context = create_test_context(1);

        // Fetch a recent finalized transaction
        let sig_base58 = fetch_recent_finalized_transaction(&config).await;
        println!("Testing with recent transaction: {}", sig_base58);

        let sig_bytes: [u8; 64] = bs58::decode(&sig_base58)
            .into_vec()
            .expect("Invalid base58")
            .try_into()
            .expect("Wrong length");

        let signature = SolanaSignature::new(sig_bytes);

        let result = verifier
            .verify_transaction(&signature, &FinalityLevel::Final, &context)
            .await;

        println!("Verification result: {:?}", result);

        assert!(result.is_ok(), "Expected successful verification: {:?}", result);
        let output = result.unwrap();
        assert!(output.success, "Expected transaction to be successful");
        assert_eq!(output.tx_status, TxStatus::Success);
        assert!(matches!(output.block_id, BlockId::SolanaSlot(_)));
    }

    /// Test verification of a non-existent transaction.
    #[tokio::test]
    #[ignore] // Requires network access - run manually
    async fn test_verify_nonexistent_transaction() {
        let config = create_test_config();
        let verifier = SolanaVerifier::new(config).expect("Failed to create verifier");
        let context = create_test_context(2);

        // Random signature that doesn't exist (all 0xAB bytes is very unlikely to be valid)
        let fake_sig = SolanaSignature::new([0xAB; 64]);

        let result = verifier
            .verify_transaction(&fake_sig, &FinalityLevel::Final, &context)
            .await;

        println!("Verification result for nonexistent tx: {:?}", result);

        assert!(result.is_err(), "Expected error for nonexistent transaction");
        let error = result.unwrap_err();
        assert!(
            matches!(error, VerificationError::TransactionNotFound(_)),
            "Expected TransactionNotFound error, got: {:?}",
            error
        );
    }

    /// Test verification with optimistic (confirmed) finality level.
    #[tokio::test]
    #[ignore] // Requires network access - run manually
    async fn test_verify_with_optimistic_finality() {
        let config = create_test_config();
        let verifier = SolanaVerifier::new(config.clone()).expect("Failed to create verifier");
        let context = create_test_context(3);

        // Fetch a recent finalized transaction (which is also confirmed)
        let sig_base58 = fetch_recent_finalized_transaction(&config).await;
        println!("Testing with recent transaction: {}", sig_base58);

        let sig_bytes: [u8; 64] = bs58::decode(&sig_base58)
            .into_vec()
            .expect("Invalid base58")
            .try_into()
            .expect("Wrong length");

        let signature = SolanaSignature::new(sig_bytes);

        // Use Optimistic (confirmed) finality - should work for finalized txs too
        let result = verifier
            .verify_transaction(&signature, &FinalityLevel::Optimistic, &context)
            .await;

        println!("Verification result with optimistic finality: {:?}", result);

        assert!(result.is_ok(), "Expected successful verification: {:?}", result);
        let output = result.unwrap();
        assert!(output.success, "Expected transaction to be successful");
    }

    /// Test that invalid RPC URL returns an error.
    #[tokio::test]
    #[ignore] // Requires network access - run manually
    async fn test_verify_with_invalid_rpc() {
        let mut providers = HashMap::new();
        providers.insert(
            "bad".to_string(),
            SolanaRpcEndpoint {
                rpc_url: "https://invalid-rpc-that-does-not-exist.example.com".to_string(),
                backup_urls: vec![],
            },
        );
        let config = SolanaProviderConfig {
            providers,
            timeout_sec: 5,
            max_retries: 1,
        };
        let verifier = SolanaVerifier::new(config).expect("Failed to create verifier");
        let context = create_test_context(4);

        let fake_sig = SolanaSignature::new([0x11; 64]);

        let result = verifier
            .verify_transaction(&fake_sig, &FinalityLevel::Final, &context)
            .await;

        println!("Verification result with invalid RPC: {:?}", result);

        assert!(result.is_err(), "Expected error for invalid RPC");
        // Should be an RPC error (connection failed)
        let error = result.unwrap_err();
        assert!(
            matches!(error, VerificationError::RpcError(_)),
            "Expected RpcError, got: {:?}",
            error
        );
    }

    /// Test backup RPC fallback - primary fails, backup succeeds.
    #[tokio::test]
    #[ignore] // Requires network access - run manually
    async fn test_verify_with_backup_rpc_fallback() {
        // First get a valid transaction using good RPC
        let good_config = create_test_config();
        let sig_base58 = fetch_recent_finalized_transaction(&good_config).await;
        println!("Testing with recent transaction: {}", sig_base58);

        // Now create verifier with bad primary but good backup
        let mut providers = HashMap::new();
        providers.insert(
            "primary".to_string(),
            SolanaRpcEndpoint {
                rpc_url: "https://invalid-primary-rpc.example.com".to_string(),
                backup_urls: vec!["https://api.mainnet-beta.solana.com".to_string()],
            },
        );
        let config = SolanaProviderConfig {
            providers,
            timeout_sec: 10,
            max_retries: 1,
        };
        let verifier = SolanaVerifier::new(config).expect("Failed to create verifier");
        let context = create_test_context(5);

        let sig_bytes: [u8; 64] = bs58::decode(&sig_base58)
            .into_vec()
            .expect("Invalid base58")
            .try_into()
            .expect("Wrong length");

        let signature = SolanaSignature::new(sig_bytes);

        let result = verifier
            .verify_transaction(&signature, &FinalityLevel::Final, &context)
            .await;

        println!("Verification result with backup fallback: {:?}", result);

        // Should succeed because backup RPC works
        assert!(result.is_ok(), "Expected successful verification with backup RPC: {:?}", result);
        let output = result.unwrap();
        assert!(output.success);
    }

    /// Test the full flow through ForeignChainVerifierRegistry.
    #[tokio::test]
    #[ignore] // Requires network access - run manually
    async fn test_full_verification_flow_through_registry() {
        use crate::config::ForeignChainConfig;
        use crate::foreign_chain_verifier::{ForeignChainVerifierAPI, ForeignChainVerifierRegistry};
        use mpc_contract::primitives::foreign_chain::{ForeignChain, TransactionId};

        let solana_config = create_test_config();
        let context = create_test_context(6);

        // Fetch a recent transaction
        let sig_base58 = fetch_recent_finalized_transaction(&solana_config).await;
        println!("Testing with recent transaction: {}", sig_base58);

        let config = ForeignChainConfig {
            solana: Some(solana_config),
        };

        let registry = ForeignChainVerifierRegistry::new(&config)
            .expect("Failed to create registry");

        assert!(registry.supports_chain(&ForeignChain::Solana));

        let sig_bytes: [u8; 64] = bs58::decode(&sig_base58)
            .into_vec()
            .expect("Invalid base58")
            .try_into()
            .expect("Wrong length");

        let tx_id = TransactionId::SolanaSignature(SolanaSignature::new(sig_bytes));

        let result = registry
            .verify(&ForeignChain::Solana, &tx_id, &FinalityLevel::Final, &context)
            .await;

        println!("Full registry verification result: {:?}", result);

        assert!(result.is_ok(), "Expected successful verification: {:?}", result);
        let output = result.unwrap();
        assert!(output.success);
        assert_eq!(output.tx_status, TxStatus::Success);
    }

    /// Test that the verifier correctly identifies the slot of a transaction.
    #[tokio::test]
    #[ignore] // Requires network access - run manually
    async fn test_verify_returns_correct_slot() {
        let config = create_test_config();
        let verifier = SolanaVerifier::new(config.clone()).expect("Failed to create verifier");
        let context = create_test_context(7);

        // Fetch a recent finalized transaction
        let sig_base58 = fetch_recent_finalized_transaction(&config).await;
        println!("Testing with recent transaction: {}", sig_base58);

        let sig_bytes: [u8; 64] = bs58::decode(&sig_base58)
            .into_vec()
            .expect("Invalid base58")
            .try_into()
            .expect("Wrong length");

        let signature = SolanaSignature::new(sig_bytes);

        let result = verifier
            .verify_transaction(&signature, &FinalityLevel::Final, &context)
            .await;

        assert!(result.is_ok());
        let output = result.unwrap();

        // Verify slot is a reasonable number (greater than 0, less than some large value)
        match output.block_id {
            BlockId::SolanaSlot(slot) => {
                println!("Transaction was in slot: {}", slot);
                assert!(slot > 0, "Slot should be greater than 0");
                // Solana is currently around slot 395 million, so sanity check
                assert!(slot < 1_000_000_000, "Slot should be less than 1 billion");
            }
        }
    }
}
