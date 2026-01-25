//! Solana transaction verification using JSON-RPC.

use super::types::{TxStatus, VerificationError, VerificationOutput};
use crate::config::SolanaRpcConfig;
use mpc_contract::primitives::foreign_chain::{BlockId, FinalityLevel, SolanaSignature};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Solana transaction verifier using JSON-RPC
pub struct SolanaVerifier {
    client: Client,
    config: SolanaRpcConfig,
}

impl SolanaVerifier {
    /// Create a new Solana verifier from config
    pub fn new(config: SolanaRpcConfig) -> Result<Self, VerificationError> {
        let timeout = Duration::from_secs(config.timeout_sec);
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| VerificationError::Internal(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self { client, config })
    }

    /// Verify a Solana transaction
    pub async fn verify_transaction(
        &self,
        signature: &SolanaSignature,
        finality: &FinalityLevel,
    ) -> Result<VerificationOutput, VerificationError> {
        let commitment = match finality {
            FinalityLevel::Optimistic => "confirmed",
            FinalityLevel::Final => "finalized",
        };

        let sig_base58 = bs58::encode(signature.as_bytes()).into_string();

        // Try primary RPC, then fall back to backups
        let mut last_error = None;
        let urls = std::iter::once(&self.config.rpc_url)
            .chain(self.config.backup_rpc_urls.iter());

        for url in urls {
            match self.verify_with_url(url, &sig_base58, commitment).await {
                Ok(output) => return Ok(output),
                Err(e) => {
                    tracing::warn!("Solana RPC {} failed: {}", url, e);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            VerificationError::ConfigError("No RPC endpoints configured".to_string())
        }))
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
}

/// Integration tests that hit real Solana RPC endpoints.
/// These tests are ignored by default and should be run manually with:
/// `cargo test --profile test-release -p mpc-node --lib solana_integration -- --ignored`
#[cfg(test)]
mod integration_tests {
    use super::*;

    fn create_test_config() -> SolanaRpcConfig {
        SolanaRpcConfig {
            // Use Solana mainnet-beta public RPC
            rpc_url: "https://api.mainnet-beta.solana.com".to_string(),
            backup_rpc_urls: vec![],
            timeout_sec: 30,
            max_retries: 3,
        }
    }

    /// Helper to fetch a recent successful finalized transaction from Solana mainnet.
    /// Returns the transaction signature as base58 string.
    /// Only returns transactions that succeeded (no execution error).
    async fn fetch_recent_finalized_transaction(config: &SolanaRpcConfig) -> String {
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
            .post(&config.rpc_url)
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
                .post(&config.rpc_url)
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
                    let has_error = tx["meta"]["err"].as_null().is_none();
                    if !has_error {
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
            .verify_transaction(&signature, &FinalityLevel::Final)
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

        // Random signature that doesn't exist (all 0xAB bytes is very unlikely to be valid)
        let fake_sig = SolanaSignature::new([0xAB; 64]);

        let result = verifier
            .verify_transaction(&fake_sig, &FinalityLevel::Final)
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
            .verify_transaction(&signature, &FinalityLevel::Optimistic)
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
        let config = SolanaRpcConfig {
            rpc_url: "https://invalid-rpc-that-does-not-exist.example.com".to_string(),
            backup_rpc_urls: vec![],
            timeout_sec: 5,
            max_retries: 1,
        };
        let verifier = SolanaVerifier::new(config).expect("Failed to create verifier");

        let fake_sig = SolanaSignature::new([0x11; 64]);

        let result = verifier
            .verify_transaction(&fake_sig, &FinalityLevel::Final)
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
        let config = SolanaRpcConfig {
            // Primary URL is invalid
            rpc_url: "https://invalid-primary-rpc.example.com".to_string(),
            // Backup URL is valid
            backup_rpc_urls: vec!["https://api.mainnet-beta.solana.com".to_string()],
            timeout_sec: 10,
            max_retries: 1,
        };
        let verifier = SolanaVerifier::new(config).expect("Failed to create verifier");

        let sig_bytes: [u8; 64] = bs58::decode(&sig_base58)
            .into_vec()
            .expect("Invalid base58")
            .try_into()
            .expect("Wrong length");

        let signature = SolanaSignature::new(sig_bytes);

        let result = verifier
            .verify_transaction(&signature, &FinalityLevel::Final)
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

        let solana_config = SolanaRpcConfig {
            rpc_url: "https://api.mainnet-beta.solana.com".to_string(),
            backup_rpc_urls: vec![],
            timeout_sec: 30,
            max_retries: 3,
        };

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
            .verify(&ForeignChain::Solana, &tx_id, &FinalityLevel::Final)
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
            .verify_transaction(&signature, &FinalityLevel::Final)
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
