//! Foreign chain transaction verification module.
//!
//! This module provides the infrastructure for verifying transactions on foreign chains
//! (non-NEAR chains) before MPC signing. Each supported chain has its own verifier
//! implementation that connects to the chain's RPC endpoints.
//!
//! Provider Selection:
//! Each MPC node is assigned a specific RPC provider to query based on a deterministic
//! hash of (participant_id, request_id). This ensures that different nodes query different
//! providers for the same request, reducing the risk of a single provider returning bad data.

pub mod solana;
pub mod types;

use crate::config::ForeignChainConfig;
use crate::primitives::ParticipantId;
use async_trait::async_trait;
use mpc_contract::primitives::foreign_chain::{FinalityLevel, ForeignChain, TransactionId};
use near_indexer_primitives::CryptoHash;
pub use types::{TxStatus, VerificationError, VerificationOutput};

use self::solana::SolanaVerifier;

/// Trait for foreign chain transaction verifiers.
///
/// Each supported chain implements this trait to provide transaction verification
/// functionality. The verification checks that a transaction exists and has reached
/// the required finality level.
#[async_trait]
pub trait ForeignChainVerifier: Send + Sync {
    /// Verify a transaction on the foreign chain.
    ///
    /// Returns verification output if the transaction is found and meets the
    /// finality requirements. Returns an error if verification fails.
    async fn verify_transaction(
        &self,
        tx_id: &TransactionId,
        finality: &FinalityLevel,
    ) -> Result<VerificationOutput, VerificationError>;
}

/// Context for provider selection, passed from the MPC client to the verifier.
/// This allows deterministic provider selection based on (participant_id, request_id).
#[derive(Debug, Clone)]
pub struct ProviderSelectionContext {
    /// The current node's participant ID
    pub my_participant_id: ParticipantId,
    /// The request ID (used for deterministic provider selection)
    pub request_id: CryptoHash,
}

/// Trait for the verifier registry, allowing for mockable verification in tests.
#[async_trait]
pub trait ForeignChainVerifierAPI: Send + Sync {
    /// Verify a transaction on the specified chain.
    ///
    /// The `provider_context` is used to deterministically select which RPC provider
    /// this node should query. Each node will query a different provider based on
    /// hash(participant_id, request_id), reducing the risk of a single provider
    /// returning bad data.
    async fn verify(
        &self,
        chain: &ForeignChain,
        tx_id: &TransactionId,
        finality: &FinalityLevel,
        provider_context: &ProviderSelectionContext,
    ) -> Result<VerificationOutput, VerificationError>;

    /// Check if a specific chain is supported (configured).
    fn supports_chain(&self, chain: &ForeignChain) -> bool;
}

/// Registry of foreign chain verifiers.
///
/// This struct holds verifier instances for all supported chains and provides
/// a unified interface for verifying transactions across chains.
pub struct ForeignChainVerifierRegistry {
    solana: Option<SolanaVerifier>,
}

impl ForeignChainVerifierRegistry {
    /// Create a new verifier registry from configuration.
    ///
    /// Initializes verifiers for all configured chains.
    pub fn new(config: &ForeignChainConfig) -> Result<Self, VerificationError> {
        let solana = config
            .solana
            .as_ref()
            .map(|cfg| SolanaVerifier::new(cfg.clone()))
            .transpose()?;

        Ok(Self { solana })
    }
}

#[async_trait]
impl ForeignChainVerifierAPI for ForeignChainVerifierRegistry {
    /// Verify a transaction on the specified chain.
    ///
    /// Routes the verification request to the appropriate chain-specific verifier.
    /// Uses the provider_context to deterministically select which RPC provider to use.
    async fn verify(
        &self,
        chain: &ForeignChain,
        tx_id: &TransactionId,
        finality: &FinalityLevel,
        provider_context: &ProviderSelectionContext,
    ) -> Result<VerificationOutput, VerificationError> {
        match chain {
            ForeignChain::Solana => {
                let verifier = self.solana.as_ref().ok_or_else(|| {
                    VerificationError::ConfigError(
                        "Solana verifier not configured".to_string(),
                    )
                })?;

                // Extract Solana signature from TransactionId
                match tx_id {
                    TransactionId::SolanaSignature(sig) => {
                        verifier.verify_transaction(sig, finality, provider_context).await
                    }
                }
            }
        }
    }

    /// Check if a specific chain is supported (configured).
    fn supports_chain(&self, chain: &ForeignChain) -> bool {
        match chain {
            ForeignChain::Solana => self.solana.is_some(),
        }
    }
}

/// Mock foreign chain verifier for testing.
///
/// Allows configuring specific responses for different transaction IDs.
#[cfg(any(test, feature = "test-utils"))]
pub mod mock {
    use super::*;
    use mpc_contract::primitives::foreign_chain::BlockId;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// A mock verifier that returns pre-configured responses for testing.
    #[derive(Clone, Default)]
    pub struct MockForeignChainVerifier {
        /// Map of (chain, tx_id) to the result to return
        responses: Arc<Mutex<HashMap<(ForeignChain, TransactionId), Result<VerificationOutput, VerificationError>>>>,
        /// Default response when no specific mapping is found
        default_response: Arc<Mutex<Option<Result<VerificationOutput, VerificationError>>>>,
    }

    impl MockForeignChainVerifier {
        pub fn new() -> Self {
            Self::default()
        }

        /// Configure a successful verification for a specific transaction.
        pub fn set_success(&self, chain: ForeignChain, tx_id: TransactionId, block_id: BlockId) {
            let output = VerificationOutput {
                success: true,
                block_id,
                tx_status: TxStatus::Success,
            };
            self.responses
                .lock()
                .unwrap()
                .insert((chain, tx_id), Ok(output));
        }

        /// Configure a failed transaction verification.
        pub fn set_failed_tx(&self, chain: ForeignChain, tx_id: TransactionId, block_id: BlockId) {
            let output = VerificationOutput {
                success: false,
                block_id,
                tx_status: TxStatus::Failed,
            };
            self.responses
                .lock()
                .unwrap()
                .insert((chain, tx_id), Ok(output));
        }

        /// Configure a not found response for a specific transaction.
        pub fn set_not_found(&self, chain: ForeignChain, tx_id: TransactionId) {
            self.responses.lock().unwrap().insert(
                (chain, tx_id),
                Err(VerificationError::TransactionNotFound("Transaction not found".to_string())),
            );
        }

        /// Configure a verification error for a specific transaction.
        pub fn set_error(&self, chain: ForeignChain, tx_id: TransactionId, error: VerificationError) {
            self.responses
                .lock()
                .unwrap()
                .insert((chain, tx_id), Err(error));
        }

        /// Set a default response for any transaction not specifically configured.
        pub fn set_default_response(&self, response: Result<VerificationOutput, VerificationError>) {
            *self.default_response.lock().unwrap() = Some(response);
        }

        /// Set default to return success with a given block_id.
        pub fn set_default_success(&self, block_id: BlockId) {
            let output = VerificationOutput {
                success: true,
                block_id,
                tx_status: TxStatus::Success,
            };
            self.set_default_response(Ok(output));
        }

        /// Set default to return not found.
        pub fn set_default_not_found(&self) {
            self.set_default_response(Err(VerificationError::TransactionNotFound(
                "Transaction not found".to_string(),
            )));
        }
    }

    #[async_trait]
    impl ForeignChainVerifierAPI for MockForeignChainVerifier {
        async fn verify(
            &self,
            chain: &ForeignChain,
            tx_id: &TransactionId,
            _finality: &FinalityLevel,
            _provider_context: &ProviderSelectionContext,
        ) -> Result<VerificationOutput, VerificationError> {
            // Check for specific response
            if let Some(response) = self
                .responses
                .lock()
                .unwrap()
                .get(&(chain.clone(), tx_id.clone()))
            {
                return response.clone();
            }

            // Return default response if set
            if let Some(response) = self.default_response.lock().unwrap().as_ref() {
                return response.clone();
            }

            // No configuration found - return error
            Err(VerificationError::ConfigError(format!(
                "No mock response configured for chain {:?}, tx_id {:?}",
                chain, tx_id
            )))
        }

        fn supports_chain(&self, _chain: &ForeignChain) -> bool {
            // Mock supports all chains
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SolanaProviderConfig, SolanaRpcEndpoint};
    use std::collections::HashMap;

    fn create_test_context(request_id_seed: u8) -> ProviderSelectionContext {
        let mut request_id_bytes = [0u8; 32];
        request_id_bytes[0] = request_id_seed;
        ProviderSelectionContext {
            my_participant_id: ParticipantId::from_raw(1),
            request_id: CryptoHash(request_id_bytes),
        }
    }

    #[test]
    fn test_registry_creation_without_config() {
        let config = ForeignChainConfig::default();
        let registry = ForeignChainVerifierRegistry::new(&config).unwrap();
        assert!(!registry.supports_chain(&ForeignChain::Solana));
    }

    #[test]
    fn test_registry_creation_with_solana_config() {
        let mut providers = HashMap::new();
        providers.insert(
            "mainnet".to_string(),
            SolanaRpcEndpoint {
                rpc_url: "https://api.mainnet-beta.solana.com".to_string(),
                backup_urls: vec![],
            },
        );
        let config = ForeignChainConfig {
            solana: Some(SolanaProviderConfig {
                providers,
                timeout_sec: 30,
                max_retries: 3,
            }),
        };
        let registry = ForeignChainVerifierRegistry::new(&config).unwrap();
        assert!(registry.supports_chain(&ForeignChain::Solana));
    }

    #[tokio::test]
    async fn test_mock_verifier_success() {
        use mpc_contract::primitives::foreign_chain::{BlockId, SolanaSignature};

        let mock = mock::MockForeignChainVerifier::new();
        let tx_id = TransactionId::SolanaSignature(SolanaSignature::new([1u8; 64]));
        let block_id = BlockId::SolanaSlot(12345);
        let context = create_test_context(1);

        mock.set_success(ForeignChain::Solana, tx_id.clone(), block_id.clone());

        let result = mock
            .verify(&ForeignChain::Solana, &tx_id, &FinalityLevel::Final, &context)
            .await;

        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.success);
        assert_eq!(output.block_id, block_id);
        assert_eq!(output.tx_status, TxStatus::Success);
    }

    #[tokio::test]
    async fn test_mock_verifier_not_found() {
        use mpc_contract::primitives::foreign_chain::SolanaSignature;

        let mock = mock::MockForeignChainVerifier::new();
        let tx_id = TransactionId::SolanaSignature(SolanaSignature::new([2u8; 64]));
        let context = create_test_context(2);

        mock.set_not_found(ForeignChain::Solana, tx_id.clone());

        let result = mock
            .verify(&ForeignChain::Solana, &tx_id, &FinalityLevel::Final, &context)
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VerificationError::TransactionNotFound(_)
        ));
    }

    #[tokio::test]
    async fn test_mock_verifier_failed_tx() {
        use mpc_contract::primitives::foreign_chain::{BlockId, SolanaSignature};

        let mock = mock::MockForeignChainVerifier::new();
        let tx_id = TransactionId::SolanaSignature(SolanaSignature::new([3u8; 64]));
        let block_id = BlockId::SolanaSlot(12345);
        let context = create_test_context(3);

        mock.set_failed_tx(ForeignChain::Solana, tx_id.clone(), block_id);

        let result = mock
            .verify(&ForeignChain::Solana, &tx_id, &FinalityLevel::Final, &context)
            .await;

        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(!output.success);
        assert_eq!(output.tx_status, TxStatus::Failed);
    }

    #[tokio::test]
    async fn test_mock_verifier_default_response() {
        use mpc_contract::primitives::foreign_chain::{BlockId, SolanaSignature};

        let mock = mock::MockForeignChainVerifier::new();
        let block_id = BlockId::SolanaSlot(99999);

        mock.set_default_success(block_id.clone());

        // Any tx_id should return success
        let tx_id1 = TransactionId::SolanaSignature(SolanaSignature::new([10u8; 64]));
        let tx_id2 = TransactionId::SolanaSignature(SolanaSignature::new([20u8; 64]));
        let context1 = create_test_context(10);
        let context2 = create_test_context(20);

        let result1 = mock
            .verify(&ForeignChain::Solana, &tx_id1, &FinalityLevel::Final, &context1)
            .await;
        let result2 = mock
            .verify(&ForeignChain::Solana, &tx_id2, &FinalityLevel::Optimistic, &context2)
            .await;

        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert_eq!(result1.unwrap().block_id, block_id);
        assert_eq!(result2.unwrap().block_id, block_id);
    }
}
