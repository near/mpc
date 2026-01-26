//! Tests for foreign chain transaction verification.
//!
//! These tests verify the verify_foreign_tx flow using a mock foreign chain verifier.

use mpc_contract::primitives::{
    domain::DomainId,
    foreign_chain::{BlockId, FinalityLevel, ForeignChain, SolanaSignature, TransactionId},
    signature::Tweak,
};
use near_indexer_primitives::CryptoHash;

use crate::{
    foreign_chain_verifier::{
        mock::MockForeignChainVerifier, ForeignChainVerifierAPI, TxStatus, VerificationError,
    },
    types::VerifyForeignTxRequest,
};

fn create_test_verify_request(tx_bytes: [u8; 64]) -> VerifyForeignTxRequest {
    VerifyForeignTxRequest {
        id: CryptoHash(rand::random()),
        receipt_id: CryptoHash(rand::random()),
        chain: ForeignChain::Solana,
        tx_id: TransactionId::SolanaSignature(SolanaSignature::new(tx_bytes)),
        finality: FinalityLevel::Final,
        tweak: Tweak::new([0u8; 32]),
        entropy: [0u8; 32],
        timestamp_nanosec: 0,
        domain: DomainId::legacy_ecdsa_id(),
    }
}

#[tokio::test]
async fn test_verify_foreign_tx_success() {
    let mock = MockForeignChainVerifier::new();
    let request = create_test_verify_request([1u8; 64]);
    let block_id = BlockId::SolanaSlot(12345);

    // Configure mock to return success for this specific tx
    mock.set_success(
        request.chain.clone(),
        request.tx_id.clone(),
        block_id.clone(),
    );

    // Verify the transaction
    let result = mock
        .verify(&request.chain, &request.tx_id, &request.finality)
        .await;

    assert!(result.is_ok());
    let output = result.unwrap();
    assert!(output.success);
    assert_eq!(output.tx_status, TxStatus::Success);
    assert_eq!(output.block_id, block_id);
}

#[tokio::test]
async fn test_verify_foreign_tx_failed_transaction() {
    let mock = MockForeignChainVerifier::new();
    let request = create_test_verify_request([2u8; 64]);
    let block_id = BlockId::SolanaSlot(12345);

    // Configure mock to return failed tx (tx exists but reverted)
    mock.set_failed_tx(
        request.chain.clone(),
        request.tx_id.clone(),
        block_id.clone(),
    );

    let result = mock
        .verify(&request.chain, &request.tx_id, &request.finality)
        .await;

    // Verification succeeds (tx was found) but success flag is false
    assert!(result.is_ok());
    let output = result.unwrap();
    assert!(!output.success);
    assert_eq!(output.tx_status, TxStatus::Failed);
}

#[tokio::test]
async fn test_verify_foreign_tx_not_found() {
    let mock = MockForeignChainVerifier::new();
    let request = create_test_verify_request([3u8; 64]);

    // Configure mock to return not found
    mock.set_not_found(request.chain.clone(), request.tx_id.clone());

    let result = mock
        .verify(&request.chain, &request.tx_id, &request.finality)
        .await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(matches!(error, VerificationError::TransactionNotFound(_)));
}

#[tokio::test]
async fn test_verify_foreign_tx_rpc_error() {
    let mock = MockForeignChainVerifier::new();
    let request = create_test_verify_request([4u8; 64]);

    // Configure mock to return an RPC error
    mock.set_error(
        request.chain.clone(),
        request.tx_id.clone(),
        VerificationError::RpcError("Connection timeout".to_string()),
    );

    let result = mock
        .verify(&request.chain, &request.tx_id, &request.finality)
        .await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(matches!(error, VerificationError::RpcError(_)));
}

#[tokio::test]
async fn test_verify_foreign_tx_not_finalized() {
    let mock = MockForeignChainVerifier::new();
    let request = create_test_verify_request([5u8; 64]);

    // Configure mock to return not finalized error
    mock.set_error(
        request.chain.clone(),
        request.tx_id.clone(),
        VerificationError::NotFinalized,
    );

    let result = mock
        .verify(&request.chain, &request.tx_id, &request.finality)
        .await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(matches!(error, VerificationError::NotFinalized));
}

#[tokio::test]
async fn test_verify_foreign_tx_default_success_for_any_tx() {
    let mock = MockForeignChainVerifier::new();
    let block_id = BlockId::SolanaSlot(99999);

    // Set default to return success
    mock.set_default_success(block_id.clone());

    // Any transaction should succeed
    let request1 = create_test_verify_request([10u8; 64]);
    let request2 = create_test_verify_request([20u8; 64]);
    let request3 = create_test_verify_request([30u8; 64]);

    let result1 = mock
        .verify(&request1.chain, &request1.tx_id, &request1.finality)
        .await;
    let result2 = mock
        .verify(&request2.chain, &request2.tx_id, &request2.finality)
        .await;
    let result3 = mock
        .verify(&request3.chain, &request3.tx_id, &request3.finality)
        .await;

    assert!(result1.is_ok());
    assert!(result2.is_ok());
    assert!(result3.is_ok());
    assert_eq!(result1.unwrap().block_id, block_id);
    assert_eq!(result2.unwrap().block_id, block_id);
    assert_eq!(result3.unwrap().block_id, block_id);
}

#[tokio::test]
async fn test_verify_foreign_tx_default_not_found_for_any_tx() {
    let mock = MockForeignChainVerifier::new();

    // Set default to return not found
    mock.set_default_not_found();

    // Any transaction should fail with not found
    let request1 = create_test_verify_request([40u8; 64]);
    let request2 = create_test_verify_request([50u8; 64]);

    let result1 = mock
        .verify(&request1.chain, &request1.tx_id, &request1.finality)
        .await;
    let result2 = mock
        .verify(&request2.chain, &request2.tx_id, &request2.finality)
        .await;

    assert!(result1.is_err());
    assert!(result2.is_err());
    assert!(matches!(
        result1.unwrap_err(),
        VerificationError::TransactionNotFound(_)
    ));
    assert!(matches!(
        result2.unwrap_err(),
        VerificationError::TransactionNotFound(_)
    ));
}

#[tokio::test]
async fn test_verify_foreign_tx_specific_override_default() {
    let mock = MockForeignChainVerifier::new();
    let block_id = BlockId::SolanaSlot(12345);

    // Set default to not found
    mock.set_default_not_found();

    // But set specific tx to succeed
    let specific_request = create_test_verify_request([100u8; 64]);
    mock.set_success(
        specific_request.chain.clone(),
        specific_request.tx_id.clone(),
        block_id.clone(),
    );

    // Another tx should use default (not found)
    let other_request = create_test_verify_request([200u8; 64]);

    let specific_result = mock
        .verify(
            &specific_request.chain,
            &specific_request.tx_id,
            &specific_request.finality,
        )
        .await;
    let other_result = mock
        .verify(
            &other_request.chain,
            &other_request.tx_id,
            &other_request.finality,
        )
        .await;

    // Specific tx succeeds
    assert!(specific_result.is_ok());
    assert!(specific_result.unwrap().success);

    // Other tx uses default (not found)
    assert!(other_result.is_err());
    assert!(matches!(
        other_result.unwrap_err(),
        VerificationError::TransactionNotFound(_)
    ));
}

#[tokio::test]
async fn test_verify_foreign_tx_payload_derivation() {
    // Test that payload is derived correctly from tx_id
    let request = create_test_verify_request([1u8; 64]);

    // The payload should be deterministic - same tx_id always gives same payload
    let payload1 = request.payload();
    let payload2 = request.payload();

    assert_eq!(payload1, payload2);

    // Different tx_id should give different payload
    let other_request = create_test_verify_request([2u8; 64]);
    let other_payload = other_request.payload();

    assert_ne!(payload1, other_payload);
}

#[tokio::test]
async fn test_verify_foreign_tx_payload_uses_sha256() {
    use sha2::{Digest, Sha256};

    // Create a request with known tx_id bytes
    let tx_bytes = [42u8; 64];
    let request = create_test_verify_request(tx_bytes);

    // Calculate expected payload using SHA-256 directly
    // This MUST match what the contract uses (near_sdk::env::sha256)
    let expected_hash = Sha256::digest(&tx_bytes);
    let expected_hash_array: [u8; 32] = expected_hash.into();

    // Get the actual payload from the request
    let payload = request.payload();

    // The payload bytes should match the SHA-256 hash
    // This ensures consistency with the contract's payload derivation
    match payload {
        mpc_contract::primitives::signature::Payload::Ecdsa(payload_bytes) => {
            // Compare using as_fixed_bytes()
            assert_eq!(
                payload_bytes.as_fixed_bytes(),
                &expected_hash_array,
                "Payload derivation must use SHA-256 to match contract"
            );
        }
        _ => panic!("Expected ECDSA payload"),
    }
}

#[tokio::test]
async fn test_mock_verifier_supports_all_chains() {
    let mock = MockForeignChainVerifier::new();

    // Mock verifier should support all chains for testing
    assert!(mock.supports_chain(&ForeignChain::Solana));
}

// Integration tests using the fake indexer and multiple signing nodes

use crate::indexer::participants::ContractState;
use crate::p2p::testing::PortSeed;
use crate::tests::{
    request_verify_foreign_tx_and_await_response, IntegrationTestSetup, DEFAULT_BLOCK_TIME,
    DEFAULT_MAX_PROTOCOL_WAIT_TIME, DEFAULT_MAX_SIGNATURE_WAIT_TIME,
};
use crate::tracking::AutoAbortTask;
use mpc_contract::primitives::domain::DomainConfig;
use near_o11y::testonly::init_integration_logger;
use near_time::Clock;
use rand::RngCore;
use std::sync::Arc;

/// Integration test that verifies the full verify_foreign_tx flow.
///
/// This test:
/// 1. Creates a cluster of 4 MPC nodes with a threshold of 3
/// 2. Configures a mock foreign chain verifier that returns success for all transactions
/// 3. Generates keys for an ECDSA domain
/// 4. Sends a verify_foreign_tx request with a Solana transaction ID
/// 5. Verifies that a signature is generated and returned
#[tokio::test]
async fn test_verify_foreign_tx_integration() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();

    let mut setup: IntegrationTestSetup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::VERIFY_FOREIGN_TX_TEST,
        DEFAULT_BLOCK_TIME,
    );

    // Create a Solana transaction ID for verification (before mock setup to whitelist it)
    let mut tx_bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut tx_bytes);
    let tx_id = TransactionId::SolanaSignature(SolanaSignature::new(tx_bytes));

    // Create a mock foreign chain verifier that only succeeds for the specific tx_id
    // Default is not found - this ensures the test fails if wrong tx_id is passed
    let mock_verifier = Arc::new(MockForeignChainVerifier::new());
    mock_verifier.set_default_not_found();
    mock_verifier.set_success(
        ForeignChain::Solana,
        tx_id.clone(),
        BlockId::SolanaSlot(12345),
    );

    // Set the mock verifier for all nodes
    setup.set_foreign_verifier(mock_verifier);

    // Configure domain for ECDSA signatures (required for verify_foreign_tx)
    let signature_domain_ecdsa = DomainConfig {
        id: DomainId::legacy_ecdsa_id(),
        scheme: mpc_contract::primitives::domain::SignatureScheme::Secp256k1,
    };

    let domains = vec![signature_domain_ecdsa.clone()];

    // Initialize the contract and add the domain
    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(domains.clone());
    }

    // Start all the nodes
    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    // Wait for keygen to complete
    setup
        .indexer
        .wait_for_contract_state(
            |state| matches!(state, ContractState::Running(_)),
            DEFAULT_MAX_PROTOCOL_WAIT_TIME * domains.len() as u32,
        )
        .await
        .expect("timeout waiting for keygen to complete");

    // Request verification and signature
    let result = request_verify_foreign_tx_and_await_response(
        &mut setup.indexer,
        "user0",
        &signature_domain_ecdsa,
        ForeignChain::Solana,
        tx_id,
        DEFAULT_MAX_SIGNATURE_WAIT_TIME,
    )
    .await;

    assert!(
        result.is_some(),
        "Expected to receive a signature for the verify_foreign_tx request"
    );
    tracing::info!(
        "Successfully completed verify_foreign_tx in {:?}",
        result.unwrap()
    );
}

/// Integration test that verifies verify_foreign_tx fails when the transaction is not found.
///
/// This test configures the mock verifier to return "not found" and verifies that
/// the request times out (no signature is generated for an unverified transaction).
#[tokio::test]
async fn test_verify_foreign_tx_not_found_integration() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();

    let mut setup: IntegrationTestSetup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::VERIFY_FOREIGN_TX_NOT_FOUND_TEST,
        DEFAULT_BLOCK_TIME,
    );

    // Create a mock foreign chain verifier that returns "not found" for all transactions
    let mock_verifier = Arc::new(MockForeignChainVerifier::new());
    mock_verifier.set_default_not_found();

    // Set the mock verifier for all nodes
    setup.set_foreign_verifier(mock_verifier);

    // Configure domain for ECDSA signatures
    let signature_domain_ecdsa = DomainConfig {
        id: DomainId::legacy_ecdsa_id(),
        scheme: mpc_contract::primitives::domain::SignatureScheme::Secp256k1,
    };

    let domains = vec![signature_domain_ecdsa.clone()];

    // Initialize the contract and add the domain
    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(domains.clone());
    }

    // Start all the nodes
    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    // Wait for keygen to complete
    setup
        .indexer
        .wait_for_contract_state(
            |state| matches!(state, ContractState::Running(_)),
            DEFAULT_MAX_PROTOCOL_WAIT_TIME * domains.len() as u32,
        )
        .await
        .expect("timeout waiting for keygen to complete");

    // Create a Solana transaction ID for verification
    let mut tx_bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut tx_bytes);
    let tx_id = TransactionId::SolanaSignature(SolanaSignature::new(tx_bytes));

    // Request verification - should timeout since the transaction is "not found"
    // Use a shorter timeout to make the test faster
    let short_timeout = std::time::Duration::from_secs(10);
    let result = request_verify_foreign_tx_and_await_response(
        &mut setup.indexer,
        "user0",
        &signature_domain_ecdsa,
        ForeignChain::Solana,
        tx_id,
        short_timeout,
    )
    .await;

    assert!(
        result.is_none(),
        "Expected no signature when transaction verification fails"
    );
    tracing::info!("Correctly timed out for unverified transaction");
}
