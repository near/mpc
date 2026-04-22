use crate::common;

use backon::{ConstantBuilder, Retryable};
use e2e_tests::CLUSTER_WAIT_TIMEOUT;
use e2e_tests::foreign_chain_mock::{setup_bitcoin_mock, setup_evm_mock, setup_starknet_mock};
use httpmock::prelude::*;
use mpc_node_config::ForeignChainsConfig;
use mpc_node_config::foreign_chains::{
    AbstractApiVariant, AbstractChainConfig, AbstractProviderConfig, BaseApiVariant,
    BaseChainConfig, BaseProviderConfig, BitcoinApiVariant, BitcoinChainConfig,
    BitcoinProviderConfig, BnbApiVariant, BnbChainConfig, BnbProviderConfig, StarknetApiVariant,
    StarknetChainConfig, StarknetProviderConfig,
};
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types::{
    BitcoinExtractor, BitcoinRpcRequest, BitcoinTxId, BlockConfirmations, Curve, DomainConfig,
    DomainId, DomainPurpose, EvmExtractor, EvmFinality, EvmRpcRequest, EvmTxId,
    ForeignChainRpcRequest, ForeignTxPayloadVersion, StarknetExtractor, StarknetFelt,
    StarknetFinality, StarknetRpcRequest, StarknetTxId, VerifyForeignTransactionRequestArgs,
};

struct ForeignTxTestEnv {
    cluster: e2e_tests::MpcCluster,
    secp_domain_id: DomainId,
    _mock_servers: Vec<MockServer>,
}

struct MockServerUrls {
    bitcoin: String,
    abstract_chain: String,
    bnb: String,
    starknet: String,
    base: String,
}

fn build_foreign_chains_config(urls: &MockServerUrls) -> ForeignChainsConfig {
    ForeignChainsConfig {
        bitcoin: Some(BitcoinChainConfig {
            timeout_sec: 30,
            max_retries: 3,
            providers: NonEmptyBTreeMap::new(
                "mock".to_string(),
                BitcoinProviderConfig {
                    rpc_url: urls.bitcoin.clone(),
                    api_variant: BitcoinApiVariant::Standard,
                    auth: Default::default(),
                },
            ),
        }),
        abstract_chain: Some(AbstractChainConfig {
            timeout_sec: 30,
            max_retries: 3,
            providers: NonEmptyBTreeMap::new(
                "mock".to_string(),
                AbstractProviderConfig {
                    rpc_url: urls.abstract_chain.clone(),
                    api_variant: AbstractApiVariant::Standard,
                    auth: Default::default(),
                },
            ),
        }),
        bnb: Some(BnbChainConfig {
            timeout_sec: 30,
            max_retries: 3,
            providers: NonEmptyBTreeMap::new(
                "mock".to_string(),
                BnbProviderConfig {
                    rpc_url: urls.bnb.clone(),
                    api_variant: BnbApiVariant::Standard,
                    auth: Default::default(),
                },
            ),
        }),
        starknet: Some(StarknetChainConfig {
            timeout_sec: 30,
            max_retries: 3,
            providers: NonEmptyBTreeMap::new(
                "mock".to_string(),
                StarknetProviderConfig {
                    rpc_url: urls.starknet.clone(),
                    api_variant: StarknetApiVariant::Standard,
                    auth: Default::default(),
                },
            ),
        }),
        base: Some(BaseChainConfig {
            timeout_sec: 30,
            max_retries: 3,
            providers: NonEmptyBTreeMap::new(
                "mock".to_string(),
                BaseProviderConfig {
                    rpc_url: urls.base.clone(),
                    api_variant: BaseApiVariant::Standard,
                    auth: Default::default(),
                },
            ),
        }),
        ..Default::default()
    }
}

async fn setup_foreign_tx_cluster() -> ForeignTxTestEnv {
    let bitcoin_server = MockServer::start();
    let abstract_server = MockServer::start();
    let bnb_server = MockServer::start();
    let starknet_server = MockServer::start();
    let base_server = MockServer::start();

    setup_bitcoin_mock(&bitcoin_server);
    setup_evm_mock(&abstract_server);
    setup_evm_mock(&bnb_server);
    setup_starknet_mock(&starknet_server);
    setup_evm_mock(&base_server);

    let urls = MockServerUrls {
        bitcoin: bitcoin_server.url("/"),
        abstract_chain: abstract_server.url("/"),
        bnb: bnb_server.url("/"),
        starknet: starknet_server.url("/"),
        base: base_server.url("/"),
    };

    let mock_servers = vec![
        bitcoin_server,
        abstract_server,
        bnb_server,
        starknet_server,
        base_server,
    ];

    let fc_config = build_foreign_chains_config(&urls);

    let (cluster, _running) = common::setup_cluster(common::FOREIGN_TX_VALIDATION_PORT_SEED, |c| {
        c.num_nodes = 2;
        c.threshold = 2;
        c.domains = vec![DomainConfig {
            id: DomainId(0),
            curve: Curve::Secp256k1,
            purpose: DomainPurpose::ForeignTx,
        }];
        c.node_foreign_chains_configs = vec![fc_config.clone(), fc_config];
    })
    .await;

    (|| async {
        let policy = cluster
            .view_foreign_chain_policy()
            .await
            .expect("failed to view policy");
        anyhow::ensure!(
            !policy.chains.is_empty(),
            "foreign chain policy not yet applied"
        );
        Ok(())
    })
    .retry(
        ConstantBuilder::default()
            .with_delay(common::POLL_INTERVAL)
            .with_max_times(
                (CLUSTER_WAIT_TIMEOUT.as_millis() / common::POLL_INTERVAL.as_millis()) as usize,
            ),
    )
    .await
    .expect("timed out waiting for foreign chain policy to be applied");

    let state = cluster
        .get_contract_state()
        .await
        .expect("failed to get contract state");
    let running = match &state {
        near_mpc_contract_interface::types::ProtocolContractState::Running(r) => r,
        _ => panic!("expected Running state"),
    };
    let secp_domain_id = running
        .domains
        .domains
        .iter()
        .find(|d| d.curve == Curve::Secp256k1)
        .expect("no Secp256k1 domain")
        .id;

    ForeignTxTestEnv {
        cluster,
        secp_domain_id,
        _mock_servers: mock_servers,
    }
}

fn verify_foreign_tx_response(outcome: &near_kit::FinalExecutionOutcome) {
    assert!(
        outcome.is_success(),
        "verify_foreign_transaction failed: {:?}",
        outcome.failure_message()
    );

    let response: serde_json::Value = outcome
        .json()
        .expect("failed to parse verify_foreign_transaction response");

    tracing::info!(?response, "verify_foreign_transaction response");

    let payload_hash = response["payload_hash"]
        .as_str()
        .expect("expected payload_hash string");
    assert_eq!(
        payload_hash.len(),
        64,
        "expected 64 hex chars in payload_hash, got {}",
        payload_hash.len()
    );

    let signature = &response["signature"];
    assert_eq!(
        signature["scheme"].as_str().unwrap(),
        "Secp256k1",
        "expected Secp256k1 signature scheme"
    );
    assert!(
        signature.get("big_r").is_some(),
        "expected big_r in signature"
    );
    assert!(signature.get("s").is_some(), "expected s in signature");
    assert!(
        signature.get("recovery_id").is_some(),
        "expected recovery_id in signature"
    );
}

async fn verify_bitcoin(env: &ForeignTxTestEnv) {
    let request = VerifyForeignTransactionRequestArgs {
        request: ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
            tx_id: BitcoinTxId([0xbb; 32]),
            confirmations: BlockConfirmations(1),
            extractors: vec![BitcoinExtractor::BlockHash],
        }),
        domain_id: env.secp_domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
    };
    let outcome = env
        .cluster
        .send_verify_foreign_transaction(&request)
        .await
        .expect("verify_foreign_transaction (Bitcoin) failed");
    verify_foreign_tx_response(&outcome);
}

async fn verify_abstract(env: &ForeignTxTestEnv) {
    let request = VerifyForeignTransactionRequestArgs {
        request: ForeignChainRpcRequest::Abstract(EvmRpcRequest {
            tx_id: EvmTxId([0xbb; 32]),
            extractors: vec![EvmExtractor::BlockHash, EvmExtractor::Log { log_index: 0 }],
            finality: EvmFinality::Finalized,
        }),
        domain_id: env.secp_domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
    };
    let outcome = env
        .cluster
        .send_verify_foreign_transaction(&request)
        .await
        .expect("verify_foreign_transaction (Abstract) failed");
    verify_foreign_tx_response(&outcome);
}

async fn verify_bnb(env: &ForeignTxTestEnv) {
    let request = VerifyForeignTransactionRequestArgs {
        request: ForeignChainRpcRequest::Bnb(EvmRpcRequest {
            tx_id: EvmTxId([0xbb; 32]),
            extractors: vec![EvmExtractor::BlockHash, EvmExtractor::Log { log_index: 0 }],
            finality: EvmFinality::Finalized,
        }),
        domain_id: env.secp_domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
    };
    let outcome = env
        .cluster
        .send_verify_foreign_transaction(&request)
        .await
        .expect("verify_foreign_transaction (Bnb) failed");
    verify_foreign_tx_response(&outcome);
}

async fn verify_base(env: &ForeignTxTestEnv) {
    let request = VerifyForeignTransactionRequestArgs {
        request: ForeignChainRpcRequest::Base(EvmRpcRequest {
            tx_id: EvmTxId([0xbb; 32]),
            extractors: vec![EvmExtractor::BlockHash, EvmExtractor::Log { log_index: 0 }],
            finality: EvmFinality::Finalized,
        }),
        domain_id: env.secp_domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
    };
    let outcome = env
        .cluster
        .send_verify_foreign_transaction(&request)
        .await
        .expect("verify_foreign_transaction (Base) failed");
    verify_foreign_tx_response(&outcome);
}

async fn verify_starknet(env: &ForeignTxTestEnv) {
    let request = VerifyForeignTransactionRequestArgs {
        request: ForeignChainRpcRequest::Starknet(StarknetRpcRequest {
            tx_id: StarknetTxId(StarknetFelt([0xbb; 32])),
            finality: StarknetFinality::AcceptedOnL1,
            extractors: vec![StarknetExtractor::BlockHash],
        }),
        domain_id: env.secp_domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
    };
    let outcome = env
        .cluster
        .send_verify_foreign_transaction(&request)
        .await
        .expect("verify_foreign_transaction (Starknet) failed");
    verify_foreign_tx_response(&outcome);
}

/// Sets up a single 2-node cluster with mock RPC servers for all chains,
/// then submits verify_foreign_transaction requests for Bitcoin, Abstract,
/// BNB, Base, and Starknet and verifies the MPC nodes return valid signed responses.
/// Also verifies rejection for unsupported chains and non-existent domains.
#[tokio::test]
#[expect(non_snake_case)]
async fn verify_foreign_transaction__should_sign_all_supported_chains() {
    // Given — 2-node cluster with Bitcoin, Abstract, BNB, Base, and Starknet configured
    let env = setup_foreign_tx_cluster().await;

    // When/Then — all configured chains produce valid signed responses
    verify_bitcoin(&env).await;
    verify_abstract(&env).await;
    verify_bnb(&env).await;
    verify_base(&env).await;
    verify_starknet(&env).await;

    // When — requesting Ethereum, which is not in the foreign chain config
    let request = VerifyForeignTransactionRequestArgs {
        request: ForeignChainRpcRequest::Ethereum(EvmRpcRequest {
            tx_id: EvmTxId([0xbb; 32]),
            extractors: vec![EvmExtractor::BlockHash],
            finality: EvmFinality::Finalized,
        }),
        domain_id: env.secp_domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
    };
    let outcome = env
        .cluster
        .send_verify_foreign_transaction(&request)
        .await
        .expect("call should succeed at the RPC level");

    // Then — the contract rejects the unsupported chain
    assert!(
        !outcome.is_success(),
        "expected verify_foreign_transaction to fail for unsupported chain"
    );
    let failure = outcome.failure_message().unwrap_or_default();
    assert!(
        failure.contains("not supported"),
        "expected 'not supported' error, got: {failure}"
    );

    // When — requesting a non-existent domain
    let request = VerifyForeignTransactionRequestArgs {
        request: ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
            tx_id: BitcoinTxId([0xbb; 32]),
            confirmations: BlockConfirmations(1),
            extractors: vec![BitcoinExtractor::BlockHash],
        }),
        domain_id: DomainId(999),
        payload_version: ForeignTxPayloadVersion::V1,
    };
    let outcome = env
        .cluster
        .send_verify_foreign_transaction(&request)
        .await
        .expect("call should succeed at the RPC level");

    // Then — the contract rejects the unknown domain
    assert!(
        !outcome.is_success(),
        "expected verify_foreign_transaction to fail for non-existent domain"
    );
    let failure = outcome.failure_message().unwrap_or_default();
    assert!(
        failure.contains("not found"),
        "expected 'not found' error, got: {failure}"
    );
}
