use crate::common;

use backon::{ConstantBuilder, Retryable};
use e2e_tests::CLUSTER_WAIT_TIMEOUT;
use e2e_tests::E2ePortAllocator;
use e2e_tests::foreign_chain_mock::{
    MOCK_TX_ID, MockServerGuard, bitcoin_rpc_handler, evm_rpc_handler, starknet_rpc_handler,
    start_mock_server,
};
use mpc_node_config::ForeignChainsConfig;
use mpc_node_config::foreign_chains::{
    AbstractApiVariant, AbstractChainConfig, AbstractProviderConfig, BitcoinApiVariant,
    BitcoinChainConfig, BitcoinProviderConfig, BnbApiVariant, BnbChainConfig, BnbProviderConfig,
    StarknetApiVariant, StarknetChainConfig, StarknetProviderConfig,
};
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types::{Curve, DomainConfig, DomainId, DomainPurpose};

struct ForeignTxTestEnv {
    cluster: e2e_tests::MpcCluster,
    secp_domain_id: DomainId,
    _guards: Vec<MockServerGuard>,
}

fn build_foreign_chains_config(ports: &E2ePortAllocator) -> ForeignChainsConfig {
    ForeignChainsConfig {
        bitcoin: Some(BitcoinChainConfig {
            timeout_sec: 30,
            max_retries: 3,
            providers: NonEmptyBTreeMap::new(
                "mock".to_string(),
                BitcoinProviderConfig {
                    rpc_url: format!("http://127.0.0.1:{}", ports.mock_bitcoin_rpc_port()),
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
                    rpc_url: format!("http://127.0.0.1:{}", ports.mock_abstract_rpc_port()),
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
                    rpc_url: format!("http://127.0.0.1:{}", ports.mock_bnb_rpc_port()),
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
                    rpc_url: format!("http://127.0.0.1:{}", ports.mock_starknet_rpc_port()),
                    api_variant: StarknetApiVariant::Standard,
                    auth: Default::default(),
                },
            ),
        }),
        ..Default::default()
    }
}

async fn setup_foreign_tx_cluster() -> ForeignTxTestEnv {
    let ports = E2ePortAllocator::new(common::FOREIGN_TX_VALIDATION_PORT_SEED);

    let guards = vec![
        start_mock_server(ports.mock_bitcoin_rpc_port(), bitcoin_rpc_handler).await,
        start_mock_server(ports.mock_abstract_rpc_port(), evm_rpc_handler).await,
        start_mock_server(ports.mock_bnb_rpc_port(), evm_rpc_handler).await,
        start_mock_server(ports.mock_starknet_rpc_port(), starknet_rpc_handler).await,
    ];

    let fc_config = build_foreign_chains_config(&ports);

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
        _guards: guards,
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
    let outcome = env
        .cluster
        .send_verify_foreign_transaction(serde_json::json!({
            "request": {
                "Bitcoin": {
                    "tx_id": MOCK_TX_ID,
                    "confirmations": 1,
                    "extractors": ["BlockHash"],
                }
            },
            "domain_id": env.secp_domain_id,
            "payload_version": 1,
        }))
        .await
        .expect("verify_foreign_transaction (Bitcoin) failed");
    verify_foreign_tx_response(&outcome);
}

async fn verify_abstract(env: &ForeignTxTestEnv) {
    let outcome = env
        .cluster
        .send_verify_foreign_transaction(serde_json::json!({
            "request": {
                "Abstract": {
                    "tx_id": MOCK_TX_ID,
                    "finality": "Finalized",
                    "extractors": ["BlockHash", { "Log": { "log_index": 0 } }],
                }
            },
            "domain_id": env.secp_domain_id,
            "payload_version": 1,
        }))
        .await
        .expect("verify_foreign_transaction (Abstract) failed");
    verify_foreign_tx_response(&outcome);
}

async fn verify_bnb(env: &ForeignTxTestEnv) {
    let outcome = env
        .cluster
        .send_verify_foreign_transaction(serde_json::json!({
            "request": {
                "Bnb": {
                    "tx_id": MOCK_TX_ID,
                    "finality": "Finalized",
                    "extractors": ["BlockHash", { "Log": { "log_index": 0 } }],
                }
            },
            "domain_id": env.secp_domain_id,
            "payload_version": 1,
        }))
        .await
        .expect("verify_foreign_transaction (Bnb) failed");
    verify_foreign_tx_response(&outcome);
}

async fn verify_starknet(env: &ForeignTxTestEnv) {
    let outcome = env
        .cluster
        .send_verify_foreign_transaction(serde_json::json!({
            "request": {
                "Starknet": {
                    "tx_id": MOCK_TX_ID,
                    "finality": "AcceptedOnL1",
                    "extractors": ["BlockHash"],
                }
            },
            "domain_id": env.secp_domain_id,
            "payload_version": 1,
        }))
        .await
        .expect("verify_foreign_transaction (Starknet) failed");
    verify_foreign_tx_response(&outcome);
}

/// Sets up a single 2-node cluster with mock RPC servers for all chains,
/// then submits verify_foreign_transaction requests for Bitcoin, Abstract,
/// BNB, and Starknet and verifies the MPC nodes return valid signed responses.
#[tokio::test]
#[expect(non_snake_case)]
async fn verify_foreign_transaction__should_sign_all_supported_chains() {
    let env = setup_foreign_tx_cluster().await;

    verify_bitcoin(&env).await;
    verify_abstract(&env).await;
    verify_bnb(&env).await;
    verify_starknet(&env).await;
}
