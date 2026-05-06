use std::num::NonZeroU64;

use crate::common;

use anyhow::{Context, bail};
use backon::{ConstantBuilder, Retryable};
use e2e_tests::CLUSTER_WAIT_TIMEOUT;
use e2e_tests::foreign_chain_mock::{setup_bitcoin_mock, setup_evm_mock, setup_starknet_mock};
use httpmock::prelude::*;
use mpc_node_config::{ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig};
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types::{
    BitcoinExtractor, BitcoinRpcRequest, BitcoinTxId, BlockConfirmations, Curve, DomainConfig,
    DomainId, DomainPurpose, EvmExtractor, EvmFinality, EvmRpcRequest, EvmTxId, ForeignChain,
    ForeignChainRpcRequest, ForeignTxPayloadVersion, Protocol, StarknetExtractor, StarknetFelt,
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
    arbitrum: String,
    hyper_evm: String,
    polygon: String,
}

fn build_foreign_chains_config(urls: &MockServerUrls) -> ForeignChainsConfig {
    ForeignChainsConfig {
        bitcoin: Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers: NonEmptyBTreeMap::new(
                "mock".to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url: urls.bitcoin.clone(),
                    auth: Default::default(),
                },
            ),
        }),
        abstract_chain: Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers: NonEmptyBTreeMap::new(
                "mock".to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url: urls.abstract_chain.clone(),
                    auth: Default::default(),
                },
            ),
        }),
        bnb: Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers: NonEmptyBTreeMap::new(
                "mock".to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url: urls.bnb.clone(),
                    auth: Default::default(),
                },
            ),
        }),
        starknet: Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers: NonEmptyBTreeMap::new(
                "mock".to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url: urls.starknet.clone(),
                    auth: Default::default(),
                },
            ),
        }),
        base: Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers: NonEmptyBTreeMap::new(
                "mock".to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url: urls.base.clone(),
                    auth: Default::default(),
                },
            ),
        }),
        arbitrum: Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers: NonEmptyBTreeMap::new(
                "mock".to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url: urls.arbitrum.clone(),
                    auth: Default::default(),
                },
            ),
        }),
        hyper_evm: Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers: NonEmptyBTreeMap::new(
                "mock".to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url: urls.hyper_evm.clone(),
                    auth: Default::default(),
                },
            ),
        }),
        polygon: Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers: NonEmptyBTreeMap::new(
                "mock".to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url: urls.polygon.clone(),
                    auth: Default::default(),
                },
            ),
        }),
        ..Default::default()
    }
}

async fn setup_foreign_tx_cluster() -> anyhow::Result<ForeignTxTestEnv> {
    let bitcoin_server = MockServer::start();
    let abstract_server = MockServer::start();
    let bnb_server = MockServer::start();
    let starknet_server = MockServer::start();
    let base_server = MockServer::start();
    let arbitrum_server = MockServer::start();
    let hyper_evm_server = MockServer::start();
    let polygon_server = MockServer::start();

    setup_bitcoin_mock(&bitcoin_server);
    setup_evm_mock(&abstract_server);
    setup_evm_mock(&bnb_server);
    setup_starknet_mock(&starknet_server);
    setup_evm_mock(&base_server);
    setup_evm_mock(&arbitrum_server);
    setup_evm_mock(&hyper_evm_server);
    setup_evm_mock(&polygon_server);

    let urls = MockServerUrls {
        bitcoin: bitcoin_server.url("/"),
        abstract_chain: abstract_server.url("/"),
        bnb: bnb_server.url("/"),
        starknet: starknet_server.url("/"),
        base: base_server.url("/"),
        arbitrum: arbitrum_server.url("/"),
        hyper_evm: hyper_evm_server.url("/"),
        polygon: polygon_server.url("/"),
    };

    let mock_servers = vec![
        bitcoin_server,
        abstract_server,
        bnb_server,
        starknet_server,
        base_server,
        arbitrum_server,
        hyper_evm_server,
        polygon_server,
    ];

    let fc_config = build_foreign_chains_config(&urls);

    let (cluster, _running) =
        common::must_setup_cluster(common::FOREIGN_TX_VALIDATION_PORT_SEED, |c| {
            c.num_nodes = 2;
            c.threshold = 2;
            c.domains = vec![DomainConfig {
                id: DomainId(0),
                curve: Curve::Secp256k1,
                protocol: Protocol::CaitSith,
                purpose: DomainPurpose::ForeignTx,
            }];
            c.node_foreign_chains_configs = vec![fc_config.clone(), fc_config];
        })
        .await;

    let expected_supported_chains: std::collections::BTreeSet<ForeignChain> = [
        ForeignChain::Bitcoin,
        ForeignChain::Abstract,
        ForeignChain::Bnb,
        ForeignChain::Starknet,
        ForeignChain::Base,
        ForeignChain::Arbitrum,
        ForeignChain::HyperEvm,
        ForeignChain::Polygon,
    ]
    .into_iter()
    .collect();

    (|| async {
        let supported = cluster
            .view_foreign_chains_supported_by_contract()
            .await
            .context("failed to view supported chains")?;
        let supported_set: std::collections::BTreeSet<ForeignChain> =
            supported.iter().copied().collect();
        anyhow::ensure!(
            supported_set == expected_supported_chains,
            "expected supported chains {:?}, got {:?}",
            expected_supported_chains,
            supported_set
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
    .context("timed out waiting for every participant to register its foreign chains")?;

    let state = cluster
        .get_contract_state()
        .await
        .context("failed to get contract state")?;
    let running = match &state {
        near_mpc_contract_interface::types::ProtocolContractState::Running(r) => r,
        _ => bail!("expected Running state"),
    };
    let secp_domain_id = running
        .domains
        .domains
        .iter()
        .find(|d| d.curve == Curve::Secp256k1)
        .context("no Secp256k1 domain")?
        .id;

    Ok(ForeignTxTestEnv {
        cluster,
        secp_domain_id,
        _mock_servers: mock_servers,
    })
}

fn verify_foreign_tx_response(outcome: &near_kit::FinalExecutionOutcome) -> anyhow::Result<()> {
    anyhow::ensure!(
        outcome.is_success(),
        "verify_foreign_transaction failed: {:?}",
        outcome.failure_message()
    );

    let response: serde_json::Value = outcome
        .json()
        .context("failed to parse verify_foreign_transaction response")?;

    tracing::info!(?response, "verify_foreign_transaction response");

    let payload_hash = response["payload_hash"]
        .as_str()
        .context("expected payload_hash string")?;
    anyhow::ensure!(
        payload_hash.len() == 64,
        "expected 64 hex chars in payload_hash, got {}",
        payload_hash.len()
    );

    let signature = &response["signature"];
    let scheme = signature["scheme"]
        .as_str()
        .context("signature.scheme missing")?;
    anyhow::ensure!(
        scheme == "Secp256k1",
        "expected Secp256k1 signature scheme, got {scheme}"
    );
    anyhow::ensure!(
        signature.get("big_r").is_some(),
        "expected big_r in signature"
    );
    anyhow::ensure!(signature.get("s").is_some(), "expected s in signature");
    anyhow::ensure!(
        signature.get("recovery_id").is_some(),
        "expected recovery_id in signature"
    );
    Ok(())
}

async fn verify_bitcoin(env: &ForeignTxTestEnv) -> anyhow::Result<()> {
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
        .context("verify_foreign_transaction (Bitcoin) failed")?;
    verify_foreign_tx_response(&outcome)
}

async fn verify_abstract(env: &ForeignTxTestEnv) -> anyhow::Result<()> {
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
        .context("verify_foreign_transaction (Abstract) failed")?;
    verify_foreign_tx_response(&outcome)
}

async fn verify_bnb(env: &ForeignTxTestEnv) -> anyhow::Result<()> {
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
        .context("verify_foreign_transaction (Bnb) failed")?;
    verify_foreign_tx_response(&outcome)
}

async fn verify_base(env: &ForeignTxTestEnv) -> anyhow::Result<()> {
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
        .context("verify_foreign_transaction (Base) failed")?;
    verify_foreign_tx_response(&outcome)
}

async fn verify_starknet(env: &ForeignTxTestEnv) -> anyhow::Result<()> {
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
        .context("verify_foreign_transaction (Starknet) failed")?;
    verify_foreign_tx_response(&outcome)
}

async fn verify_arbitrum(env: &ForeignTxTestEnv) -> anyhow::Result<()> {
    let request = VerifyForeignTransactionRequestArgs {
        request: ForeignChainRpcRequest::Arbitrum(EvmRpcRequest {
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
        .context("verify_foreign_transaction (Arbitrum) failed")?;
    verify_foreign_tx_response(&outcome)
}

async fn verify_hyper_evm(env: &ForeignTxTestEnv) -> anyhow::Result<()> {
    let request = VerifyForeignTransactionRequestArgs {
        request: ForeignChainRpcRequest::HyperEvm(EvmRpcRequest {
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
        .context("verify_foreign_transaction (HyperEVM) failed")?;
    verify_foreign_tx_response(&outcome)
}

async fn verify_polygon(env: &ForeignTxTestEnv) -> anyhow::Result<()> {
    let request = VerifyForeignTransactionRequestArgs {
        request: ForeignChainRpcRequest::Polygon(EvmRpcRequest {
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
        .context("verify_foreign_transaction (Polygon) failed")?;
    verify_foreign_tx_response(&outcome)
}

/// Sets up a single 2-node cluster with mock RPC servers for all chains,
/// then submits verify_foreign_transaction requests for Bitcoin, Abstract,
/// BNB, Base, and Starknet and verifies the MPC nodes return valid signed responses.
/// Also verifies rejection for unsupported chains and non-existent domains.
#[tokio::test]
#[expect(non_snake_case)]
async fn verify_foreign_transaction__should_sign_all_supported_chains() {
    // Given — 2-node cluster with Bitcoin, Abstract, BNB, Base, and Starknet configured
    let env = setup_foreign_tx_cluster()
        .await
        .expect("setup_foreign_tx_cluster failed");

    // When/Then — all configured chains produce valid signed responses
    verify_bitcoin(&env)
        .await
        .expect("bitcoin verification failed");
    verify_abstract(&env)
        .await
        .expect("abstract verification failed");
    verify_bnb(&env).await.expect("bnb verification failed");
    verify_base(&env).await.expect("base verification failed");
    verify_starknet(&env)
        .await
        .expect("starknet verification failed");
    verify_arbitrum(&env)
        .await
        .expect("arbitrum verification failed");
    verify_hyper_evm(&env)
        .await
        .expect("hyper_evm verification failed");
    verify_polygon(&env)
        .await
        .expect("polygon verification failed");

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
