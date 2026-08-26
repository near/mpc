use std::collections::BTreeMap;
use std::num::NonZeroU64;

use crate::common;

use anyhow::Context;
use e2e_tests::cluster::placeholder_chain_entry;
use e2e_tests::foreign_chain_mock::{
    MOCK_BLOCK_HASH, MockAuthExpectation, MockServerExt, setup_bitcoin_mock, setup_evm_mock,
    setup_starknet_mock,
};
use httpmock::prelude::*;
use mpc_node_config::{
    AuthConfig, ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig, TokenConfig,
    foreign_chains::RpcProviderName,
};
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types::{
    BitcoinExtractor, BitcoinRpcRequest, BitcoinTxId, BlockConfirmations, DomainConfig, DomainId,
    DomainPurpose, EvmExtractor, EvmFinality, EvmRpcRequest, EvmTxId, ForeignChain,
    ForeignChainRpcRequest, ForeignTxPayloadVersion, Protocol, ReconstructionThreshold,
    SolanaFinality, SolanaRpcRequest, SolanaTxId, StarknetExtractor, StarknetFelt,
    StarknetFinality, StarknetRpcRequest, StarknetTxId, VerifyForeignTransactionRequestArgs,
    VerifyForeignTransactionResponse,
};
use near_mpc_sdk::foreign_chain::ForeignChainRequestBuilder;

/// One chain per credential-carrying [`AuthConfig`] kind: Bitcoin uses `path`,
/// Base `header`, BNB `query`; the remaining chains use `None`.
const PATH_AUTH_PLACEHOLDER: &str = "{api_key}";
const PATH_AUTH_API_KEY: &str = "bitcoin-path-api-key";
const HEADER_AUTH_NAME: &str = "authorization";
const HEADER_AUTH_SCHEME: &str = "Bearer";
const HEADER_AUTH_TOKEN: &str = "base-bearer-token";
const QUERY_AUTH_PARAM: &str = "apikey";
const QUERY_AUTH_TOKEN: &str = "bnb-query-token";

struct ForeignTxTestEnv {
    cluster: e2e_tests::MpcCluster,
    foreign_tx_domain_id: DomainId,
    _mock_servers: Vec<MockServer>,
    /// Polygon is configured with multiple RPC providers so the test can verify
    /// that [`FanOut`] queries every one of them.
    polygon_mocks: Vec<MockServerExt>,
    bitcoin_mock: MockServerExt,
    base_mock: MockServerExt,
    bnb_mock: MockServerExt,
}

struct MockServerUrls {
    bitcoin: String,
    abstract_chain: String,
    bnb: String,
    starknet: String,
    base: String,
    arbitrum: String,
    hyper_evm: String,
    avalanche: String,
    adi: String,
    ethereum: String,
    polygon: Vec<String>,
}

/// A chain served by a single `"mock"` provider at `rpc_url`.
fn mock_chain(rpc_url: &str, auth: AuthConfig) -> ForeignChainConfig {
    mock_chain_with_providers(NonEmptyBTreeMap::new(
        "mock".to_string().into(),
        ForeignChainProviderConfig {
            rpc_url: rpc_url.to_string(),
            auth,
        },
    ))
}

fn mock_chain_with_providers(
    providers: NonEmptyBTreeMap<RpcProviderName, ForeignChainProviderConfig>,
) -> ForeignChainConfig {
    ForeignChainConfig {
        timeout_sec: NonZeroU64::new(30).unwrap(),
        max_retries: NonZeroU64::new(3).unwrap(),
        // The mocks serve inspector calls, not identity queries, so there is nothing to check.
        expected_network_fingerprint: None,
        providers,
    }
}

fn build_foreign_chains_config(urls: &MockServerUrls) -> ForeignChainsConfig {
    ForeignChainsConfig {
        bitcoin: Some(mock_chain(
            &urls.bitcoin,
            AuthConfig::Path {
                placeholder: PATH_AUTH_PLACEHOLDER.to_string(),
                token: TokenConfig::Val {
                    val: PATH_AUTH_API_KEY.to_string(),
                },
            },
        )),
        abstract_chain: Some(mock_chain(&urls.abstract_chain, Default::default())),
        bnb: Some(mock_chain(
            &urls.bnb,
            AuthConfig::Query {
                name: QUERY_AUTH_PARAM.to_string(),
                token: TokenConfig::Val {
                    val: QUERY_AUTH_TOKEN.to_string(),
                },
            },
        )),
        starknet: Some(mock_chain(&urls.starknet, Default::default())),
        base: Some(mock_chain(
            &urls.base,
            AuthConfig::Header {
                name: HEADER_AUTH_NAME.parse().expect("valid header name"),
                scheme: Some(HEADER_AUTH_SCHEME.to_string()),
                token: TokenConfig::Val {
                    val: HEADER_AUTH_TOKEN.to_string(),
                },
            },
        )),
        arbitrum: Some(mock_chain(&urls.arbitrum, Default::default())),
        hyper_evm: Some(mock_chain(&urls.hyper_evm, Default::default())),
        avalanche: Some(mock_chain(&urls.avalanche, Default::default())),
        adi: Some(mock_chain(&urls.adi, Default::default())),
        ethereum: Some(mock_chain(&urls.ethereum, Default::default())),
        polygon: Some(mock_chain_with_providers(
            common::build_providers_from_urls(&urls.polygon, "polygon"),
        )),
        ..Default::default()
    }
}

async fn must_setup_foreign_tx_cluster() -> ForeignTxTestEnv {
    let bitcoin_server = MockServer::start();
    let abstract_server = MockServer::start();
    let bnb_server = MockServer::start();
    let starknet_server = MockServer::start();
    let base_server = MockServer::start();
    let arbitrum_server = MockServer::start();
    let hyper_evm_server = MockServer::start();
    let avalanche_server = MockServer::start();
    let adi_server = MockServer::start();
    let ethereum_server = MockServer::start();

    let bitcoin_mock_id = setup_bitcoin_mock(
        &bitcoin_server,
        MockAuthExpectation::ApiKeyInPath {
            key: PATH_AUTH_API_KEY.to_string(),
        },
    );
    let base_mock_id = setup_evm_mock(
        &base_server,
        MockAuthExpectation::Header {
            name: HEADER_AUTH_NAME.to_string(),
            value: format!("{HEADER_AUTH_SCHEME} {HEADER_AUTH_TOKEN}"),
        },
    );
    let bnb_mock_id = setup_evm_mock(
        &bnb_server,
        MockAuthExpectation::QueryParam {
            name: QUERY_AUTH_PARAM.to_string(),
            value: QUERY_AUTH_TOKEN.to_string(),
        },
    );
    setup_evm_mock(&abstract_server, MockAuthExpectation::None);
    setup_starknet_mock(&starknet_server, MockAuthExpectation::None);
    setup_evm_mock(&arbitrum_server, MockAuthExpectation::None);
    setup_evm_mock(&hyper_evm_server, MockAuthExpectation::None);
    setup_evm_mock(&avalanche_server, MockAuthExpectation::None);
    setup_evm_mock(&adi_server, MockAuthExpectation::None);
    setup_evm_mock(&ethereum_server, MockAuthExpectation::None);

    // Polygon is configured with three RPC providers so the test can assert
    // that `FanOut` queries every one of them.
    let polygon_mocks: Vec<MockServerExt> = (0..3)
        .map(|_| {
            let server = MockServer::start();
            let mock_id = setup_evm_mock(&server, MockAuthExpectation::None);
            MockServerExt::new(server, mock_id)
        })
        .collect();

    let urls = MockServerUrls {
        // The configured URL carries the literal placeholder; the node must
        // substitute the API key into it before any request can match the mock.
        bitcoin: bitcoin_server.url(format!("/{PATH_AUTH_PLACEHOLDER}")),
        abstract_chain: abstract_server.url("/"),
        bnb: bnb_server.url("/"),
        starknet: starknet_server.url("/"),
        base: base_server.url("/"),
        arbitrum: arbitrum_server.url("/"),
        hyper_evm: hyper_evm_server.url("/"),
        avalanche: avalanche_server.url("/"),
        adi: adi_server.url("/"),
        ethereum: ethereum_server.url("/"),
        polygon: polygon_mocks.iter().map(|m| m.server.url("/")).collect(),
    };

    let bitcoin_mock = MockServerExt::new(bitcoin_server, bitcoin_mock_id);
    let base_mock = MockServerExt::new(base_server, base_mock_id);
    let bnb_mock = MockServerExt::new(bnb_server, bnb_mock_id);
    let mock_servers = vec![
        abstract_server,
        starknet_server,
        arbitrum_server,
        hyper_evm_server,
        avalanche_server,
        adi_server,
        ethereum_server,
    ];

    let fc_config = build_foreign_chains_config(&urls);

    let whitelist: BTreeMap<_, _> = [
        ForeignChain::Bitcoin,
        ForeignChain::Abstract,
        ForeignChain::Bnb,
        ForeignChain::Starknet,
        ForeignChain::Base,
        ForeignChain::Arbitrum,
        ForeignChain::HyperEvm,
        ForeignChain::Avalanche,
        ForeignChain::Adi,
        ForeignChain::Ethereum,
        ForeignChain::Polygon,
    ]
    .into_iter()
    .map(|chain| (chain, placeholder_chain_entry(chain)))
    .collect();
    let expected_chains: std::collections::BTreeSet<ForeignChain> =
        whitelist.keys().copied().collect();

    let (cluster, _running) =
        common::must_setup_cluster(common::FOREIGN_TX_VALIDATION_PORT_SEED, |c| {
            c.num_nodes = 2;
            c.threshold = 2;
            c.domains = vec![DomainConfig {
                id: DomainId(0),
                protocol: Protocol::CaitSith,
                reconstruction_threshold: ReconstructionThreshold::new(2),
                purpose: DomainPurpose::ForeignTx,
            }];
            c.foreign_chains.node_configs = vec![fc_config.clone(), fc_config];
            c.foreign_chains.whitelist = whitelist.clone();
        })
        .await;

    cluster
        .wait_for_available_foreign_chains(&expected_chains)
        .await
        .expect("timed out waiting for all chains to become available");

    // TODO(#3630): drop the legacy view once deprecated API is dropped.
    let supported = cluster
        .view_foreign_chains_supported_by_contract()
        .await
        .expect("failed to view supported chains");
    assert_eq!(*supported, expected_chains, "supported chains mismatch");
    let allowed = cluster
        .view_allowed_foreign_chain_providers()
        .await
        .expect("failed to view allowed foreign chain providers");
    assert_eq!(allowed, whitelist, "allowed providers mismatch");

    let state = cluster
        .get_contract_state()
        .await
        .expect("failed to get contract state");
    let near_mpc_contract_interface::types::ProtocolContractState::Running(running) = &state else {
        panic!("expected Running state, got {state:?}");
    };
    let foreign_tx_domain_id = running
        .domains
        .domains
        .iter()
        .find(|d| d.purpose == DomainPurpose::ForeignTx)
        .expect("no ForeignTx domain")
        .id;

    ForeignTxTestEnv {
        cluster,
        foreign_tx_domain_id,
        _mock_servers: mock_servers,
        polygon_mocks,
        bitcoin_mock,
        base_mock,
        bnb_mock,
    }
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
        domain_id: env.foreign_tx_domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: None,
    };
    let outcome = env
        .cluster
        .send_verify_foreign_transaction(&request)
        .await
        .context("verify_foreign_transaction (Bitcoin) failed")?;
    verify_foreign_tx_response(&outcome)
}

/// Submits a request built by the SDK, bound to the payload hash the SDK derives
/// from the expected extracted values. The nodes derive the payload independently
/// and the contract rejects a response whose hash differs from the request's
/// expectation, so this passing proves the SDK and the node agree on the payload
/// encoding.
async fn verify_bitcoin_bound_to_expected_payload_hash(
    env: &ForeignTxTestEnv,
) -> anyhow::Result<()> {
    let mock_block_hash: [u8; 32] = hex::decode(MOCK_BLOCK_HASH)
        .context("MOCK_BLOCK_HASH must be valid hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("MOCK_BLOCK_HASH must be 32 bytes"))?;
    let (_verifier, request) = ForeignChainRequestBuilder::new_bitcoin()
        .with_tx_id(BitcoinTxId([0xbb; 32]))
        .with_block_confirmations(1)
        .with_expected_block_hash(mock_block_hash)
        .with_domain_id(env.foreign_tx_domain_id)
        .build()
        .context("SDK request builder failed")?;
    anyhow::ensure!(
        request.expected_payload_hash.is_some(),
        "the SDK builder must bind the request to an expected payload hash"
    );

    let outcome = env
        .cluster
        .send_verify_foreign_transaction(&request)
        .await
        .context("verify_foreign_transaction (Bitcoin, hash-bound) failed")?;
    verify_foreign_tx_response(&outcome)?;

    let response: VerifyForeignTransactionResponse = outcome
        .json()
        .context("failed to parse verify_foreign_transaction response")?;
    anyhow::ensure!(
        Some(&response.payload_hash) == request.expected_payload_hash.as_ref(),
        "response payload hash must equal the SDK-computed expectation"
    );
    Ok(())
}

async fn verify_abstract(env: &ForeignTxTestEnv) -> anyhow::Result<()> {
    let request = VerifyForeignTransactionRequestArgs {
        request: ForeignChainRpcRequest::Abstract(EvmRpcRequest {
            tx_id: EvmTxId([0xbb; 32]),
            extractors: vec![EvmExtractor::BlockHash, EvmExtractor::Log { log_index: 0 }],
            finality: EvmFinality::Finalized,
        }),
        domain_id: env.foreign_tx_domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: None,
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
        domain_id: env.foreign_tx_domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: None,
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
        domain_id: env.foreign_tx_domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: None,
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
        domain_id: env.foreign_tx_domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: None,
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
        domain_id: env.foreign_tx_domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: None,
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
        domain_id: env.foreign_tx_domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: None,
    };
    let outcome = env
        .cluster
        .send_verify_foreign_transaction(&request)
        .await
        .context("verify_foreign_transaction (HyperEVM) failed")?;
    verify_foreign_tx_response(&outcome)
}

async fn verify_avalanche(env: &ForeignTxTestEnv) -> anyhow::Result<()> {
    let request = VerifyForeignTransactionRequestArgs {
        request: ForeignChainRpcRequest::Avalanche(EvmRpcRequest {
            tx_id: EvmTxId([0xbb; 32]),
            extractors: vec![EvmExtractor::BlockHash, EvmExtractor::Log { log_index: 0 }],
            finality: EvmFinality::Finalized,
        }),
        domain_id: env.foreign_tx_domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: None,
    };
    let outcome = env
        .cluster
        .send_verify_foreign_transaction(&request)
        .await
        .context("verify_foreign_transaction (Avalanche) failed")?;
    verify_foreign_tx_response(&outcome)
}

async fn verify_adi(env: &ForeignTxTestEnv) -> anyhow::Result<()> {
    let request = VerifyForeignTransactionRequestArgs {
        request: ForeignChainRpcRequest::Adi(EvmRpcRequest {
            tx_id: EvmTxId([0xbb; 32]),
            extractors: vec![EvmExtractor::BlockHash, EvmExtractor::Log { log_index: 0 }],
            finality: EvmFinality::Finalized,
        }),
        domain_id: env.foreign_tx_domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: None,
    };
    let outcome = env
        .cluster
        .send_verify_foreign_transaction(&request)
        .await
        .context("verify_foreign_transaction (ADI) failed")?;
    verify_foreign_tx_response(&outcome)
}

async fn verify_ethereum(env: &ForeignTxTestEnv) -> anyhow::Result<()> {
    let request = VerifyForeignTransactionRequestArgs {
        request: ForeignChainRpcRequest::Ethereum(EvmRpcRequest {
            tx_id: EvmTxId([0xbb; 32]),
            extractors: vec![EvmExtractor::BlockHash, EvmExtractor::Log { log_index: 0 }],
            finality: EvmFinality::Finalized,
        }),
        domain_id: env.foreign_tx_domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: None,
    };
    let outcome = env
        .cluster
        .send_verify_foreign_transaction(&request)
        .await
        .context("verify_foreign_transaction (Ethereum) failed")?;
    verify_foreign_tx_response(&outcome)
}

/// A successful verification implies the credentialed mock answered,
/// so this is a backstop against the mock setup being loosened to answer unauthenticated requests.
fn assert_authenticated_provider_was_queried(mock: &MockServerExt, provider: &str) {
    let calls = mock.calls();
    assert!(
        calls > 0,
        "the {provider} mock was never hit with the expected credentials; \
         expected >= 1 matching RPC request, got {calls}"
    );
}

/// Verifies that every Polygon RPC provider configured in the fan-out received
/// at least one HTTP request during the preceding `verify_polygon` call.
///
/// A regression in [`FanOut`] (e.g. routing each verify request to a single
/// provider instead of fanning out to all of them) would leave at least one
/// mock untouched and this assertion would fail.
fn assert_fan_out_queried_every_polygon_provider(env: &ForeignTxTestEnv) {
    for (i, polygon) in env.polygon_mocks.iter().enumerate() {
        let calls = polygon.calls();
        assert!(
            calls > 0,
            "polygon provider #{i} was not queried by FanOut; expected >= 1 RPC hit, got {calls}"
        );
    }
}

async fn verify_polygon(env: &ForeignTxTestEnv) -> anyhow::Result<()> {
    let request = VerifyForeignTransactionRequestArgs {
        request: ForeignChainRpcRequest::Polygon(EvmRpcRequest {
            tx_id: EvmTxId([0xbb; 32]),
            extractors: vec![EvmExtractor::BlockHash, EvmExtractor::Log { log_index: 0 }],
            finality: EvmFinality::Finalized,
        }),
        domain_id: env.foreign_tx_domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: None,
    };
    let outcome = env
        .cluster
        .send_verify_foreign_transaction(&request)
        .await
        .context("verify_foreign_transaction (Polygon) failed")?;
    verify_foreign_tx_response(&outcome)
}

/// Verifies all supported chains sign, and unsupported chains and non-existent
/// domains are rejected. Bitcoin, Base and BNB require authentication (one per
/// credential-carrying [`AuthConfig`] kind), proving the node applies configured
/// RPC credentials end to end.
#[tokio::test]
#[expect(non_snake_case)]
async fn verify_foreign_transaction__should_sign_all_supported_chains() {
    // Given — 2-node cluster with Bitcoin, Abstract, BNB, Base, Starknet,
    // Arbitrum, HyperEVM, Avalanche, ADI, Ethereum, and Polygon configured
    let env = must_setup_foreign_tx_cluster().await;

    // When/Then — all configured chains produce valid signed responses
    verify_bitcoin(&env)
        .await
        .expect("bitcoin verification failed");
    assert_authenticated_provider_was_queried(&env.bitcoin_mock, "bitcoin (path auth)");
    verify_bitcoin_bound_to_expected_payload_hash(&env)
        .await
        .expect("hash-bound bitcoin verification failed");
    verify_abstract(&env)
        .await
        .expect("abstract verification failed");
    verify_bnb(&env).await.expect("bnb verification failed");
    assert_authenticated_provider_was_queried(&env.bnb_mock, "bnb (query auth)");
    verify_base(&env).await.expect("base verification failed");
    assert_authenticated_provider_was_queried(&env.base_mock, "base (header auth)");
    verify_starknet(&env)
        .await
        .expect("starknet verification failed");
    verify_arbitrum(&env)
        .await
        .expect("arbitrum verification failed");
    verify_hyper_evm(&env)
        .await
        .expect("hyper_evm verification failed");
    verify_avalanche(&env)
        .await
        .expect("avalanche verification failed");
    verify_adi(&env).await.expect("adi verification failed");
    verify_ethereum(&env)
        .await
        .expect("ethereum verification failed");
    verify_polygon(&env)
        .await
        .expect("polygon verification failed");
    assert_fan_out_queried_every_polygon_provider(&env);

    // When — requesting Solana, which is not in the foreign chain config
    let request = VerifyForeignTransactionRequestArgs {
        request: ForeignChainRpcRequest::Solana(SolanaRpcRequest {
            tx_id: SolanaTxId([0xbb; 64]),
            finality: SolanaFinality::Finalized,
            extractors: vec![],
        }),
        domain_id: env.foreign_tx_domain_id,
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: None,
    };
    let outcome = env
        .cluster
        .send_verify_foreign_transaction(&request)
        .await
        .expect("call should succeed at the RPC level");

    // Then — the contract rejects the unavailable chain
    assert!(
        !outcome.is_success(),
        "expected verify_foreign_transaction to fail for unavailable chain"
    );
    let failure = outcome.failure_message().unwrap_or_default();
    assert!(
        failure.contains("Requested foreign chain, Solana, is not available"),
        "expected 'is not available' error, got: {failure}"
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
        expected_payload_hash: None,
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
