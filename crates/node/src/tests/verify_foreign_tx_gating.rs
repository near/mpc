use crate::indexer::fake::FakeIndexerManager;
use crate::indexer::participants::ContractState;
use crate::metrics::{ONLINE_PRESIGN_MODE_LABEL, STORED_PRESIGNATURE_MODE_LABEL};
use crate::p2p::testing::{NodeTestPorts, port_seed};
use crate::tests::{
    DEFAULT_BLOCK_TIME, DEFAULT_MAX_PROTOCOL_WAIT_TIME, DEFAULT_MAX_SIGNATURE_WAIT_TIME,
    IntegrationTestSetup, every_node_owns_triples, request_verify_foreign_tx_and_await_response,
    signatures_led, wait_until,
};
use crate::tracking::AutoAbortTask;
use httpmock::prelude::*;
use httpmock::{HttpMockRequest, HttpMockResponse};
use mpc_node_config::foreign_chains::RpcProviderName;
use mpc_node_config::{
    AuthConfig, ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig,
};
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_mpc_contract_interface::types::{
    AuthScheme, ChainEntry, ChainRouting, DomainConfig, DomainId, DomainPurpose, ForeignChain,
    Protocol, ProviderConfig, ProviderId, ReconstructionThreshold,
};
use near_time::Clock;
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use std::time::Duration;

const MOCK_BLOCK_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// Long enough for a served request to answer, so no answer means the request was not served.
const NO_RESPONSE_WAIT: Duration = Duration::from_secs(15);

/// Serves the RPC methods the EVM inspector issues for a block-hash extraction at finality
/// `finalized`, so any tx verification against it succeeds.
fn must_start_ethereum_rpc_mock() -> MockServer {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST);
        then.respond_with(|req: &HttpMockRequest| {
            let body: serde_json::Value =
                serde_json::from_slice(req.body().as_ref()).expect("valid json-rpc request");
            let id = body["id"].clone();
            let result = match body["method"].as_str().expect("method field") {
                "eth_getTransactionReceipt" => serde_json::json!({
                    "transactionHash": body["params"][0],
                    "blockHash": format!("0x{MOCK_BLOCK_HASH}"),
                    "blockNumber": "0xa",
                    "status": "0x1",
                    "logs": [],
                }),
                "eth_getBlockByNumber" => serde_json::json!({
                    "number": if body["params"][0] == "finalized" { "0x64" } else { "0xa" },
                    "hash": format!("0x{MOCK_BLOCK_HASH}"),
                }),
                other => panic!("unexpected ethereum rpc method: {other}"),
            };
            let response_body = serde_json::json!({
                "jsonrpc": "2.0",
                "result": result,
                "id": id,
            });
            HttpMockResponse::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(serde_json::to_string(&response_body).unwrap())
                .build()
        });
    });
    server
}

const ETHEREUM_PROVIDER: &str = "public";

fn ethereum_whitelist(rpc_url: &str) -> BTreeMap<ForeignChain, ChainEntry> {
    BTreeMap::from([(
        ForeignChain::Ethereum,
        ChainEntry {
            providers: NonEmptyBTreeMap::new(
                ProviderId(ETHEREUM_PROVIDER.to_string()),
                ProviderConfig {
                    base_url: rpc_url.to_string(),
                    auth_scheme: AuthScheme::None,
                    chain_routing: ChainRouting::Embedded,
                },
            ),
            quorum: 1,
        },
    )])
}

/// The mock plus a provider nobody runs, with a quorum of two that one local provider cannot reach.
fn ethereum_whitelist_out_of_reach(rpc_url: &str) -> BTreeMap<ForeignChain, ChainEntry> {
    let mut whitelist = ethereum_whitelist(rpc_url);
    let entry = whitelist
        .get_mut(&ForeignChain::Ethereum)
        .expect("ethereum entry");
    entry.providers.insert(
        ProviderId("other".to_string()),
        ProviderConfig {
            base_url: "https://rpc.other.example.com".to_string(),
            auth_scheme: AuthScheme::None,
            chain_routing: ChainRouting::Embedded,
        },
    );
    entry.quorum = 2;
    whitelist
}

fn ethereum_only_config(rpc_url: &str) -> ForeignChainsConfig {
    let providers = NonEmptyBTreeMap::new(
        RpcProviderName::from(ETHEREUM_PROVIDER.to_string()),
        ForeignChainProviderConfig {
            rpc_url: rpc_url.parse().unwrap(),
            auth: AuthConfig::None,
        },
    );
    ForeignChainsConfig {
        ethereum: Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers,
            expected_network_fingerprint: None,
        }),
        solana: None,
        bitcoin: None,
        abstract_chain: None,
        starknet: None,
        bnb: None,
        base: None,
        arbitrum: None,
        hyper_evm: None,
        polygon: None,
        aptos: None,
        sui: None,
        avalanche: None,
        adi: None,
        fogo: None,
        rpc_preset: None,
        credentials: Default::default(),
    }
}

// Tests that nodes only serve a chain while it is available.
//
// Setup is with four nodes with Ethereum RPC while meeting the reconstruction
// threshold; two nodes then drop their registration, taking Ethereum below the
// ForeignTx reconstruction threshold. Leader selection is narrowed to the
// chain's supporters, so no node picks the request up: it parks in the queue
// and never gets a response.
#[tokio::test]
#[test_log::test]
#[expect(non_snake_case)]
async fn verify_foreign_tx__should_only_be_served_while_chain_is_available() {
    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;
    const SUPPORTERS_PUBLISH_WAIT: Duration = Duration::from_secs(10);

    // Given
    let rpc_mock = must_start_ethereum_rpc_mock();
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup: IntegrationTestSetup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        port_seed::VERIFY_FOREIGN_TX_GATING_TEST,
        DEFAULT_BLOCK_TIME,
    );
    for config in &mut setup.configs {
        config.config.foreign_chains = ethereum_only_config(&rpc_mock.base_url());
    }

    let foreign_tx_domain = DomainConfig {
        id: DomainId(0),
        protocol: Protocol::CaitSith,
        reconstruction_threshold: ReconstructionThreshold::new(THRESHOLD as u64),
        purpose: DomainPurpose::ForeignTx,
    };
    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(vec![foreign_tx_domain.clone()]);
        contract.whitelist_foreign_chain_providers(ethereum_whitelist(&rpc_mock.base_url()));
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    setup
        .indexer
        .wait_for_contract_state(
            |state| matches!(state, ContractState::Running(_)),
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("timeout waiting for keygen to complete");

    // Sanity: the request is served while Ethereum is available.
    assert!(
        request_verify_foreign_tx_and_await_response(
            &mut setup.indexer,
            "user0",
            &foreign_tx_domain,
            [42u8; 32],
            DEFAULT_MAX_SIGNATURE_WAIT_TIME,
        )
        .await
        .is_some()
    );

    // When
    let parked_before = crate::requests::metrics::MPC_NUM_REQUESTS_WITHOUT_REFINED_LEADER_TOTAL
        .with_label_values(&["verify_foreign_tx", "ethereum"])
        .get();
    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.register_foreign_chains_config("test2".parse().unwrap(), BTreeSet::new().into());
        contract.register_foreign_chains_config("test3".parse().unwrap(), BTreeSet::new().into());
        assert!(contract.available_foreign_chains().is_empty());
    }
    // Wait for the fake core to publish the post-change value on the shared
    // upstream channel. No extra grace for the per-node resolver fan-out: it
    // is a watch notification, while the request below travels through the fake
    // chain (at least one block), so nodes observe the change before the
    // request can reach them.
    let mut supporters = setup.indexer.subscribe_foreign_chain_supporters();
    tokio::time::timeout(SUPPORTERS_PUBLISH_WAIT, async {
        while !supporters.borrow_and_update().is_empty() {
            supporters.changed().await.unwrap();
        }
    })
    .await
    .expect("timed out waiting for the empty supporters snapshot to publish");

    // Then
    assert!(
        request_verify_foreign_tx_and_await_response(
            &mut setup.indexer,
            "user0",
            &foreign_tx_domain,
            [43u8; 32],
            NO_RESPONSE_WAIT,
        )
        .await
        .is_none()
    );
    // All nodes run in-process, so parked requests are visible in the
    // process-global counter: with no supporters for Ethereum, refinement
    // leaves no eligible leader and the request parks instead of being
    // attempted and rejected.
    assert!(
        crate::requests::metrics::MPC_NUM_REQUESTS_WITHOUT_REFINED_LEADER_TOTAL
            .with_label_values(&["verify_foreign_tx", "ethereum"])
            .get()
            > parked_before,
        "expected the request to park with no refined eligible leader"
    );
}

/// A running 4-node cluster whose only domain is `domain`, a ForeignTx one, so every signature
/// it leads serves a verify-foreign-tx request. Every node owns triples.
struct ForeignTxCluster {
    // Declared first so the nodes stop before the indexer, mock and temp dir they use are dropped.
    _nodes: Vec<AutoAbortTask<anyhow::Result<()>>>,
    indexer: FakeIndexerManager,
    domain: DomainConfig,
    _rpc_mock: MockServer,
    _temp_dir: tempfile::TempDir,
}

/// Starts the cluster with `signature.online_presign` set as given and `whitelist` voted for the
/// mock's URL, and waits until every node owns triples.
async fn must_start_foreign_tx_cluster(
    case: u16,
    online_presign: bool,
    whitelist: fn(&str) -> BTreeMap<ForeignChain, ChainEntry>,
) -> ForeignTxCluster {
    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;

    let rpc_mock = must_start_ethereum_rpc_mock();
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{i}").parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        port_seed::VERIFY_FOREIGN_TX_ONLINE_PRESIGN_TEST.with_case(case),
        DEFAULT_BLOCK_TIME,
    );
    for config in &mut setup.configs {
        config.config.foreign_chains = ethereum_only_config(&rpc_mock.base_url());
        config.config.signature.online_presign = online_presign;
    }
    let domain = DomainConfig {
        id: DomainId(0),
        protocol: Protocol::CaitSith,
        reconstruction_threshold: ReconstructionThreshold::new(THRESHOLD as u64),
        purpose: DomainPurpose::ForeignTx,
    };
    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(vec![domain.clone()]);
        contract.whitelist_foreign_chain_providers(whitelist(&rpc_mock.base_url()));
    }
    let nodes = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect();
    setup
        .indexer
        .wait_for_contract_state(
            |state| matches!(state, ContractState::Running(_)),
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("timeout waiting for keygen to complete");
    wait_until(
        || every_node_owns_triples(NUM_PARTICIPANTS),
        "every node to own triples",
    )
    .await;
    ForeignTxCluster {
        _nodes: nodes,
        indexer: setup.indexer,
        domain,
        _rpc_mock: rpc_mock,
        _temp_dir: temp_dir,
    }
}

#[tokio::test]
#[test_log::test]
#[expect(non_snake_case)]
async fn verify_foreign_tx__should_presign_online_when_online_presign_is_enabled() {
    // Given
    let mut cluster = must_start_foreign_tx_cluster(0, true, ethereum_whitelist).await;
    let online_presign_before = signatures_led(ONLINE_PRESIGN_MODE_LABEL);
    let stored_presignature_before = signatures_led(STORED_PRESIGNATURE_MODE_LABEL);

    // When
    let response = request_verify_foreign_tx_and_await_response(
        &mut cluster.indexer,
        "user0",
        &cluster.domain,
        [42u8; 32],
        DEFAULT_MAX_SIGNATURE_WAIT_TIME,
    )
    .await;

    // Then
    assert!(response.is_some());
    assert!(signatures_led(ONLINE_PRESIGN_MODE_LABEL) > online_presign_before);
    assert_eq!(
        signatures_led(STORED_PRESIGNATURE_MODE_LABEL),
        stored_presignature_before
    );
}

#[tokio::test]
#[test_log::test]
#[expect(non_snake_case)]
async fn verify_foreign_tx__should_sign_from_stored_presignatures_when_online_presign_is_disabled()
{
    // Given
    let mut cluster = must_start_foreign_tx_cluster(1, false, ethereum_whitelist).await;
    let online_presign_before = signatures_led(ONLINE_PRESIGN_MODE_LABEL);
    let stored_presignature_before = signatures_led(STORED_PRESIGNATURE_MODE_LABEL);

    // When
    let response = request_verify_foreign_tx_and_await_response(
        &mut cluster.indexer,
        "user0",
        &cluster.domain,
        [42u8; 32],
        DEFAULT_MAX_SIGNATURE_WAIT_TIME,
    )
    .await;

    // Then
    assert!(response.is_some());
    assert!(signatures_led(STORED_PRESIGNATURE_MODE_LABEL) > stored_presignature_before);
    assert_eq!(
        signatures_led(ONLINE_PRESIGN_MODE_LABEL),
        online_presign_before
    );
}

#[tokio::test]
#[test_log::test]
#[expect(non_snake_case)]
async fn verify_foreign_tx__should_not_be_served_when_local_providers_are_below_the_rpc_quorum() {
    // Given
    let mut cluster = must_start_foreign_tx_cluster(2, true, ethereum_whitelist_out_of_reach).await;
    let rejections_before =
        crate::metrics::MPC_NUM_VERIFY_FOREIGN_TX_NO_RPC_QUORUM_REJECTIONS.get();

    // When
    let response = request_verify_foreign_tx_and_await_response(
        &mut cluster.indexer,
        "user0",
        &cluster.domain,
        [42u8; 32],
        NO_RESPONSE_WAIT,
    )
    .await;

    // Then
    assert!(response.is_none());
    assert!(
        crate::metrics::MPC_NUM_VERIFY_FOREIGN_TX_NO_RPC_QUORUM_REJECTIONS.get()
            > rejections_before,
        "expected the leader to abstain for lack of an RPC quorum"
    );
}
