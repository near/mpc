use crate::indexer::participants::ContractState;
use crate::p2p::testing::port_seed;
use crate::tests::{
    DEFAULT_BLOCK_TIME, DEFAULT_MAX_PROTOCOL_WAIT_TIME, DEFAULT_MAX_SIGNATURE_WAIT_TIME,
    IntegrationTestSetup, request_verify_foreign_tx_and_await_response,
};
use crate::tracking::AutoAbortTask;
use httpmock::prelude::*;
use httpmock::{HttpMockRequest, HttpMockResponse};
use mpc_node_config::foreign_chains::RpcProviderName;
use mpc_node_config::{
    AuthConfig, ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig,
};
use near_mpc_contract_interface::types::{
    DomainConfig, DomainId, DomainPurpose, Protocol, ReconstructionThreshold,
};
use near_time::Clock;
use std::collections::BTreeSet;
use std::num::NonZeroU64;
use std::time::Duration;

const MOCK_BLOCK_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Serves the three RPC methods the Bitcoin inspector issues, so any
/// tx verification against it succeeds.
fn must_start_bitcoin_rpc_mock() -> MockServer {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST);
        then.respond_with(|req: &HttpMockRequest| {
            let body: serde_json::Value =
                serde_json::from_slice(req.body().as_ref()).expect("valid json-rpc request");
            let id = body["id"].clone();
            let result = match body["method"].as_str().expect("method field") {
                "getrawtransaction" => serde_json::json!({
                    "blockhash": MOCK_BLOCK_HASH,
                    "confirmations": 10,
                }),
                "getblockheader" => serde_json::json!({
                    "hash": MOCK_BLOCK_HASH,
                    "height": 800_000,
                }),
                "getblockhash" => serde_json::Value::String(MOCK_BLOCK_HASH.to_string()),
                other => panic!("unexpected bitcoin rpc method: {other}"),
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

fn bitcoin_only_config(rpc_url: &str) -> ForeignChainsConfig {
    let providers = near_mpc_bounded_collections::NonEmptyBTreeMap::new(
        RpcProviderName::from("public".to_string()),
        ForeignChainProviderConfig {
            rpc_url: rpc_url.parse().unwrap(),
            auth: AuthConfig::None,
        },
    );
    ForeignChainsConfig {
        bitcoin: Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            providers,
        }),
        solana: None,
        ethereum: None,
        abstract_chain: None,
        starknet: None,
        bnb: None,
        base: None,
        arbitrum: None,
        hyper_evm: None,
        polygon: None,
        aptos: None,
        sui: None,
    }
}

#[tokio::test]
#[test_log::test]
#[expect(non_snake_case)]
async fn verify_foreign_tx__should_only_be_served_while_chain_is_available() {
    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;
    const SUPPORTERS_PUBLISH_WAIT: Duration = Duration::from_secs(10);
    const UNAVAILABLE_RESPONSE_WAIT: Duration = Duration::from_secs(15);

    // Given: four nodes with a mocked Bitcoin RPC (so inspection would
    // succeed) and a ForeignTx domain whose reconstruction threshold is met
    // by all four auto-registrations.
    let rpc_mock = must_start_bitcoin_rpc_mock();
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
        config.config.foreign_chains = bitcoin_only_config(&rpc_mock.base_url());
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

    // Sanity: the request is served while Bitcoin is available.
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

    // When: two nodes drop their registration, taking Bitcoin below the
    // ForeignTx reconstruction threshold.
    let rejections_before =
        crate::metrics::MPC_NUM_VERIFY_FOREIGN_TX_UNAVAILABLE_CHAIN_REJECTIONS.get();
    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.register_foreign_chains_config("test2".parse().unwrap(), BTreeSet::new().into());
        contract.register_foreign_chains_config("test3".parse().unwrap(), BTreeSet::new().into());
        assert!(contract.available_foreign_chains().is_empty());
    }
    // Wait for the fake core to publish the post-change snapshot on the shared
    // upstream channel; the per-node resolver fan-out from it is in-process and
    // subsumed by the response wait below.
    let mut supporters = setup.indexer.subscribe_foreign_chain_supporters();
    tokio::time::timeout(SUPPORTERS_PUBLISH_WAIT, async {
        while !supporters.borrow_and_update().is_empty() {
            supporters.changed().await.unwrap();
        }
    })
    .await
    .expect("timed out waiting for the empty supporters snapshot to publish");

    // Then: nodes reject the request against their supporters snapshot,
    // even though inspection itself would succeed. The distinct tx id keeps
    // stray duplicate responses from the first request from matching.
    assert!(
        request_verify_foreign_tx_and_await_response(
            &mut setup.indexer,
            "user0",
            &foreign_tx_domain,
            [43u8; 32],
            UNAVAILABLE_RESPONSE_WAIT,
        )
        .await
        .is_none()
    );
    // All nodes run in-process, so the availability gate's rejections are
    // visible in the process-global counter.
    assert!(
        crate::metrics::MPC_NUM_VERIFY_FOREIGN_TX_UNAVAILABLE_CHAIN_REJECTIONS.get()
            > rejections_before,
        "expected the availability gate to reject at least one attempt"
    );
}
