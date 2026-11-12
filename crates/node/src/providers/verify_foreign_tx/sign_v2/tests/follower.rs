use super::*;
use crate::config::MpcConfig;
use crate::db::SecretDB;
use crate::foreign_chain_policy::SupportersByForeignChain;
use crate::indexer::foreign_chain::ForeignChainWhitelist;
use crate::network::testing::{new_test_client_with_versions, run_test_clients};
use crate::network::wire_format::{MpcMessageKind, MpcTaskId};
use crate::protocol_version::NetworkProtocolVersion;
use crate::providers::EcdsaSignatureProvider;
use crate::storage::{SignRequestStorage, VerifyForeignTransactionRequestStorage};
use crate::tracking::testing::start_root_task_with_periodic_dump;
use httpmock::prelude::*;
use httpmock::{HttpMockRequest, HttpMockResponse};
use mpc_node_config::foreign_chains::RpcProviderName;
use mpc_node_config::{
    AuthConfig, CKDConfig, ConfigFile, ForeignChainConfig, ForeignChainProviderConfig,
    ForeignChainsConfig, IndexerConfig, KeygenConfig, SignatureConfig, SyncMode, TripleBatchSize,
    TripleConfig,
};
use near_indexer_primitives::types::Finality;
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use near_time::Clock;
use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicUsize, Ordering};

const ETHEREUM_PROVIDER: &str = "public";

/// Serves an Ethereum transaction in block 10. The first finality check reports block 5 as
/// final, a transient error, and every later one block 100.
fn start_ethereum_rpc_mock_final_on_second_check() -> MockServer {
    start_ethereum_rpc_mock(|| {})
}

/// Like [`start_ethereum_rpc_mock_final_on_second_check`], and runs `on_rpc_call` before it
/// answers each call.
fn start_ethereum_rpc_mock(on_rpc_call: impl Fn() + Send + Sync + 'static) -> MockServer {
    let server = MockServer::start();
    let finality_checks = Arc::new(AtomicUsize::new(0));
    server.mock(|when, then| {
        when.method(POST);
        then.respond_with(move |req: &HttpMockRequest| {
            on_rpc_call();
            let body: serde_json::Value = serde_json::from_slice(req.body().as_ref()).unwrap();
            let hash = format!("0x{}", hex::encode(MOCK_BLOCK_HASH));
            let result = match body["method"].as_str().unwrap() {
                "eth_getTransactionReceipt" => serde_json::json!({
                    "transactionHash": body["params"][0],
                    "blockHash": hash,
                    "blockNumber": "0xa",
                    "status": "0x1",
                    "logs": [],
                }),
                "eth_getBlockByNumber" if body["params"][0] == "finalized" => {
                    let number = match finality_checks.fetch_add(1, Ordering::SeqCst) {
                        0 => "0x5",
                        _ => "0x64",
                    };
                    serde_json::json!({ "number": number, "hash": hash })
                }
                "eth_getBlockByNumber" => serde_json::json!({ "number": "0xa", "hash": hash }),
                other => panic!("unexpected ethereum rpc method: {other}"),
            };
            HttpMockResponse::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(
                    serde_json::json!({ "jsonrpc": "2.0", "result": result, "id": body["id"] })
                        .to_string(),
                )
                .build()
        });
    });
    server
}

fn config(rpc_url: &str) -> ConfigFile {
    ConfigFile {
        my_near_account_id: "test.near".parse().unwrap(),
        web_ui: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        migration_web_ui: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        pprof_bind_address: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        indexer: IndexerConfig {
            concurrency: 1.try_into().unwrap(),
            finality: Finality::Final,
            mpc_contract_id: "mpc.test.near".parse().unwrap(),
            port_override: None,
            wipe_near_data_token: 0,
            sync_mode: SyncMode::Latest,
            validate_genesis: false,
        },
        triple: TripleConfig {
            concurrency: 1,
            desired_triples_to_buffer: 0,
            parallel_triple_generation_stagger_time_sec: 1,
            timeout_sec: 120,
            batch_size: TripleBatchSize::default(),
        },
        signature: SignatureConfig { timeout_sec: 60 },
        ckd: CKDConfig { timeout_sec: 60 },
        keygen: KeygenConfig { timeout_sec: 60 },
        foreign_chains: ForeignChainsConfig {
            ethereum: Some(ForeignChainConfig {
                timeout_sec: NonZeroU64::new(5).unwrap(),
                max_retries: NonZeroU64::new(1).unwrap(),
                expected_network_fingerprint: None,
                providers: NonEmptyBTreeMap::new(
                    RpcProviderName::from(ETHEREUM_PROVIDER.to_string()),
                    ForeignChainProviderConfig {
                        rpc_url: rpc_url.to_string(),
                        auth: AuthConfig::None,
                    },
                ),
            }),
            ..Default::default()
        },
        cores: None,
        separate_asset_generation_runtime: false,
    }
}

fn whitelist(rpc_url: &str) -> ForeignChainWhitelist {
    BTreeMap::from([(
        dtos::ForeignChain::Ethereum,
        dtos::ChainEntry {
            providers: NonEmptyBTreeMap::new(
                dtos::ProviderId(ETHEREUM_PROVIDER.to_string()),
                dtos::ProviderConfig {
                    base_url: rpc_url.to_string(),
                    auth_scheme: dtos::AuthScheme::None,
                    chain_routing: dtos::ChainRouting::Embedded,
                },
            ),
            quorum: 1,
        },
    )])
}

/// A provider for `client` with no keyshares, whose chain supporters are every participant.
struct TestProvider {
    provider: VerifyForeignTxProvider,
    _db_dir: tempfile::TempDir,
}

impl TestProvider {
    fn new(
        client: Arc<MeshNetworkClient>,
        rpc_url: &str,
        open_requests: Arc<OpenVerifyForeignTxRequestsV2>,
    ) -> Self {
        let participants = client.all_participant_ids();
        let me = client.my_participant_id();
        let config = Arc::new(config(rpc_url));
        let db_dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(db_dir.path(), [1; 16]).unwrap();
        let keys = keys(&participants);
        let ecdsa_signature_provider = Arc::new(
            EcdsaSignatureProvider::new(
                config.clone(),
                Arc::new(MpcConfig {
                    my_participant_id: me,
                    participants: (*keys).clone(),
                }),
                client.clone(),
                Clock::real(),
                db.clone(),
                Arc::new(SignRequestStorage::new(db.clone()).unwrap()),
                HashMap::new(),
            )
            .unwrap(),
        );
        let supporters: SupportersByForeignChain = BTreeMap::from([(
            dtos::ForeignChain::Ethereum,
            participants.iter().copied().collect(),
        )]);
        let provider = VerifyForeignTxProvider::new(
            config,
            tokio::sync::watch::channel(supporters).1,
            tokio::sync::watch::channel(whitelist(rpc_url)).1,
            Some(1),
            Arc::new(VerifyForeignTransactionRequestStorage::new(db).unwrap()),
            ecdsa_signature_provider,
            VerifyForeignTxV2Context {
                open_requests,
                signing_key: signing_key(me),
                participants: keys,
                network: client,
            },
        )
        .unwrap();
        Self {
            provider,
            _db_dir: db_dir,
        }
    }
}

#[tokio::test]
async fn reach_node_outcome__should_retry_a_transient_error_within_the_inspection_cap() {
    // Given
    let rpc_mock = start_ethereum_rpc_mock_final_on_second_check();
    let participants = vec![ParticipantId::from_raw(0)];
    let client = crate::network::testing::new_test_client(participants.clone(), participants[0]);
    let indexed = IndexedRequests::with(request());
    let node = TestProvider::new(client, &rpc_mock.base_url(), indexed.open.clone());

    // When
    let outcome = node
        .provider
        .reach_node_outcome(&request().request, &request().expected_values_hash)
        .await;

    // Then
    assert_eq!(outcome.unwrap(), VERIFIED);
}

/// The packets the follower sends to the leader for the Start of a V2 attempt at `request()`.
async fn run_v2_follower(
    open_requests: Arc<OpenVerifyForeignTxRequestsV2>,
    rpc_url: String,
) -> Vec<MpcMessageKind> {
    let participants = vec![ParticipantId::from_raw(0), ParticipantId::from_raw(1)];
    let leader = participants[0];
    let results = run_test_clients(participants.clone(), move |client, mut receiver| {
        let participants = participants.clone();
        let open_requests = open_requests.clone();
        let rpc_url = rpc_url.clone();
        async move {
            let me = client.my_participant_id();
            if me == leader {
                let mut channel = client.new_channel_for_task(
                    VerifyForeignTxTaskId::VerifyForeignTxV2 {
                        id: request().id,
                        paired_triple_id: UniqueId::new(leader, 1, 0),
                    },
                    participants,
                )?;
                let received = match channel.receive_node_outcomes().await {
                    Ok(PeerNodeOutcomes { outcomes, .. }) => MpcMessageKind::NodeOutcomes(outcomes),
                    Err(err) => MpcMessageKind::Abort(err.to_string()),
                };
                return Ok(vec![received]);
            }
            let channel = receiver.recv().await.context("no channel received")?;
            let MpcTaskId::VerifyForeignTxTaskId(VerifyForeignTxTaskId::VerifyForeignTxV2 {
                id,
                paired_triple_id,
            }) = channel.task_id()
            else {
                anyhow::bail!("unexpected task {:?}", channel.task_id());
            };
            let node = TestProvider::new(client, &rpc_url, open_requests);
            let _ = node
                .provider
                .make_verify_foreign_tx_v2_follower(channel, id, paired_triple_id)
                .await;
            Ok(vec![])
        }
    })
    .await
    .unwrap();
    results.into_iter().flatten().collect()
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn make_verify_foreign_tx_v2_follower__should_send_its_signed_outcome_to_the_leader() {
    start_root_task_with_periodic_dump(async {
        // Given
        let rpc_mock = start_ethereum_rpc_mock_final_on_second_check();
        let follower = ParticipantId::from_raw(1);

        // When
        let indexed = IndexedRequests::with(request());
        let received = run_v2_follower(indexed.open.clone(), rpc_mock.base_url()).await;

        // Then
        let [MpcMessageKind::NodeOutcomes(outcomes)] = &received[..] else {
            panic!("expected one node outcomes message, got {received:?}");
        };
        let [outcome] = &outcomes[..] else {
            panic!("expected exactly one node outcome, got {outcomes:?}");
        };
        let participants = [ParticipantId::from_raw(0), follower];
        let verified = outcome.clone().verify(&keys(&participants)).unwrap();
        let statement = verified.statement();
        assert_eq!(statement.signer, follower);
        assert_eq!(statement.leader, ParticipantId::from_raw(0));
        assert_eq!(statement.yield_id, request().yield_id);
        assert_eq!(statement.outcome, VERIFIED);
    })
    .await;
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn make_verify_foreign_tx_v2_follower__should_refuse_a_request_it_has_not_indexed() {
    start_root_task_with_periodic_dump(async {
        // Given
        let not_indexed = IndexedRequests::none().open.clone();

        // When
        let received = run_v2_follower(not_indexed, "http://127.0.0.1:1".to_string()).await;

        // Then
        let [MpcMessageKind::Abort(error)] = &received[..] else {
            panic!("expected the network abort, got {received:?}");
        };
        assert!(error.contains("Aborted by participant"), "{error}");
    })
    .await;
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn make_verify_foreign_tx_v2_follower__should_refuse_a_request_that_completes_during_the_inspection()
 {
    start_root_task_with_periodic_dump(async {
        // Given
        let indexed = IndexedRequests::with(request());
        let rpc_mock = start_ethereum_rpc_mock({
            let indexed = indexed.clone();
            move || indexed.complete(request().id)
        });

        // When
        let received = run_v2_follower(indexed.open.clone(), rpc_mock.base_url()).await;

        // Then
        let [MpcMessageKind::Abort(error)] = &received[..] else {
            panic!("expected the network abort before any outcome, got {received:?}");
        };
        assert!(
            error.contains("the V2 request closed during the inspection"),
            "{error}"
        );
    })
    .await;
}

#[tokio::test]
async fn v2_attempt_candidates__should_leave_out_participants_without_the_v2_messages() {
    // Given
    let participants: Vec<_> = (0..3).map(ParticipantId::from_raw).collect();
    let versions = HashMap::from([
        (participants[1], NetworkProtocolVersion::Nov2026),
        (participants[2], NetworkProtocolVersion::Oct2026),
    ]);
    let (client, _transport) =
        new_test_client_with_versions(participants.clone(), participants[0], versions);
    let indexed = IndexedRequests::with(request());
    let node = TestProvider::new(client, "http://127.0.0.1:1", indexed.open.clone());

    // When
    let candidates = node
        .provider
        .v2_attempt_candidates(dtos::ForeignChain::Ethereum);

    // Then
    assert_eq!(candidates.unwrap(), participants[..2]);
}
