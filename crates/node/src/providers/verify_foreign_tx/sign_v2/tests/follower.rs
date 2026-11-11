use super::*;
use crate::config::MpcConfig;
use crate::db::SecretDB;
use crate::foreign_chain_policy::SupportersByForeignChain;
use crate::indexer::foreign_chain::ForeignChainWhitelist;
use crate::network::testing::{new_test_client_with_versions, run_test_clients};
use crate::network::wire_format::{MpcMessageKind, MpcTaskId};
use crate::protocol_version::NetworkProtocolVersion;
use crate::providers::EcdsaSignatureProvider;
use crate::requests::queue::{LEADER_FAILOVER_INTERVAL, leader_selection_order};
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

/// A provider for `client` with no keyshares.
struct TestProvider {
    provider: VerifyForeignTxProvider,
    _db_dir: tempfile::TempDir,
}

impl TestProvider {
    /// A provider whose Ethereum supporters are every participant.
    fn new(
        client: Arc<MeshNetworkClient>,
        rpc_url: &str,
        open_requests: Arc<OpenVerifyForeignTxRequestsV2>,
    ) -> Self {
        let ethereum_supporters = client.all_participant_ids();
        Self::with_ethereum_supporters(client, rpc_url, open_requests, &ethereum_supporters)
    }

    fn with_ethereum_supporters(
        client: Arc<MeshNetworkClient>,
        rpc_url: &str,
        open_requests: Arc<OpenVerifyForeignTxRequestsV2>,
        ethereum_supporters: &[ParticipantId],
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
            ethereum_supporters.iter().copied().collect(),
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
    let node = TestProvider::new(client, &rpc_mock.base_url(), open_requests_with(request()));

    // When
    let outcome = node.provider.reach_node_outcome(&request().request).await;

    // Then
    assert_eq!(outcome.unwrap(), VERIFIED);
}

fn attempt_participants() -> Vec<ParticipantId> {
    vec![ParticipantId::from_raw(0), ParticipantId::from_raw(1)]
}

/// The participant of `rank` in the leader selection order of `request()`.
fn leader_of_rank(rank: usize) -> ParticipantId {
    leader_selection_order(&attempt_participants(), request().id)[rank]
}

/// The packets the follower sends to the leader for the Start of a V2 attempt at `request()`,
/// led by its first eligible leader.
async fn run_v2_follower(
    open_requests: Arc<OpenVerifyForeignTxRequestsV2>,
    rpc_url: String,
) -> Vec<MpcMessageKind> {
    V2FollowerRun::new(open_requests, rpc_url).run().await
}

/// A V2 attempt at `request()` between the [`attempt_participants`], seen from the follower.
struct V2FollowerRun {
    leader_rank: usize,
    open_requests: Arc<OpenVerifyForeignTxRequestsV2>,
    rpc_url: String,
    ethereum_supporters: Vec<ParticipantId>,
}

impl V2FollowerRun {
    fn new(open_requests: Arc<OpenVerifyForeignTxRequestsV2>, rpc_url: String) -> Self {
        Self {
            leader_rank: 0,
            open_requests,
            rpc_url,
            ethereum_supporters: attempt_participants(),
        }
    }

    fn led_by_rank(self, leader_rank: usize) -> Self {
        Self {
            leader_rank,
            ..self
        }
    }

    /// The Ethereum supporters in the follower's view.
    fn with_ethereum_supporters(self, ethereum_supporters: Vec<ParticipantId>) -> Self {
        Self {
            ethereum_supporters,
            ..self
        }
    }

    /// The packets the follower sends to the leader for the Start of the attempt.
    async fn run(self) -> Vec<MpcMessageKind> {
        let Self {
            leader_rank,
            open_requests,
            rpc_url,
            ethereum_supporters,
        } = self;
        let participants = attempt_participants();
        let leader = leader_of_rank(leader_rank);
        let results = run_test_clients(participants.clone(), move |client, mut receiver| {
            let participants = participants.clone();
            let open_requests = open_requests.clone();
            let rpc_url = rpc_url.clone();
            let ethereum_supporters = ethereum_supporters.clone();
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
                        Ok(PeerNodeOutcomes { outcomes, .. }) => {
                            MpcMessageKind::NodeOutcomes(outcomes)
                        }
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
                let node = TestProvider::with_ethereum_supporters(
                    client,
                    &rpc_url,
                    open_requests,
                    &ethereum_supporters,
                );
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
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn make_verify_foreign_tx_v2_follower__should_send_its_signed_outcome_to_the_leader() {
    start_root_task_with_periodic_dump(async {
        // Given
        let rpc_mock = start_ethereum_rpc_mock_final_on_second_check();
        let leader = leader_of_rank(0);
        let follower = leader_of_rank(1);

        // When
        let received = run_v2_follower(open_requests_with(request()), rpc_mock.base_url()).await;

        // Then
        let [MpcMessageKind::NodeOutcomes(outcomes)] = &received[..] else {
            panic!("expected one node outcomes message, got {received:?}");
        };
        let [outcome] = &outcomes[..] else {
            panic!("expected exactly one node outcome, got {outcomes:?}");
        };
        let verified = outcome
            .clone()
            .verify(&keys(&attempt_participants()))
            .unwrap();
        let statement = verified.statement();
        assert_eq!(statement.signer, follower);
        assert_eq!(statement.leader, leader);
        assert_eq!(statement.yield_id, request().yield_id);
        assert_eq!(statement.outcome, VERIFIED);
    })
    .await;
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn make_verify_foreign_tx_v2_follower__should_refuse_a_request_it_has_not_indexed() {
    start_root_task_with_periodic_dump(async {
        // Given
        let (not_indexed, _clock) = no_open_requests();

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
        let open_requests = open_requests_with(request());
        let rpc_mock = start_ethereum_rpc_mock({
            let open_requests = open_requests.clone();
            move || complete(&open_requests, request().id)
        });

        // When
        let received = run_v2_follower(open_requests, rpc_mock.base_url()).await;

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

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn make_verify_foreign_tx_v2_follower__should_refuse_a_backup_leader_before_its_turn() {
    start_root_task_with_periodic_dump(async {
        // Given
        let first_backup = 1;

        // When
        let received = V2FollowerRun::new(
            open_requests_with(request()),
            "http://127.0.0.1:1".to_string(),
        )
        .led_by_rank(first_backup)
        .run()
        .await;

        // Then
        let [MpcMessageKind::Abort(error)] = &received[..] else {
            panic!("expected the network abort, got {received:?}");
        };
        assert!(error.contains("is not an acting leader"), "{error}");
    })
    .await;
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn make_verify_foreign_tx_v2_follower__should_refuse_a_fourth_attempt_of_one_leader() {
    start_root_task_with_periodic_dump(async {
        // Given
        let open_requests = open_requests_with(request());
        let leader = leader_of_rank(0);
        for _ in 0..3 {
            open_requests.join_attempt(request().id, leader).unwrap();
        }

        // When
        let received = run_v2_follower(open_requests, "http://127.0.0.1:1".to_string()).await;

        // Then
        let [MpcMessageKind::Abort(error)] = &received[..] else {
            panic!("expected the network abort, got {received:?}");
        };
        assert!(error.contains("already joined 3 attempts"), "{error}");
    })
    .await;
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn make_verify_foreign_tx_v2_follower__should_join_a_backup_leader_from_the_margin_before_its_turn()
 {
    start_root_task_with_periodic_dump(async {
        // Given
        let rpc_mock = start_ethereum_rpc_mock_final_on_second_check();
        let first_backup = 1;
        let margin = near_time::Duration::try_from(FOLLOWER_INDEX_WAIT).unwrap();
        let open_requests = open_requests_indexed_ago(request(), LEADER_FAILOVER_INTERVAL - margin);

        // When
        let received = V2FollowerRun::new(open_requests, rpc_mock.base_url())
            .led_by_rank(first_backup)
            .run()
            .await;

        // Then
        let [MpcMessageKind::NodeOutcomes(outcomes)] = &received[..] else {
            panic!("expected one node outcomes message, got {received:?}");
        };
        let [outcome] = &outcomes[..] else {
            panic!("expected exactly one node outcome, got {outcomes:?}");
        };
        let verified = outcome
            .clone()
            .verify(&keys(&attempt_participants()))
            .unwrap();
        assert_eq!(verified.statement().leader, leader_of_rank(first_backup));
        assert_eq!(verified.statement().outcome, VERIFIED);
    })
    .await;
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn make_verify_foreign_tx_v2_follower__should_refuse_a_leader_that_does_not_support_the_chain()
 {
    start_root_task_with_periodic_dump(async {
        // Given
        let follower = leader_of_rank(1);

        // When
        let received = V2FollowerRun::new(
            open_requests_with(request()),
            "http://127.0.0.1:1".to_string(),
        )
        .with_ethereum_supporters(vec![follower])
        .run()
        .await;

        // Then
        let [MpcMessageKind::Abort(error)] = &received[..] else {
            panic!("expected the network abort, got {received:?}");
        };
        assert!(error.contains("is not an acting leader"), "{error}");
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
    let node = TestProvider::new(client, "http://127.0.0.1:1", open_requests_with(request()));

    // When
    let candidates = node
        .provider
        .v2_attempt_candidates(dtos::ForeignChain::Ethereum);

    // Then
    assert_eq!(candidates.unwrap(), participants[..2]);
}

#[tokio::test]
async fn v2_attempt_candidates__should_leave_out_participants_more_than_five_blocks_behind() {
    // Given
    let participants: Vec<_> = (0..3).map(ParticipantId::from_raw).collect();
    let (client, _transport) = new_test_client_with_versions(
        participants.clone(),
        participants[0],
        crate::network::testing::current_protocol_versions(&participants),
    );
    client.update_indexer_height(100);
    client.set_peer_indexer_height(participants[1], 95);
    client.set_peer_indexer_height(participants[2], 94);
    let node = TestProvider::new(client, "http://127.0.0.1:1", open_requests_with(request()));

    // When
    let candidates = node
        .provider
        .v2_attempt_candidates(dtos::ForeignChain::Ethereum);

    // Then
    assert_eq!(candidates.unwrap(), participants[..2]);
}

#[tokio::test(start_paused = true)]
async fn take_v2_triples__should_stop_waiting_when_the_request_closes() {
    // Given
    let participants = vec![ParticipantId::from_raw(0)];
    let client = crate::network::testing::new_test_client(participants.clone(), participants[0]);
    let open_requests = open_requests_with(request());
    let node = TestProvider::new(client.clone(), "http://127.0.0.1:1", open_requests.clone());
    let db_dir = tempfile::tempdir().unwrap();
    let triples = TripleStorage::new(
        near_time::FakeClock::default().clock(),
        SecretDB::new(db_dir.path(), [1; 16]).unwrap(),
        client,
        mpc_primitives::ReconstructionThreshold::new(1),
    )
    .unwrap();
    let request = request();
    let avoid = BTreeSet::new();
    let wait_before_close = Duration::from_secs(5);
    let started = tokio::time::Instant::now();

    // When
    let (taken, ()) = timeout(Duration::from_mins(1), async {
        tokio::join!(
            node.provider.take_v2_triples(&request, &triples, &avoid),
            async {
                tokio::time::sleep(wait_before_close).await;
                complete(&open_requests, request.id);
            }
        )
    })
    .await
    .expect("the wait for a triple pair ends once the request closes");

    // Then
    let error = taken.err().unwrap();
    assert!(
        error.to_string().contains("the V2 request closed"),
        "{error:#}"
    );
    assert!(started.elapsed() >= wait_before_close);
}
