use super::*;
use crate::assets::test_utils::make_triple;
use crate::db::SecretDB;
use crate::keyshare::KeyshareData;
use crate::keyshare::test_utils::generate_dummy_keyshare;
use crate::network::testing::{
    current_protocol_versions, new_task_channel_for_test, new_test_client_with_versions,
};
use crate::network::wire_format::{MpcMessageKind, Packet};
use crate::primitives::{ChannelId, MpcMessage, MpcPeerMessage};
use crate::providers::verify_foreign_tx::node_outcome::{NoVerdictReason, NodeOutcome};
use crate::providers::verify_foreign_tx::node_outcome_statement::NodeOutcomeStatement;
use crate::providers::verify_foreign_tx::node_outcome_statement::testing::{
    outcome_public_keys, signed_by_its_signer,
};
use crate::providers::verify_foreign_tx::open_requests::test_chain::TestChain;
use crate::providers::verify_foreign_tx::testing::{TestProvider, open_with};
use crate::tracking::start_root_task;
use mpc_primitives::domain::DomainId;
use near_contract_transport::BlockHeight;
use near_indexer_primitives::CryptoHash;
use near_mpc_contract_interface::types::{
    self as dtos, ForeignTxVerificationNegativeVerdict, YieldId,
};
use near_time::{Clock, FakeClock};
use rand::SeedableRng;
use std::assert_matches;
use std::sync::Mutex;
use std::time::Duration;

mod inconclusive;

const THRESHOLD: usize = 3;
const NOT_FOUND: NodeVerdict =
    NodeVerdict::Negative(ForeignTxVerificationNegativeVerdict::TransactionNotFound);

fn participant(id: u32) -> ParticipantId {
    ParticipantId::from_raw(id)
}

fn participants(ids: &[u32]) -> BTreeSet<ParticipantId> {
    ids.iter().copied().map(participant).collect()
}

fn signed(signer: u32, outcome: NodeOutcome) -> SignedNodeOutcome {
    signed_by_its_signer(NodeOutcomeStatement {
        yield_id: YIELD,
        signer: participant(signer),
        outcome,
    })
}

fn verified(outcomes: &[SignedNodeOutcome]) -> Vec<VerifiedNodeOutcome> {
    let keys = outcome_public_keys(&(0..8).map(participant).collect::<Vec<_>>());
    outcomes
        .iter()
        .map(|outcome| outcome.clone().verify(&keys).unwrap())
        .collect()
}

#[test]
fn evidence_to_sign__should_return_the_backers_statements_once_t_signed_the_verdict() {
    // Given
    let backer_statements = [
        signed(0, NodeOutcome::Verdict(NOT_FOUND)),
        signed(2, NodeOutcome::Verdict(NOT_FOUND)),
        signed(3, NodeOutcome::Verdict(NOT_FOUND)),
    ];
    let mut outcomes = backer_statements.to_vec();
    outcomes.insert(1, signed(1, NodeOutcome::Verdict(NodeVerdict::Verified)));

    // When
    let to_sign = evidence_to_sign(
        &verified(&outcomes),
        participant(0),
        &participants(&[0, 1, 2, 3]),
        THRESHOLD,
    );

    // Then
    assert_eq!(
        to_sign,
        Ok(Some(RoundEvidence {
            proven: ProvenOutcome::Verdict(NOT_FOUND),
            eligible: participants(&[0, 2, 3]),
            statements: backer_statements.to_vec(),
        }))
    );
}

#[test]
fn evidence_to_sign__should_wait_while_a_verdict_can_still_reach_t() {
    // Given
    let outcomes = [
        signed(0, NodeOutcome::Verdict(NOT_FOUND)),
        signed(1, NodeOutcome::Verdict(NOT_FOUND)),
    ];

    // When
    let to_sign = evidence_to_sign(
        &verified(&outcomes),
        participant(0),
        &participants(&[0, 1, 2, 3]),
        THRESHOLD,
    );

    // Then
    assert_eq!(to_sign, Ok(None));
}

#[test]
fn evidence_to_sign__should_stop_a_leader_that_did_not_sign_the_verdict() {
    // Given
    let outcomes = [
        signed(0, NodeOutcome::NoVerdict(NoVerdictReason::Transient)),
        signed(1, NodeOutcome::Verdict(NOT_FOUND)),
        signed(2, NodeOutcome::Verdict(NOT_FOUND)),
        signed(3, NodeOutcome::Verdict(NOT_FOUND)),
    ];

    // When
    let to_sign = evidence_to_sign(
        &verified(&outcomes),
        participant(0),
        &participants(&[0, 1, 2, 3]),
        THRESHOLD,
    );

    // Then
    assert_eq!(to_sign, Err(StopLeading::NotABacker(NOT_FOUND)));
}

#[test]
fn round_candidates__should_keep_only_backers_that_speak_the_v2_messages() {
    // Given
    let backers = participants(&[0, 2, 3, 5]);
    let v2_capable: HashSet<ParticipantId> = [0, 1, 2, 5].into_iter().map(participant).collect();

    // When
    let candidates = round_candidates(&backers, &v2_capable);

    // Then
    assert_eq!(
        candidates,
        vec![participant(0), participant(2), participant(5)]
    );
}

#[test]
fn evidence_to_sign__should_pick_the_verdict_the_leader_backs_when_two_reach_t() {
    // Given
    let outcomes = [
        signed(0, NodeOutcome::Verdict(NOT_FOUND)),
        signed(1, NodeOutcome::Verdict(NodeVerdict::Verified)),
        signed(2, NodeOutcome::Verdict(NOT_FOUND)),
        signed(3, NodeOutcome::Verdict(NodeVerdict::Verified)),
        signed(4, NodeOutcome::Verdict(NOT_FOUND)),
        signed(5, NodeOutcome::Verdict(NodeVerdict::Verified)),
    ];

    // When
    let to_sign = evidence_to_sign(
        &verified(&outcomes),
        participant(1),
        &participants(&[0, 1, 2, 3, 4, 5]),
        THRESHOLD,
    );

    // Then
    let evidence = to_sign.unwrap().unwrap();
    assert_eq!(
        evidence.proven,
        ProvenOutcome::Verdict(NodeVerdict::Verified)
    );
    assert_eq!(evidence.eligible, participants(&[1, 3, 5]));
}

/// One owned asset shared with `participants`. A take completes only once every one of them is
/// eligible.
struct OneAsset {
    participants: BTreeSet<ParticipantId>,
    eligible_sets: Mutex<Vec<Vec<ParticipantId>>>,
}

impl OneAsset {
    fn among(ids: &[u32]) -> Self {
        Self {
            participants: participants(ids),
            eligible_sets: Mutex::new(Vec::new()),
        }
    }
}

impl TakeOwnedMatching for OneAsset {
    type Asset = ();

    fn take_owned_matching(
        &self,
        eligible: Vec<ParticipantId>,
    ) -> impl Future<Output = (UniqueId, ())> + Send {
        let matches = self
            .participants
            .iter()
            .all(|participant| eligible.contains(participant));
        self.eligible_sets.lock().unwrap().push(eligible);
        async move {
            if !matches {
                std::future::pending::<()>().await;
            }
            (asset_id(), ())
        }
    }
}

fn asset_id() -> UniqueId {
    UniqueId::new(participant(0), 1, 1)
}
const YIELD: YieldId = YieldId([4; 32]);

/// A node's outcomes and open requests, with `request()` open.
struct LeaderView {
    node_outcomes: NodeOutcomes,
    open_requests: OpenVerifyForeignTxRequestsV2,
    chain: Mutex<TestChain>,
}

impl LeaderView {
    fn new() -> Self {
        let node_outcomes = NodeOutcomes::new();
        node_outcomes.set_outcome_keys(outcome_public_keys(
            &(0..8).map(participant).collect::<Vec<_>>(),
        ));
        node_outcomes.index([YIELD]);
        let open_requests = OpenVerifyForeignTxRequestsV2::default();
        let mut chain = TestChain::starting_at(BlockHeight::new(999));
        open_requests.notify_new_block(&chain.extend(vec![request()], vec![]));
        Self {
            node_outcomes,
            open_requests,
            chain: Mutex::new(chain),
        }
    }

    fn receive(&self, signer: u32) {
        self.receive_outcome(signer, NodeOutcome::Verdict(NOT_FOUND));
    }

    fn receive_outcome(&self, signer: u32, outcome: NodeOutcome) {
        self.node_outcomes
            .receive(participant(signer), signed(signer, outcome))
            .unwrap();
    }

    fn close(&self) {
        let update = self
            .chain
            .lock()
            .unwrap()
            .extend(vec![], vec![request().id]);
        self.open_requests.notify_new_block(&update);
    }

    async fn evidence_and_asset(
        &self,
        assets: &OneAsset,
    ) -> Result<EvidenceAndAsset<()>, StopLeading> {
        RoundWait {
            node_outcomes: &self.node_outcomes,
            open_requests: &self.open_requests,
            assets,
            request: &request(),
            me: participant(0),
            threshold: THRESHOLD,
        }
        .evidence_and_asset(
            || participants(&[0, 1, 2, 3]),
            || (0..4).map(participant).collect(),
        )
        .await
    }
}

fn request() -> VerifyForeignTxRequestV2 {
    VerifyForeignTxRequestV2 {
        id: CryptoHash([1; 32]),
        receipt_id: CryptoHash([2; 32]),
        yield_id: YIELD,
        request_block_height: BlockHeight::new(1000),
        request: dtos::ForeignChainRpcRequest::Bitcoin(dtos::BitcoinRpcRequest {
            tx_id: dtos::BitcoinTxId([0; 32]),
            confirmations: dtos::BlockConfirmations(1),
            extractors: [dtos::BitcoinExtractor::BlockHash].into(),
        }),
        domain_id: DomainId(0),
        expected_values_hash: dtos::Hash256([4; 32]),
        entropy: [0; 32],
        timestamp_nanosec: 0,
    }
}

#[tokio::test]
async fn round_wait__should_take_an_asset_among_a_later_backer_set_when_the_first_t_own_none() {
    // Given
    let view = LeaderView::new();
    for signer in [0, 1, 2] {
        view.receive(signer);
    }
    let asset = OneAsset::among(&[0, 2, 3]);
    let late_backer = async { view.receive(3) };

    // When
    let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(view.evidence_and_asset(&asset), late_backer)
    })
    .await
    .unwrap();

    // Then
    let EvidenceAndAsset {
        evidence,
        asset: taken,
    } = result.unwrap();
    assert_eq!(taken.id, asset_id());
    assert_eq!(evidence.eligible, participants(&[0, 1, 2, 3]));
    let eligible_sets = asset.eligible_sets.lock().unwrap();
    assert_eq!(
        eligible_sets.first(),
        Some(&vec![participant(0), participant(1), participant(2)])
    );
}

#[tokio::test]
async fn round_wait__should_stop_without_an_asset_once_the_request_closes() {
    // Given
    let view = LeaderView::new();
    for signer in [0, 1, 2] {
        view.receive(signer);
    }
    let asset = OneAsset::among(&[0, 2, 3]);
    let closing = async { view.close() };

    // When
    let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(view.evidence_and_asset(&asset), closing)
    })
    .await
    .unwrap();

    // Then
    assert_matches!(result, Err(StopLeading::RequestClosed));
}

#[tokio::test]
async fn round_wait__should_take_no_asset_for_a_closed_request() {
    // Given
    let view = LeaderView::new();
    for signer in [0, 1, 2] {
        view.receive(signer);
    }
    view.close();
    let asset = OneAsset::among(&[0, 1, 2]);

    // When
    let result = view.evidence_and_asset(&asset).await;

    // Then
    assert_matches!(result, Err(StopLeading::RequestClosed));
    assert!(asset.eligible_sets.lock().unwrap().is_empty());
}

/// Owned assets, each shared with a set of participants. A take removes the first free asset
/// whose participants are all eligible, and waits for one while there is none.
#[derive(Default)]
struct FreeAssets {
    assets: Mutex<Vec<SharedAsset>>,
    added: tokio::sync::Notify,
}

struct SharedAsset {
    id: UniqueId,
    participants: BTreeSet<ParticipantId>,
}

impl FreeAssets {
    fn add(&self, counter: u32, ids: &[u32]) {
        self.assets.lock().unwrap().push(SharedAsset {
            id: UniqueId::new(participant(0), 1, counter),
            participants: participants(ids),
        });
        self.added.notify_waiters();
    }

    fn take_matching(&self, eligible: &[ParticipantId]) -> Option<SharedAsset> {
        let mut assets = self.assets.lock().unwrap();
        let position = assets.iter().position(|asset| {
            asset
                .participants
                .iter()
                .all(|participant| eligible.contains(participant))
        })?;
        Some(assets.remove(position))
    }
}

impl TakeOwnedMatching for FreeAssets {
    type Asset = BTreeSet<ParticipantId>;

    async fn take_owned_matching(
        &self,
        eligible: Vec<ParticipantId>,
    ) -> (UniqueId, BTreeSet<ParticipantId>) {
        loop {
            let added = self.added.notified();
            tokio::pin!(added);
            added.as_mut().enable();
            if let Some(asset) = self.take_matching(&eligible) {
                return (asset.id, asset.participants);
            }
            added.await;
        }
    }
}

impl LeaderView {
    async fn retry_asset(
        &self,
        assets: &FreeAssets,
        avoid: &[u32],
    ) -> Result<OwnedAsset<BTreeSet<ParticipantId>>, StopLeading> {
        RetryAssetWait {
            open_requests: &self.open_requests,
            assets,
            request_id: request().id,
        }
        .take(
            || participants(&[0, 1, 2, 3]).into_iter().collect(),
            &participants(avoid),
        )
        .await
    }
}

#[tokio::test]
async fn retry_asset_wait__should_take_a_free_asset_without_the_avoided_signers_first() {
    // Given
    let view = LeaderView::new();
    let assets = FreeAssets::default();
    assets.add(1, &[0, 1, 3]);
    assets.add(2, &[0, 1, 2]);

    // When
    let taken = view.retry_asset(&assets, &[3]).await.unwrap();

    // Then
    assert_eq!(taken.asset, participants(&[0, 1, 2]));
    assert_eq!(assets.assets.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn retry_asset_wait__should_take_an_asset_with_an_avoided_signer_when_no_other_is_free() {
    // Given
    let view = LeaderView::new();
    let assets = FreeAssets::default();
    assets.add(1, &[0, 1, 3]);

    // When
    let taken = view.retry_asset(&assets, &[3]).await.unwrap();

    // Then
    assert_eq!(taken.asset, participants(&[0, 1, 3]));
}

#[tokio::test(start_paused = true)]
async fn retry_asset_wait__should_wait_past_the_round_deadline_until_an_asset_is_free() {
    // Given
    let view = LeaderView::new();
    let assets = FreeAssets::default();
    let freed_late = async {
        tokio::time::sleep(ROUND_DEADLINE * 4).await;
        assets.add(1, &[0, 1, 2]);
    };

    // When
    let (taken, ()) = tokio::join!(view.retry_asset(&assets, &[]), freed_late);

    // Then
    assert_eq!(taken.unwrap().asset, participants(&[0, 1, 2]));
}

#[tokio::test]
async fn retry_asset_wait__should_take_no_asset_outside_the_candidates_and_stop_once_the_request_closes()
 {
    // Given
    let view = LeaderView::new();
    let assets = FreeAssets::default();
    assets.add(1, &[0, 1, 5]);
    let closing = async { view.close() };

    // When
    let (taken, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(view.retry_asset(&assets, &[]), closing)
    })
    .await
    .unwrap();

    // Then
    assert_matches!(taken.map(|taken| taken.id), Err(StopLeading::RequestClosed));
    assert_eq!(assets.assets.lock().unwrap().len(), 1);
}

/// A round that receives until it fails, so it ends only at the round deadline.
struct ReceiveUntilFailure;

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<()> for ReceiveUntilFailure {
    async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<()> {
        loop {
            channel.receive().await?;
        }
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}

fn led_rounds_with(label: &str) -> u64 {
    metrics::MPC_NUM_VERIFY_FOREIGN_TX_COMPUTATIONS_LED
        .with_label_values(&[label])
        .get()
}

#[tokio::test(start_paused = true)]
async fn run_led_round__should_fail_with_the_silent_signers_exactly_at_the_round_deadline() {
    let (test, _) = start_root_task("round deadline", async {
        // Given
        let [me, heard, silent] = [0, 1, 2].map(participant);
        let task_id = VerifyForeignTxTaskId::SignOutcome {
            yield_id: YIELD,
            outcome: RoundOutcome::Verdict(NOT_FOUND),
            paired_triple_id: asset_id(),
        };
        let (channel, raw_sender) =
            new_task_channel_for_test(task_id.into(), me, me, vec![me, heard, silent]);
        raw_sender
            .send(MpcPeerMessage {
                from: heard,
                message: MpcMessage {
                    channel_id: ChannelId(asset_id()),
                    kind: MpcMessageKind::Computation(vec![vec![1]]),
                },
            })
            .unwrap();
        let deadline_exceeded_before = led_rounds_with(metrics::DEADLINE_EXCEEDED_OUTCOME_LABEL);
        let started = tokio::time::Instant::now();

        // When
        let result = run_led_round(Ok(channel), ReceiveUntilFailure).await;

        // Then
        assert_eq!(started.elapsed(), ROUND_DEADLINE);
        assert_matches!(
            result,
            Err(RoundFailure::DeadlineExceeded { silent: signers }) if signers == BTreeSet::from([silent])
        );
        assert_eq!(
            led_rounds_with(metrics::DEADLINE_EXCEEDED_OUTCOME_LABEL),
            deadline_exceeded_before + 1
        );
    });
    test.await;
}

#[tokio::test]
async fn run_led_round__should_count_a_channel_that_failed_to_open_as_a_failed_round() {
    // Given
    let failed_before = led_rounds_with(metrics::FAILED_OUTCOME_LABEL);
    let total_before = led_rounds_with(metrics::TOTAL_RESULT_LABEL);

    // When
    let result = run_led_round(
        Err(anyhow::anyhow!("no connection to the signer")),
        ReceiveUntilFailure,
    )
    .await;

    // Then
    assert_matches!(result, Err(RoundFailure::Unattributed(_)));
    assert_eq!(
        led_rounds_with(metrics::FAILED_OUTCOME_LABEL),
        failed_before + 1
    );
    assert_eq!(
        led_rounds_with(metrics::TOTAL_RESULT_LABEL),
        total_before + 1
    );
}

fn keygen_output() -> KeygenOutput {
    let mut rng = rand::rngs::StdRng::from_seed([1; 32]);
    match generate_dummy_keyshare(0, 0, 0, &mut rng).data {
        KeyshareData::Secp256k1(keygen_output) => keygen_output,
        other => panic!("unexpected keyshare {other:?}"),
    }
}

#[rstest::rstest]
#[case::verdict(ProvenOutcome::Verdict(NOT_FOUND))]
#[case::inconclusive(ProvenOutcome::Inconclusive(InconclusiveCause::VerdictsDiffer))]
#[tokio::test(start_paused = true)]
async fn outcome_rounds__should_send_the_same_evidence_in_every_round(
    #[case] proven: ProvenOutcome,
) {
    let (test, _) = start_root_task("evidence reuse", async move {
        // Given
        let signers = vec![participant(0), participant(1), participant(2)];
        let (network, transport) = new_test_client_with_versions(
            signers.clone(),
            participant(0),
            current_protocol_versions(&signers),
        );
        let (open_requests, _chain) = open_with(request(), Clock::real());
        let provider = TestProvider::new(
            network.clone(),
            open_requests,
            request().request.chain(),
            signers.iter().copied().collect(),
        );
        let db_dir = tempfile::tempdir().unwrap();
        let triple_store = Arc::new(
            TripleStorage::new(
                FakeClock::default().clock(),
                SecretDB::new(db_dir.path(), [1; 16]).unwrap(),
                network.clone(),
                dtos::ReconstructionThreshold::new(3),
            )
            .unwrap(),
        );
        let statements: Vec<_> = [0, 1, 2]
            .into_iter()
            .map(|signer| signed(signer, NodeOutcome::Verdict(NOT_FOUND)))
            .collect();
        let rounds = OutcomeRounds {
            provider: &provider.provider,
            request: request(),
            evidence: RoundEvidence {
                proven,
                eligible: participants(&[0, 1, 2]),
                statements: statements.clone(),
            },
            payload_hash: dtos::Hash256([5; 32]),
            triple_store,
            keygen_out: keygen_output(),
            reconstruction_threshold: ReconstructionThreshold::from(THRESHOLD),
        };

        // When
        for counter in [1, 2] {
            let triples = OwnedAsset {
                id: UniqueId::new(participant(0), 1, counter),
                asset: make_triple(&signers),
            };
            let failure = rounds.run_round(triples).await.err();
            assert_matches!(failure, Some(RoundFailure::DeadlineExceeded { .. }));
        }

        // Then
        let evidence_sent: Vec<_> = transport
            .take_packets_sent()
            .into_iter()
            .filter_map(|(recipient, packet)| match packet {
                Packet::MpcMessage(MpcMessage {
                    kind: MpcMessageKind::Evidence(evidence),
                    ..
                }) => Some((recipient, evidence)),
                _ => None,
            })
            .collect();
        assert_eq!(
            evidence_sent,
            vec![
                (participant(1), statements.clone()),
                (participant(2), statements.clone()),
                (participant(1), statements.clone()),
                (participant(2), statements),
            ]
        );
    });
    test.await;
}
