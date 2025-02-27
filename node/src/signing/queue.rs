use super::progress::SignatureComputationProgress;
use super::recent_blocks_tracker::{BlockViewLite, CheckBlockResult, RecentBlocksTracker};
use crate::primitives::ParticipantId;
use crate::sign_request::{SignatureId, SignatureRequest};
use k256::sha2::Sha256;
use near_indexer_primitives::types::NumBlocks;
use near_indexer_primitives::CryptoHash;
use near_time::Duration;
use sha3::Digest;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, Weak};

pub const CHECK_EACH_SIGNATURE_REQUEST_INTERVAL: Duration = Duration::seconds(1);
const STALE_PARTICIPANT_THRESHOLD: NumBlocks = 10;
const REQUEST_EXPIRATION_BLOCKS: NumBlocks = 200;
const MAX_LATENCY_BEFORE_EXPECTING_TRANSACTION_TO_FINALIZE: Duration = Duration::seconds(10);
const MAX_ATTEMPTS_PER_SIGNATURE_AS_LEADER: u64 = 10;

pub struct PendingSignatureRequests {
    clock: near_time::Clock,

    all_participants: Vec<ParticipantId>,
    my_participant_id: ParticipantId,
    requests: HashMap<SignatureId, QueuedSignatureRequest>,
    recent_blocks: RecentBlocksTracker<BufferedBlockData>,
    network_api: Arc<dyn NetworkAPIForSigning>,
}

/// Block data to be buffered until the block is final.
#[derive(Clone)]
struct BufferedBlockData {
    completed_requests: Vec<SignatureId>,
}

pub trait NetworkAPIForSigning: Send + Sync + 'static {
    fn alive_participants(&self) -> HashSet<ParticipantId>;
    fn indexer_heights(&self) -> HashMap<ParticipantId, u64>;
}

struct QueuedSignatureRequest {
    request: SignatureRequest,
    block_hash: CryptoHash,
    block_height: u64,
    leader_selection_order: Vec<ParticipantId>,
    next_check_due: near_time::Instant,
    computation_progress: Arc<Mutex<SignatureComputationProgress>>,
    active_attempt: Weak<SignatureGenerationAttempt>,
}

pub struct SignatureGenerationAttempt {
    pub request: SignatureRequest,
    pub block_hash: CryptoHash,
    pub computation_progress: Arc<Mutex<SignatureComputationProgress>>,
}

impl QueuedSignatureRequest {
    pub fn new(
        clock: &near_time::Clock,
        request: SignatureRequest,
        block_hash: CryptoHash,
        block_height: u64,
        all_participants: &[ParticipantId],
    ) -> Self {
        let leader_selection_order = Self::leader_selection_order(all_participants, request.id);

        Self {
            request,
            block_hash,
            block_height,
            leader_selection_order,
            computation_progress: Arc::new(Mutex::new(SignatureComputationProgress::default())),
            next_check_due: clock.now(),
            active_attempt: Weak::new(),
        }
    }

    fn leader_selection_order(
        participants: &[ParticipantId],
        signature_request_id: CryptoHash,
    ) -> Vec<ParticipantId> {
        let mut leader_selection_hashes = participants
            .iter()
            .map(|p| (Self::leader_selection_hash(p, signature_request_id), *p))
            .collect::<Vec<_>>();
        leader_selection_hashes.sort();
        leader_selection_hashes
            .into_iter()
            .map(|(_, p)| p)
            .collect()
    }

    fn leader_selection_hash(
        participant_id: &ParticipantId,
        signature_request_id: CryptoHash,
    ) -> u64 {
        let mut h = Sha256::new();
        h.update(participant_id.raw().to_le_bytes());
        h.update(signature_request_id.0);
        let hash: [u8; 32] = h.finalize().into();
        u64::from_le_bytes(hash[0..8].try_into().unwrap())
    }

    fn current_leader(&self, eligible_leaders: &HashSet<ParticipantId>) -> Option<ParticipantId> {
        for candidate_leader in &self.leader_selection_order {
            if eligible_leaders.contains(candidate_leader) {
                return Some(*candidate_leader);
            }
        }
        None
    }
}

impl PendingSignatureRequests {
    pub fn new(
        clock: near_time::Clock,
        all_participants: Vec<ParticipantId>,
        my_participant_id: ParticipantId,
        network_api: Arc<dyn NetworkAPIForSigning>,
    ) -> Self {
        Self {
            clock,
            all_participants,
            my_participant_id,
            requests: HashMap::new(),
            recent_blocks: RecentBlocksTracker::new(REQUEST_EXPIRATION_BLOCKS),
            network_api,
        }
    }

    pub fn notify_new_block(
        &mut self,
        request: Vec<SignatureRequest>,
        completed_requests: Vec<SignatureId>,
        block: &BlockViewLite,
    ) {
        let add_result = match self
            .recent_blocks
            .add_block(block, BufferedBlockData { completed_requests })
        {
            Ok(add_result) => add_result,
            Err(err) => {
                // block already exists.
                tracing::warn!(target: "signing", "Ignoring block {:?} at height {}: {:?}", block.hash, block.height, err);
                return;
            }
        };
        for (_, buffered_block_data) in add_result.new_final_blocks {
            for request_id in &buffered_block_data.completed_requests {
                tracing::debug!(target: "signing", "Removing completed request {:?}", request_id);
                self.requests.remove(request_id);
            }
        }
        for request in request {
            self.requests
                .entry(request.id)
                .or_insert(QueuedSignatureRequest::new(
                    &self.clock,
                    request.clone(),
                    block.hash,
                    block.height,
                    &self.all_participants,
                ));
        }
    }

    pub fn get_signatures_to_attempt(&mut self) -> Vec<Arc<SignatureGenerationAttempt>> {
        let now = self.clock.now();

        // Collect the indexer heights and alive participants. Calculate maximum available height
        // from the alive nodes. Then, filter out the participants that are not alive or are too
        // stale.
        let indexer_heights = self.network_api.indexer_heights();
        let alive_participants = self.network_api.alive_participants();
        let maximum_height = alive_participants
            .iter()
            .map(|p| indexer_heights.get(p).copied().unwrap_or(0))
            .max()
            .unwrap_or(0);
        self.recent_blocks
            .notify_maximum_height_availble(maximum_height);
        let eligible_leaders = self
            .all_participants
            .iter()
            .filter(|p| {
                alive_participants.contains(p)
                    && indexer_heights.get(p).copied().unwrap_or(0) + STALE_PARTICIPANT_THRESHOLD
                        >= maximum_height
            })
            .copied()
            .collect::<HashSet<_>>();

        let mut result = Vec::new();

        let mut signatures_to_remove = Vec::new();
        for (id, request) in &mut self.requests {
            if request.next_check_due > now {
                tracing::debug!(target: "signing", "Skipping signature request {:?} from block {} because it's not time yet", request.request.id, request.block_height);
                continue;
            }
            request.next_check_due = now + CHECK_EACH_SIGNATURE_REQUEST_INTERVAL;
            if request.active_attempt.strong_count() > 0 {
                // There's a current attempt to generate the signature, so don't do anything.
                tracing::debug!(target: "signing", "Skipping signature request {:?} from block {} because there's already an active attempt", request.request.id, request.block_height);
                continue;
            }
            match self
                .recent_blocks
                .check_block(request.block_hash, request.block_height)
            {
                CheckBlockResult::RecentAndFinal
                | CheckBlockResult::OptimisticAndCanonical
                | CheckBlockResult::Unknown => {
                    if let Some(leader) = request.current_leader(&eligible_leaders) {
                        tracing::debug!(target: "signing", "Leader for signature request {:?} from block {} is {}", request.request.id, request.block_height, leader);
                        if leader == self.my_participant_id {
                            {
                                let mut progress = request.computation_progress.lock().unwrap();
                                if progress.attempts >= MAX_ATTEMPTS_PER_SIGNATURE_AS_LEADER {
                                    tracing::debug!(target: "signing", "Discarding signature request {:?} from block {} because it has been attempted too many ({}) times", request.request.id, request.block_height, MAX_ATTEMPTS_PER_SIGNATURE_AS_LEADER);
                                    signatures_to_remove.push(*id);
                                    continue;
                                }
                                if progress.last_response_submission.is_some_and(|t| {
                                    now < t + MAX_LATENCY_BEFORE_EXPECTING_TRANSACTION_TO_FINALIZE
                                }) {
                                    tracing::debug!(target: "signing", "Skipping signature request {:?} from block {} because the last response was submitted too recently", request.request.id, request.block_height);
                                    continue;
                                }
                                progress.attempts += 1;
                            }
                            let attempt = Arc::new(SignatureGenerationAttempt {
                                request: request.request.clone(),
                                block_hash: request.block_hash,
                                computation_progress: request.computation_progress.clone(),
                            });
                            request.active_attempt = Arc::downgrade(&attempt);
                            result.push(attempt);
                        }
                    }
                }
                CheckBlockResult::OptimisticButNotCanonical => {
                    // Don't act on it yet. If it becomes canonical later, we'll try to generate
                    // the signature.
                    tracing::debug!(target: "signing", "Ignoring non-canonical signature request {:?} from block {}", request.request.id, request.block_height);
                }
                CheckBlockResult::NotIncluded | CheckBlockResult::OlderThanRecentWindow => {
                    tracing::debug!(target: "signing", "Discarding signature request {:?} from block {}", request.request.id, request.block_height);
                    // This signature request is definitely not useful anymore, so discard it.
                    signatures_to_remove.push(*id);
                }
            }
        }
        for id in signatures_to_remove {
            self.requests.remove(&id);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::{NetworkAPIForSigning, PendingSignatureRequests, QueuedSignatureRequest};
    use crate::primitives::ParticipantId;
    use crate::sign_request::SignatureRequest;
    use crate::signing::queue::{
        CHECK_EACH_SIGNATURE_REQUEST_INTERVAL, MAX_LATENCY_BEFORE_EXPECTING_TRANSACTION_TO_FINALIZE,
    };
    use crate::signing::recent_blocks_tracker::tests::TestBlockMaker;
    use crate::tests::TestGenerators;
    use crate::tracing::init_logging;
    use k256::Scalar;
    use near_indexer_primitives::CryptoHash;
    use near_time::{Duration, FakeClock};
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};

    fn test_sign_request(
        participants: &[ParticipantId],
        desired_leader_order: &[usize],
    ) -> SignatureRequest {
        let desired_leader_order = desired_leader_order
            .iter()
            .map(|i| participants[*i])
            .collect::<Vec<_>>();
        loop {
            let request = SignatureRequest {
                id: CryptoHash(rand::random::<[u8; 32]>()),
                // All other fields are irrelevant for the test.
                entropy: [0; 32],
                msg_hash: Scalar::ZERO,
                timestamp_nanosec: 0,
                tweak: Scalar::ZERO,
            };
            let leader_selection_order =
                QueuedSignatureRequest::leader_selection_order(participants, request.id);
            if leader_selection_order.starts_with(&desired_leader_order) {
                return request;
            }
        }
    }

    fn set_equals<T: Clone + Eq + Ord>(a: &[T], b: &[T]) -> bool {
        let mut a = a.to_vec();
        let mut b = b.to_vec();
        a.sort();
        b.sort();
        a == b
    }

    struct TestNetworkAPI {
        alive: Mutex<HashSet<ParticipantId>>,
        heights: Mutex<HashSet<(ParticipantId, u64)>>,
    }

    impl NetworkAPIForSigning for TestNetworkAPI {
        fn alive_participants(&self) -> HashSet<ParticipantId> {
            self.alive.lock().unwrap().clone()
        }

        fn indexer_heights(&self) -> HashMap<ParticipantId, u64> {
            self.heights.lock().unwrap().iter().cloned().collect()
        }
    }

    impl TestNetworkAPI {
        fn new(participants: &[ParticipantId]) -> Self {
            Self {
                alive: Mutex::new(participants.iter().cloned().collect()),
                heights: Mutex::new(participants.iter().map(|p| (*p, 0)).collect()),
            }
        }

        fn bring_down(&self, participant: ParticipantId) {
            self.alive.lock().unwrap().remove(&participant);
        }

        fn bring_up(&self, participant: ParticipantId) {
            self.alive.lock().unwrap().insert(participant);
        }

        fn set_height(&self, participant: ParticipantId, height: u64) {
            self.heights.lock().unwrap().insert((participant, height));
        }
    }

    #[test]
    fn test_pending_signature_requests_leader_retry() {
        init_logging();
        let clock = FakeClock::default();
        let participants = TestGenerators::new_contiguous_participant_ids(4, 3).participant_ids();
        let my_participant_id = participants[1];
        let network_api = Arc::new(TestNetworkAPI::new(&participants));

        let mut pending_requests = PendingSignatureRequests::new(
            clock.clock(),
            participants.clone(),
            my_participant_id,
            network_api.clone(),
        );

        for participant in &participants {
            network_api.set_height(*participant, 100);
        }

        let t = TestBlockMaker::new();

        let req1 = test_sign_request(&participants, &[0]);
        let req2 = test_sign_request(&participants, &[1]);
        let b1 = t.block(100);
        pending_requests.notify_new_block(
            vec![req1.clone(), req2.clone()],
            vec![],
            &b1.to_block_view(),
        );

        let to_attempt1 = pending_requests.get_signatures_to_attempt();
        assert_eq!(to_attempt1.len(), 1);
        assert_eq!(to_attempt1[0].request.id, req2.id);

        // Another attempt should not be issued while the first one is still ongoing.
        clock.advance(Duration::seconds(2));
        assert_eq!(pending_requests.get_signatures_to_attempt().len(), 0);

        let req3 = test_sign_request(&participants, &[1]);
        let req4 = test_sign_request(&participants, &[2]);
        let b2 = b1.child(101);
        pending_requests.notify_new_block(
            vec![req3.clone(), req4.clone()],
            vec![],
            &b2.to_block_view(),
        );

        let to_attempt2 = pending_requests.get_signatures_to_attempt();
        assert_eq!(to_attempt2.len(), 1);
        assert_eq!(to_attempt2[0].request.id, req3.id);

        clock.advance(Duration::seconds(2));
        assert_eq!(pending_requests.get_signatures_to_attempt().len(), 0);

        // Drop the attempt on req2. It should not immediately retry, because we need to wait
        // for at least a second before retrying anything.
        drop(to_attempt1);
        assert_eq!(pending_requests.get_signatures_to_attempt().len(), 0);
        clock.advance(CHECK_EACH_SIGNATURE_REQUEST_INTERVAL);
        let to_attempt3 = pending_requests.get_signatures_to_attempt();
        assert_eq!(to_attempt3.len(), 1);
        assert_eq!(to_attempt3[0].request.id, req2.id);

        // This attempt submits a response, but it is not yet recorded on the blockchain.
        to_attempt3[0]
            .computation_progress
            .lock()
            .unwrap()
            .last_response_submission = Some(clock.now());
        drop(to_attempt3);
        clock.advance(CHECK_EACH_SIGNATURE_REQUEST_INTERVAL);
        assert_eq!(pending_requests.get_signatures_to_attempt().len(), 0);

        // The response doesn't get recorded on the blockchain. It should try again.
        clock.advance(MAX_LATENCY_BEFORE_EXPECTING_TRANSACTION_TO_FINALIZE);
        let to_attempt4 = pending_requests.get_signatures_to_attempt();
        assert_eq!(to_attempt4.len(), 1);
        assert_eq!(to_attempt4[0].request.id, req2.id);

        // This time it gets onto the blockchain, but the block isn't finalized yet, so we should still retry.
        drop(to_attempt4);
        let b3 = b2.child(102);
        pending_requests.notify_new_block(vec![], vec![req2.id], &b3.to_block_view());
        clock.advance(CHECK_EACH_SIGNATURE_REQUEST_INTERVAL);
        assert_eq!(pending_requests.get_signatures_to_attempt().len(), 1);

        // Make b3 final, so the response is recorded, removing the request.
        let b4 = b3.child(103);
        let b5 = b4.child(104);
        pending_requests.notify_new_block(vec![], vec![], &b4.to_block_view());
        pending_requests.notify_new_block(vec![], vec![], &b5.to_block_view());
        clock.advance(CHECK_EACH_SIGNATURE_REQUEST_INTERVAL);
        assert_eq!(pending_requests.get_signatures_to_attempt().len(), 0);
    }

    #[test]
    fn test_pending_signature_requests_discard_old_and_non_canonical_requests() {
        init_logging();
        let clock = FakeClock::default();
        let participants = TestGenerators::new_contiguous_participant_ids(4, 3).participant_ids();
        let my_participant_id = participants[1];
        let network_api = Arc::new(TestNetworkAPI::new(&participants));

        let mut pending_requests = PendingSignatureRequests::new(
            clock.clock(),
            participants.clone(),
            my_participant_id,
            network_api.clone(),
        );

        for participant in &participants {
            network_api.set_height(*participant, 350);
        }

        let t = TestBlockMaker::new();

        let req1 = test_sign_request(&participants, &[1]);
        let req2 = test_sign_request(&participants, &[1]);
        let b1 = t.block(100);
        let b2 = b1.child(200);
        pending_requests.notify_new_block(vec![req1.clone()], vec![], &b1.to_block_view());
        pending_requests.notify_new_block(vec![req2.clone()], vec![], &b2.to_block_view());

        // The first request expired, so only the second one is returned.
        let to_attempt1 = pending_requests.get_signatures_to_attempt();
        assert_eq!(to_attempt1.len(), 1);
        assert_eq!(to_attempt1[0].request.id, req2.id);

        drop(to_attempt1);
        clock.advance(CHECK_EACH_SIGNATURE_REQUEST_INTERVAL);

        // Set participants to a newer height, expiring the second request as well; it should not retry.
        for participant in &participants {
            network_api.set_height(*participant, 500);
        }
        assert_eq!(pending_requests.get_signatures_to_attempt().len(), 0);

        clock.advance(CHECK_EACH_SIGNATURE_REQUEST_INTERVAL);
        let req3 = test_sign_request(&participants, &[1]);
        let b3 = b2.child(350);
        pending_requests.notify_new_block(vec![req3.clone()], vec![], &b3.to_block_view());

        // The third request is now recent enough.
        let to_attempt2 = pending_requests.get_signatures_to_attempt();
        assert_eq!(to_attempt2.len(), 1);
        assert_eq!(to_attempt2[0].request.id, req3.id);

        // Add a new request in a different fork that becomes the canonical chain.
        // Req3 is now on a non-canonical fork so should not be attempted.
        drop(to_attempt2);
        clock.advance(CHECK_EACH_SIGNATURE_REQUEST_INTERVAL);
        let b4 = b2.child(360);
        let req4 = test_sign_request(&participants, &[1]);
        pending_requests.notify_new_block(vec![req4.clone()], vec![], &b4.to_block_view());

        let to_attempt3 = pending_requests.get_signatures_to_attempt();
        assert_eq!(to_attempt3.len(), 1);
        assert_eq!(to_attempt3[0].request.id, req4.id);

        // Bring req3's block back to canonical; now we should attempt that instead.
        drop(to_attempt3);
        clock.advance(CHECK_EACH_SIGNATURE_REQUEST_INTERVAL);
        let b5 = b3.child(370);
        let req5 = test_sign_request(&participants, &[1]);
        pending_requests.notify_new_block(vec![req5.clone()], vec![], &b5.to_block_view());

        let to_attempt4 = pending_requests.get_signatures_to_attempt();
        assert_eq!(to_attempt4.len(), 2);
        assert_eq!(
            to_attempt4.iter().map(|a| a.request.id).collect::<Vec<_>>(),
            &[req3.id, req5.id]
        );
    }

    #[test]
    fn test_pending_signature_requests_fallback_leader() {
        init_logging();
        let clock = FakeClock::default();
        let participants = TestGenerators::new_contiguous_participant_ids(4, 3).participant_ids();
        let my_participant_id = participants[1];
        let network_api = Arc::new(TestNetworkAPI::new(&participants));

        let mut pending_requests = PendingSignatureRequests::new(
            clock.clock(),
            participants.clone(),
            my_participant_id,
            network_api.clone(),
        );

        // Indexer 0 is offline; indexer 2 is stale. We let indexer 0 have a higher height than
        // normal. This is to test a pathological case, in case some node reports an incorrectly high
        // height and we want to allow shutting down that node to be a mitigation.
        network_api.bring_down(participants[0]);
        network_api.set_height(participants[0], 120); // ignored because offline
        network_api.set_height(participants[1], 100);
        network_api.set_height(participants[2], 80); // stale
        network_api.set_height(participants[3], 100);

        let t = TestBlockMaker::new();

        let req1 = test_sign_request(&participants, &[0, 1]);
        let req2 = test_sign_request(&participants, &[2, 0, 1]);
        let req3 = test_sign_request(&participants, &[3, 1]);
        let b1 = t.block(100);
        pending_requests.notify_new_block(
            vec![req1.clone(), req2.clone(), req3.clone()],
            vec![],
            &b1.to_block_view(),
        );

        // Since 0 and 2 are unavailable, and we are the first available leader for req1 and req2,
        // we should attempt these.
        let to_attempt1 = pending_requests.get_signatures_to_attempt();
        assert_eq!(to_attempt1.len(), 2);
        assert!(set_equals(
            &to_attempt1.iter().map(|a| a.request.id).collect::<Vec<_>>(),
            &[req1.id, req2.id]
        ));

        drop(to_attempt1);
        clock.advance(CHECK_EACH_SIGNATURE_REQUEST_INTERVAL);

        // Bring up node 0. This causes node 1 to itself realize it is stale, so it should refuse to
        // attempt any signatures, even if it were the preferred leader.
        network_api.bring_up(participants[0]);
        let b2 = b1.child(101);
        let req4 = test_sign_request(&participants, &[1]);
        pending_requests.notify_new_block(vec![req4.clone()], vec![], &b2.to_block_view());
        assert_eq!(pending_requests.get_signatures_to_attempt().len(), 0);

        // Bring down node 0 again. Now, node 1 should retry req1, req2 again, as well as trying req4.
        network_api.bring_down(participants[0]);
        clock.advance(CHECK_EACH_SIGNATURE_REQUEST_INTERVAL);
        let to_attempt2 = pending_requests.get_signatures_to_attempt();
        assert_eq!(to_attempt2.len(), 3);
        assert!(set_equals(
            &to_attempt2.iter().map(|a| a.request.id).collect::<Vec<_>>(),
            &[req1.id, req2.id, req4.id]
        ));

        // Node 0 actually manages to complete req1 and req4 somehow. Node 1 should not retry
        // these anymore.
        drop(to_attempt2);
        let b3 = b2.child(102);
        let b4 = b3.child(103);
        let b5 = b4.child(104);
        pending_requests.notify_new_block(vec![], vec![req1.id, req4.id], &b3.to_block_view());
        pending_requests.notify_new_block(vec![], vec![], &b4.to_block_view());
        pending_requests.notify_new_block(vec![], vec![], &b5.to_block_view());
        clock.advance(CHECK_EACH_SIGNATURE_REQUEST_INTERVAL);

        let to_attempt3 = pending_requests.get_signatures_to_attempt();
        assert_eq!(to_attempt3.len(), 1);
        assert_eq!(to_attempt3[0].request.id, req2.id);
    }
}
