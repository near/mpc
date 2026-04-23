use super::debug::{CompletedRequest, CompletedRequests};
use super::recent_blocks_tracker::BlockViewLite;
use crate::indexer::types::ChainRespondArgs;
use crate::primitives::ParticipantId;
use crate::requests::metrics;
use crate::requests::recent_blocks_tracker::{
    BlockReference, CheckBlockResult, RecentBlocksTracker,
};
use crate::types::{self, FromChain, Request, RequestId};
use k256::sha2::Sha256;
use near_indexer_primitives::types::NumBlocks;
use near_indexer_primitives::CryptoHash;
use near_time::Duration;
use sha3::Digest;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::sync::{Arc, Mutex, Weak};
use time::ext::InstantExt as _;

/// Thin API that the queue needs from the network.
pub trait NetworkAPIForRequests: Send + Sync + 'static {
    /// Returns the participants that are currently connected to us.
    fn alive_participants(&self) -> HashSet<ParticipantId>;
    /// Returns the height of each indexer, including us. This must return all
    /// participants, even those who are never connected.
    fn indexer_heights(&self) -> HashMap<ParticipantId, u64>;
    /// returns the maximum known block height of all alive participants
    fn get_max_indexer_height(&self) -> u64 {
        let indexer_heights = self.indexer_heights();
        let alive_participants = self.alive_participants();
        alive_participants
            .iter()
            .map(|p| indexer_heights.get(p).copied().unwrap_or(0))
            .max()
            .unwrap_or(0)
    }
}

/// The minimum time that must elapse before we'll consider each request for another attempt.
pub const CHECK_EACH_REQUEST_INTERVAL: Duration = Duration::seconds(1);
/// A participant is considered stale if its indexer's highest height is this many blocks behind
/// the highest height of all participants.
const STALE_PARTICIPANT_THRESHOLD: NumBlocks = 10;
/// The number of blocks after which a request is assumed to have timed out.
/// This is equal to the yield-resume timeout on the blockchain.
pub(crate) const REQUEST_EXPIRATION_BLOCKS: NumBlocks = 200;
/// The maximum time we'll wait, after a transaction is submitted to the chain, before we decide
/// that the transaction is lost and that we should retry.
const MAX_LATENCY_BEFORE_EXPECTING_TRANSACTION_TO_FINALIZE: Duration = Duration::seconds(10);
/// Maximum attempts we should make for each request when we are the leader.
const MAX_ATTEMPTS_PER_REQUEST_AS_LEADER: u64 = 10;

/// Manages the queue of requests that still need to be handled.
/// The inputs to this queue are:
///  - Every block that comes from the indexer. For each block, we need the list of
///    requests as well as the list of completed requests (i.e. responses).
///  - The set of alive participants (nodes that we're currently connected to).
///  - The height of the indexer of each participant.
///
/// What this queue then provides, via `get_requests_to_attempt`, is a list of requests
/// that we should attempt to generate a request for. The list will be generated based on the
/// following goals:
///  - Assuming the network state is stable and nodes have consistent views of the connectivity and
///    indexer heights, each request will be attempted by exactly one node ("leader").
///  - Each request will be retried (by the current leader) if it has not been
///    successfully responded to on chain.
///  - If network state fluctuates (nodes going down or back up, or indexers falling behind),
///    the queue will adapt to the new state and attempt to find new leaders for the requests.
///  - If a request is too old so that it would have timed out on chain, it will be
///    discarded.
pub struct PendingRequests<RequestType: Request, ChainRespondArgsType: ChainRespondArgs> {
    pub(super) clock: near_time::Clock,

    /// All participants in the network, regardless of whether they are online.
    pub(super) all_participants: Vec<ParticipantId>,
    pub(super) my_participant_id: ParticipantId,

    /// Map from request ID to the request. Successful and expired requests are removed
    /// from this map. This is the "queue".
    pub(super) requests: HashMap<RequestId, QueuedRequest<RequestType, ChainRespondArgsType>>,

    /// Provides information about connectivity and indexer heights.
    pub(super) network_api: Arc<dyn NetworkAPIForRequests>,

    /// Recently completed requests, for debugging purposes only.
    pub(super) recently_completed_requests: CompletedRequests<RequestType, ChainRespondArgsType>,
}

/// A block in which the response to a queued request has been observed.
#[derive(Clone, Debug)]
struct SubmittedResponse {
    block_hash: CryptoHash,
    block_height: u64,
    /// Wall-clock time at which the queue observed the block containing the response.
    /// Captured here (not derived from `now` at finality-detection time) so
    /// `*_REQUEST_RESPONSE_LATENCY_SECONDS` continues to measure
    /// (response-block seen) − (request-block seen).
    timestamp_received: near_time::Instant,
}

/// The state of a single request in the queue.
pub(super) struct QueuedRequest<RequestType: Request, ChainRespondArgsType: ChainRespondArgs> {
    pub request: RequestType,

    /// The block hash the request was received in. Stored as a hash (not `Arc<BlockNode>`)
    /// so the queue stays decoupled from tracker internals; the tracker classifies this
    /// block on demand via `classify_block`.
    block_hash: CryptoHash,
    pub block_height: u64,

    /// A pre-computed order of participants that we consider for leader selection.
    /// The leader for the request would be the first in this list that is eligible
    /// (online and indexer not stale).
    pub leader_selection_order: Vec<ParticipantId>,

    /// A throttling mechanism to prevent doing too much computation on each request.
    /// This allows `get_requests_to_attempt` to be called as frequently as desired.
    next_check_due: near_time::Instant,

    /// Progress of the computation of the request. Serves multiple purposes:
    ///  - As a way to allow multiple attempts to keep some persistent state to prevent unnecessary
    ///    recomputations;
    ///  - To determine when to retry after the response is submitted to chain;
    ///  - For debugging and monitoring.
    pub computation_progress: Arc<Mutex<ComputationProgress<ChainRespondArgsType>>>,

    /// The current attempt to generate the request. This is weak to detect if the attempt has
    /// completed.
    pub active_attempt: Weak<GenerationAttempt<RequestType, ChainRespondArgsType>>,

    /// The time that the request was indexed.
    pub time_indexed: near_time::Instant,

    /// Blocks in which a response to this request has been observed.
    /// With forks and retries, the same response can legitimately land in multiple
    /// blocks; any one reaching finality completes the request. Entries are pruned
    /// on each tick in `get_requests_to_attempt` against the current tracker state.
    response_blocks: Vec<SubmittedResponse>,
}

/// Struct given to the response generation code.
pub struct GenerationAttempt<RequestType: Request, ChainRespondArgsType: ChainRespondArgs> {
    /// The request we should attempt to generate for.
    pub request: RequestType,
    /// The progress of the computation. Writable and survives multiple attempts.
    pub computation_progress: Arc<Mutex<ComputationProgress<ChainRespondArgsType>>>,
}

/// Progress that persists across attempts.
pub struct ComputationProgress<ChainRespondArgsType: ChainRespondArgs> {
    /// Number of attempts that have been made to generate the request.
    /// This is used to abort after too many attempts.
    pub attempts: u64,
    /// The computed response, if any. This is used to prevent unnecessary recomputation,
    /// if all that's needed is to submit the response to chain.
    pub computed_response: Option<ChainRespondArgsType>,
    /// The leader selected during computation
    pub selected_leader: Option<ParticipantId>,
    /// The time and when the last response was submitted to chain.
    /// This is used to delay the next retry as well as debugging.
    pub last_response_submission: Option<near_time::Instant>,
}

impl<ChainRespondArgsType: ChainRespondArgs> Default for ComputationProgress<ChainRespondArgsType> {
    fn default() -> Self {
        Self {
            attempts: Default::default(),
            computed_response: Default::default(),
            selected_leader: Default::default(),
            last_response_submission: Default::default(),
        }
    }
}

impl<RequestType: Request, ChainRespondArgsType: ChainRespondArgs>
    QueuedRequest<RequestType, ChainRespondArgsType>
{
    pub fn new(
        clock: &near_time::Clock,
        request: RequestType,
        block_hash: CryptoHash,
        block_height: u64,
        all_participants: &[ParticipantId],
        time_indexed: near_time::Instant,
    ) -> Self {
        let leader_selection_order =
            Self::leader_selection_order(all_participants, request.get_id());
        tracing::debug!(target: "request", "Leader selection order for request {:?} from block {}: {:?}", request.get_id(), block_height, leader_selection_order);

        Self {
            request,
            block_hash,
            block_height,
            leader_selection_order,
            computation_progress: Arc::new(Mutex::new(ComputationProgress::default())),
            next_check_due: clock.now(),
            active_attempt: Weak::new(),
            time_indexed,
            response_blocks: Vec::new(),
        }
    }

    /// Computes the leader selection order for a given request.
    /// This will be a different pseudorandom order for each request.
    fn leader_selection_order(
        participants: &[ParticipantId],
        request_id: CryptoHash,
    ) -> Vec<ParticipantId> {
        let mut leader_selection_hashes = participants
            .iter()
            .map(|p| (Self::leader_selection_hash(p, request_id), *p))
            .collect::<Vec<_>>();
        leader_selection_hashes.sort();
        leader_selection_hashes
            .into_iter()
            .map(|(_, p)| p)
            .collect()
    }

    fn leader_selection_hash(participant_id: &ParticipantId, request_id: CryptoHash) -> u64 {
        let mut h = Sha256::new();
        h.update(participant_id.raw().to_le_bytes());
        h.update(request_id.0);
        let hash: [u8; 32] = h.finalize().into();
        u64::from_le_bytes(hash[0..8].try_into().unwrap())
    }

    /// Selects the leader given the current state of the network.
    pub fn current_leader(
        &self,
        eligible_leaders: &HashSet<ParticipantId>,
    ) -> Option<ParticipantId> {
        for candidate_leader in &self.leader_selection_order {
            if eligible_leaders.contains(candidate_leader) {
                return Some(*candidate_leader);
            }
        }
        None
    }
}

pub(crate) struct Requests<T> {
    pub(crate) block: BlockReference,
    pub(crate) requests: Vec<T>,
    pub(crate) completed_requests: Vec<RequestId>,
}

impl<T> Requests<T> {
    pub(crate) fn from_chain<U>(
        block: &BlockViewLite,
        new_requests: Vec<U>,
        completed_requests: Vec<CryptoHash>,
    ) -> Requests<T>
    where
        T: FromChain<U>,
    {
        let requests = new_requests
            .into_iter()
            .map(|request_from_chain| T::from_chain(request_from_chain, block))
            .collect::<Vec<_>>();

        Requests {
            block: block.clone().into(),
            requests,
            completed_requests,
        }
    }
}

impl<RequestType: Request + Clone, ChainRespondArgsType: ChainRespondArgs>
    PendingRequests<RequestType, ChainRespondArgsType>
{
    pub fn new(
        clock: near_time::Clock,
        all_participants: Vec<ParticipantId>,
        my_participant_id: ParticipantId,
        network_api: Arc<dyn NetworkAPIForRequests>,
    ) -> Self {
        Self {
            clock,
            all_participants,
            my_participant_id,
            requests: HashMap::new(),
            network_api,
            recently_completed_requests: CompletedRequests::default(),
        }
    }

    // todo: write explanatory comment. No longer needs to be recorded for every block
    pub(crate) fn notify_new_block(&mut self, requests: Requests<RequestType>) {
        let Requests {
            block,
            requests,
            completed_requests,
        } = requests;
        let (
            mpc_pending_queue_blocks_indexed,
            mpc_pending_queue_responses_indexed,
            mpc_pending_queue_matching_responses_indexed,
            mpc_pending_requests_queue_requests_indexed,
        ) = match RequestType::get_type() {
            types::RequestType::CKD => (
                &metrics::MPC_PENDING_CKDS_QUEUE_BLOCKS_INDEXED,
                &metrics::MPC_PENDING_CKDS_QUEUE_RESPONSES_INDEXED,
                &metrics::MPC_PENDING_CKDS_QUEUE_MATCHING_RESPONSES_INDEXED,
                &metrics::MPC_PENDING_CKDS_QUEUE_REQUESTS_INDEXED,
            ),
            types::RequestType::Signature => (
                &metrics::MPC_PENDING_SIGNATURES_QUEUE_BLOCKS_INDEXED,
                &metrics::MPC_PENDING_SIGNATURES_QUEUE_RESPONSES_INDEXED,
                &metrics::MPC_PENDING_SIGNATURES_QUEUE_MATCHING_RESPONSES_INDEXED,
                &metrics::MPC_PENDING_SIGNATURES_QUEUE_REQUESTS_INDEXED,
            ),
            types::RequestType::VerifyForeignTx => (
                &metrics::MPC_PENDING_VERIFY_FOREIGN_TXS_QUEUE_BLOCKS_INDEXED_TOTAL,
                &metrics::MPC_PENDING_VERIFY_FOREIGN_TXS_QUEUE_RESPONSES_INDEXED_TOTAL,
                &metrics::MPC_PENDING_VERIFY_FOREIGN_TXS_QUEUE_MATCHING_RESPONSES_INDEXED_TOTAL,
                &metrics::MPC_PENDING_VERIFY_FOREIGN_TXS_QUEUE_REQUESTS_INDEXED_TOTAL,
            ),
        };

        mpc_pending_queue_blocks_indexed.inc();
        mpc_pending_queue_responses_indexed.inc_by(completed_requests.len() as u64);

        let now = self.clock.now();
        for request_id in &completed_requests {
            if let Some(request) = self.requests.get_mut(request_id) {
                mpc_pending_queue_matching_responses_indexed.inc();
                request.response_blocks.push(SubmittedResponse {
                    block_hash: block.hash,
                    block_height: block.height,
                    timestamp_received: now,
                });
            }
        }

        mpc_pending_requests_queue_requests_indexed.inc_by(requests.len() as u64);
        for request in requests {
            self.requests
                .entry(request.get_id())
                .or_insert(QueuedRequest::new(
                    &self.clock,
                    request.clone(),
                    block.hash,
                    block.height,
                    &self.all_participants,
                    now,
                ));
        }
    }

    /// Returns the set of participants that are eligible to be leaders for the requests,
    /// as well as the maximum height available.
    pub(super) fn eligible_leaders_and_maximum_height(&self) -> (HashSet<ParticipantId>, u64) {
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
        (eligible_leaders, maximum_height)
    }

    /// Returns the list of requests that we should attempt to generate a response for,
    /// right now, as the leader.
    ///
    /// The returned objects should only be dropped if:
    ///  - The generation has failed. A retry can be issued immediately after that,
    ///    subject to a throttle of once per CHECK_EACH_REQUEST_INTERVAL.
    ///  - The generation is successful, and the time that the response is submitted to
    ///    the chain has been written to the `ComputationProgress`.
    pub fn get_requests_to_attempt(
        &mut self,
        recent_blocks: &mut RecentBlocksTracker,
    ) -> Vec<Arc<GenerationAttempt<RequestType, ChainRespondArgsType>>> {
        let now = self.clock.now();

        let (eligible_leaders, maximum_height) = self.eligible_leaders_and_maximum_height();
        tracing::debug!(target: "request", "Eligible leaders: {:?}", eligible_leaders);
        recent_blocks.notify_maximum_height_available(maximum_height);

        let (request_response_latency_blocks, request_response_latency_seconds) =
            match RequestType::get_type() {
                types::RequestType::CKD => (
                    &metrics::CKD_REQUEST_RESPONSE_LATENCY_BLOCKS,
                    &metrics::CKD_REQUEST_RESPONSE_LATENCY_SECONDS,
                ),
                types::RequestType::Signature => (
                    &metrics::SIGNATURE_REQUEST_RESPONSE_LATENCY_BLOCKS,
                    &metrics::SIGNATURE_REQUEST_RESPONSE_LATENCY_SECONDS,
                ),
                types::RequestType::VerifyForeignTx => (
                    &metrics::VERIFY_FOREIGN_TXS_REQUEST_RESPONSE_LATENCY_BLOCKS,
                    &metrics::VERIFY_FOREIGN_TXS_REQUEST_RESPONSE_LATENCY_SECONDS,
                ),
            };

        let mut result = Vec::new();

        let mut requests_to_remove: Vec<(RequestId, Option<(u64, Duration)>)> = Vec::new();
        for (id, request) in &mut self.requests {
            // Did any observed response block reach finality since the last tick?
            // Drop entries whose block died on a fork or aged out of the window.
            let mut finalized_completion: Option<SubmittedResponse> = None;
            request.response_blocks.retain(|sr| {
                match recent_blocks.classify_block(sr.block_hash, sr.block_height) {
                    CheckBlockResult::RecentAndFinal => {
                        if finalized_completion.is_none() {
                            finalized_completion = Some(sr.clone());
                        }
                        false
                    }
                    CheckBlockResult::NotIncluded | CheckBlockResult::OlderThanRecentWindow => {
                        false
                    }
                    CheckBlockResult::OptimisticAndCanonical
                    | CheckBlockResult::OptimisticButNotCanonical
                    | CheckBlockResult::Unknown => true,
                }
            });
            if let Some(sr) = finalized_completion {
                tracing::debug!(target: "request", "Removing completed request {:?}", request.request.get_id());
                let latency_blocks = sr.block_height - request.block_height;
                let latency_duration = sr
                    .timestamp_received
                    .signed_duration_since(request.time_indexed);
                request_response_latency_blocks.observe(latency_blocks as f64);
                request_response_latency_seconds.observe(latency_duration.as_seconds_f64());
                requests_to_remove.push((*id, Some((latency_blocks, latency_duration))));
                continue;
            }

            if request.next_check_due > now {
                tracing::debug!(target: "request", "Skipping request {:?} from block {} because it's not time yet", request.request.get_id(), request.block_height);
                continue;
            }
            request.next_check_due = now + CHECK_EACH_REQUEST_INTERVAL;
            if request.active_attempt.strong_count() > 0 {
                // There's a current attempt to generate the response, so don't do anything.
                tracing::debug!(target: "request", "Skipping request {:?} from block {} because there's already an active attempt", request.request.get_id(), request.block_height);
                continue;
            }
            match recent_blocks.classify_block(request.block_hash, request.block_height) {
                CheckBlockResult::RecentAndFinal
                | CheckBlockResult::OptimisticAndCanonical
                | CheckBlockResult::Unknown => {
                    if let Some(leader) = request.current_leader(&eligible_leaders) {
                        tracing::debug!(target: "request", "Leader for {} request {:?} from block {} is {}", RequestType::get_type(), request.request.get_id(), request.block_height, leader);
                        let mut progress = request.computation_progress.lock().unwrap();
                        progress.selected_leader = Some(leader);
                        if leader == self.my_participant_id {
                            // TODO: removing the request from our queue only stops us
                            // retrying as leader. Another node's leader can still ask us
                            // to participate via a passive channel, and we'll reject
                            // because the request is gone. Consider tracking "gave up as
                            // leader" separately from "removed entirely".
                            if progress.attempts >= MAX_ATTEMPTS_PER_REQUEST_AS_LEADER {
                                tracing::debug!(target: "request", "Discarding {} request {:?} from block {} because it has been attempted too many ({}) times", RequestType::get_type(), request.request.get_id(), request.block_height, MAX_ATTEMPTS_PER_REQUEST_AS_LEADER);
                                // Increment metric for max retries exceeded (only for signature requests)
                                if matches!(RequestType::get_type(), types::RequestType::Signature)
                                {
                                    metrics::MPC_CLUSTER_FAILED_SIGNATURES_COUNT
                                        .with_label_values(&["max_tries_exceeded"])
                                        .inc();
                                }
                                requests_to_remove.push((*id, None));
                                continue;
                            }
                            if progress.last_response_submission.is_some_and(|t| {
                                now < t + MAX_LATENCY_BEFORE_EXPECTING_TRANSACTION_TO_FINALIZE
                            }) {
                                tracing::debug!(target: "request", "Skipping {} request {:?} from block {} because the last response was submitted too recently", RequestType::get_type(), request.request.get_id(), request.block_height);
                                continue;
                            }
                            progress.attempts += 1;
                            let attempt = Arc::new(GenerationAttempt {
                                request: request.request.clone(),
                                computation_progress: request.computation_progress.clone(),
                            });
                            request.active_attempt = Arc::downgrade(&attempt);
                            result.push(attempt);
                        }
                    }
                }
                CheckBlockResult::OptimisticButNotCanonical => {
                    // Don't act on it yet. If it becomes canonical later, we'll try to generate
                    // the request.
                    tracing::debug!(target: "request", "Ignoring non-canonical {} request {:?} from block {}", RequestType::get_type(), request.request.get_id(), request.block_height);
                }
                CheckBlockResult::NotIncluded | CheckBlockResult::OlderThanRecentWindow => {
                    tracing::debug!(target: "request", "Discarding {} request {:?} from block {}", RequestType::get_type(), request.request.get_id(), request.block_height);
                    // Increment metric for timeout (only for signature requests)
                    if matches!(RequestType::get_type(), types::RequestType::Signature) {
                        metrics::MPC_CLUSTER_FAILED_SIGNATURES_COUNT
                            .with_label_values(&["timeout"])
                            .inc();
                    }

                    // This request is definitely not useful anymore, so discard it.
                    requests_to_remove.push((*id, None));
                }
            }
        }
        for (id, completion_delay) in requests_to_remove {
            if let Some(request) = self.requests.remove(&id) {
                self.recently_completed_requests
                    .add_completed_request(CompletedRequest {
                        indexed_block_height: request.block_height,
                        request: request.request,
                        progress: request.computation_progress,
                        completion_delay,
                    });
            }
        }
        let (mpc_pending_requests_queue_size, mpc_pending_requests_queue_attempts_generated) =
            match RequestType::get_type() {
                types::RequestType::CKD => (
                    &metrics::MPC_PENDING_CKDS_QUEUE_SIZE,
                    &metrics::MPC_PENDING_CKDS_QUEUE_ATTEMPTS_GENERATED,
                ),
                types::RequestType::Signature => (
                    &metrics::MPC_PENDING_SIGNATURES_QUEUE_SIZE,
                    &metrics::MPC_PENDING_SIGNATURES_QUEUE_ATTEMPTS_GENERATED,
                ),
                types::RequestType::VerifyForeignTx => (
                    &metrics::MPC_PENDING_VERIFY_FOREIGN_TX_QUEUE_SIZE_TOTAL,
                    &metrics::MPC_PENDING_VERIFY_FOREIGN_TX_QUEUE_ATTEMPTS_GENERATED_TOTAL,
                ),
            };

        mpc_pending_requests_queue_size.set(self.requests.len() as i64);
        mpc_pending_requests_queue_attempts_generated.inc_by(result.len() as u64);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::{NetworkAPIForRequests, PendingRequests, QueuedRequest, Requests};
    use crate::indexer::types::{ChainCKDRespondArgs, ChainRespondArgs, ChainSignatureRespondArgs};
    use crate::primitives::ParticipantId;
    use crate::requests::queue::{
        CHECK_EACH_REQUEST_INTERVAL, MAX_ATTEMPTS_PER_REQUEST_AS_LEADER,
        MAX_LATENCY_BEFORE_EXPECTING_TRANSACTION_TO_FINALIZE, REQUEST_EXPIRATION_BLOCKS,
    };
    use crate::requests::recent_blocks_tracker::tests::{TestBlock, TestBlockMaker};
    use crate::requests::recent_blocks_tracker::RecentBlocksTracker;
    use crate::tests::into_participant_ids;
    use crate::types::{CKDRequest, Request, RequestId, SignatureRequest};
    use mpc_primitives::domain::DomainId;
    use near_indexer_primitives::CryptoHash;
    use near_mpc_contract_interface::types::{Payload, Tweak};
    use near_time::{Duration, FakeClock};
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};
    use threshold_signatures::test_utils::generate_participants;

    // ── TestRequestFactory ──────────────────────────────────────────────

    trait TestRequestFactory: Request + Clone {
        fn make(participants: &[ParticipantId], desired_leaders: &[ParticipantId]) -> Self;
    }

    impl TestRequestFactory for CKDRequest {
        fn make(participants: &[ParticipantId], desired_leaders: &[ParticipantId]) -> Self {
            loop {
                let request = CKDRequest {
                    id: CryptoHash(rand::random()),
                    receipt_id: CryptoHash(rand::random()),
                    app_public_key:
                        near_mpc_contract_interface::types::CKDAppPublicKey::AppPublicKey(
                            "bls12381g1:6KtVVcAAGacrjNGePN8bp3KV6fYGrw1rFsyc7cVJCqR16Zc2ZFg3HX3hSZxSfv1oH6"
                                .parse()
                                .unwrap(),
                        ),
                    app_id: [1u8; 32].into(),
                    entropy: [0; 32],
                    timestamp_nanosec: 0,
                    domain_id: DomainId::legacy_ecdsa_id(),
                };
                let order =
                    QueuedRequest::<CKDRequest, ChainCKDRespondArgs>::leader_selection_order(
                        participants,
                        request.id,
                    );
                if order.starts_with(desired_leaders) {
                    return request;
                }
            }
        }
    }

    impl TestRequestFactory for SignatureRequest {
        fn make(participants: &[ParticipantId], desired_leaders: &[ParticipantId]) -> Self {
            loop {
                let request = SignatureRequest {
                    id: CryptoHash(rand::random()),
                    receipt_id: CryptoHash([0; 32]),
                    entropy: [0; 32],
                    payload: Payload::from_legacy_ecdsa([0; 32]),
                    timestamp_nanosec: 0,
                    tweak: Tweak::new([0; 32]),
                    domain: DomainId::legacy_ecdsa_id(),
                };
                let order = QueuedRequest::<SignatureRequest, ChainSignatureRespondArgs>::leader_selection_order(
                    participants,
                    request.id,
                );
                if order.starts_with(desired_leaders) {
                    return request;
                }
            }
        }
    }

    // ── TestNetworkAPI ──────────────────────────────────────────────────

    fn set_equals<T: Clone + Eq + Ord>(a: &[T], b: &[T]) -> bool {
        let mut a = a.to_vec();
        let mut b = b.to_vec();
        a.sort();
        b.sort();
        a == b
    }

    struct TestNetworkAPI {
        alive: Mutex<HashSet<ParticipantId>>,
        heights: Mutex<HashMap<ParticipantId, u64>>,
    }

    impl NetworkAPIForRequests for TestNetworkAPI {
        fn alive_participants(&self) -> HashSet<ParticipantId> {
            self.alive.lock().unwrap().clone()
        }

        fn indexer_heights(&self) -> HashMap<ParticipantId, u64> {
            self.heights.lock().unwrap().clone()
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
            self.heights.lock().unwrap().insert(participant, height);
        }
    }

    // ── TestSetup + Builder ─────────────────────────────────────────────

    struct TestSetup {
        clock: FakeClock,
        participants: Vec<ParticipantId>,
        my_id: ParticipantId,
        other_id: ParticipantId,
        network_api: Arc<TestNetworkAPI>,
        tracker: RecentBlocksTracker,
        block_maker: Arc<TestBlockMaker>,
        chain_head: Option<Arc<TestBlock>>,
        next_height: u64,
    }

    struct TestSetupBuilder {
        participant_heights: Option<u64>,
        start_height: Option<u64>,
    }

    impl TestSetup {
        fn builder() -> TestSetupBuilder {
            TestSetupBuilder {
                participant_heights: None,
                start_height: None,
            }
        }

        fn block_builder<R: TestRequestFactory>(&self) -> BlockBuilder<R> {
            BlockBuilder {
                participants: self.participants.clone(),
                requests: Vec::new(),
                completed: Vec::new(),
                height_override: None,
            }
        }

        fn advance(&self, duration: Duration) {
            self.clock.advance(duration);
        }

        #[expect(dead_code)]
        fn set_all_participant_heights(&self, h: u64) {
            for p in &self.participants {
                self.network_api.set_height(*p, h);
            }
        }

        fn set_participant_height(&self, idx: usize, h: u64) {
            self.network_api.set_height(self.participants[idx], h);
        }

        fn set_participant_offline(&self, idx: usize) {
            self.network_api.bring_down(self.participants[idx]);
        }

        fn set_participant_online(&self, idx: usize) {
            self.network_api.bring_up(self.participants[idx]);
        }

        #[expect(dead_code)]
        fn last_block(&self) -> Arc<TestBlock> {
            self.chain_head.clone().expect("no blocks have been built")
        }

        #[expect(dead_code)]
        fn set_chain_head(&mut self, block: &Arc<TestBlock>) {
            self.chain_head = Some(block.clone());
            self.next_height = block.height() + 1;
        }
    }

    impl TestSetupBuilder {
        fn with_participant_heights(mut self, h: u64) -> Self {
            self.participant_heights = Some(h);
            self
        }

        #[expect(dead_code)]
        fn with_start_height(mut self, h: u64) -> Self {
            self.start_height = Some(h);
            self
        }

        fn build<R: Request + Clone, C: ChainRespondArgs>(
            self,
        ) -> (TestSetup, PendingRequests<R, C>) {
            let clock = FakeClock::default();
            let participants = into_participant_ids(&generate_participants(4));
            let my_id = participants[1];
            let other_id = participants[0];
            let network_api = Arc::new(TestNetworkAPI::new(&participants));

            if let Some(h) = self.participant_heights {
                for p in &participants {
                    network_api.set_height(*p, h);
                }
            }

            let start_height = self
                .start_height
                .or(self.participant_heights)
                .unwrap_or(100);

            let pending_requests = PendingRequests::<R, C>::new(
                clock.clock(),
                participants.clone(),
                my_id,
                network_api.clone(),
            );

            let setup = TestSetup {
                clock,
                participants,
                my_id,
                other_id,
                network_api,
                tracker: RecentBlocksTracker::new(REQUEST_EXPIRATION_BLOCKS),
                block_maker: TestBlockMaker::new(),
                chain_head: None,
                next_height: start_height,
            };

            (setup, pending_requests)
        }
    }

    // ── BlockBuilder ────────────────────────────────────────────────────

    struct BlockBuilder<R: TestRequestFactory> {
        participants: Vec<ParticipantId>,
        requests: Vec<R>,
        completed: Vec<RequestId>,
        height_override: Option<u64>,
    }

    impl<R: TestRequestFactory> BlockBuilder<R> {
        fn with_request(mut self, desired_leaders: &[ParticipantId]) -> (Self, R) {
            let req = R::make(&self.participants, desired_leaders);
            self.requests.push(req.clone());
            (self, req)
        }

        fn with_completed(mut self, ids: Vec<RequestId>) -> Self {
            self.completed = ids;
            self
        }

        #[expect(dead_code)]
        fn with_height(mut self, h: u64) -> Self {
            self.height_override = Some(h);
            self
        }

        fn build(self, setup: &mut TestSetup) -> Requests<R> {
            let height = self.height_override.unwrap_or(setup.next_height);

            let block = match &setup.chain_head {
                Some(parent) => parent.child(height),
                None => setup.block_maker.block(height),
            };

            setup.tracker.add_block(&block.to_block_view());
            let block_ref = block.to_block_ref();

            setup.chain_head = Some(block);
            setup.next_height = height + 1;

            Requests {
                block: block_ref,
                requests: self.requests,
                completed_requests: self.completed,
            }
        }
    }

    // ── Tests ───────────────────────────────────────────────────────────

    #[test_log::test]
    fn test_pending_ckd_requests_leader_retry() {
        // Given
        let (mut setup, mut pending_requests) = TestSetup::builder()
            .with_participant_heights(100)
            .build::<CKDRequest, ChainCKDRespondArgs>();

        let b = setup.block_builder();
        let (b, _req1) = b.with_request(&[setup.other_id]);
        let (b, req2) = b.with_request(&[setup.my_id]);
        pending_requests.notify_new_block(b.build(&mut setup));

        // When / Then — req1 is not attempted because we're not the leader. req2 is attempted.
        let to_attempt1 = pending_requests.get_requests_to_attempt(&mut setup.tracker);
        assert_eq!(to_attempt1.len(), 1);
        assert_eq!(to_attempt1[0].request.id, req2.id);

        // Another attempt should not be issued while the first one is still ongoing.
        setup.advance(Duration::seconds(2));
        assert_eq!(
            pending_requests
                .get_requests_to_attempt(&mut setup.tracker)
                .len(),
            0
        );

        let b = setup.block_builder();
        let (b, req3) = b.with_request(&[setup.my_id]);
        let (b, _req4) = b.with_request(&[setup.participants[2]]);
        pending_requests.notify_new_block(b.build(&mut setup));

        // More ckd requests came in while we're attempting the first. req3 should be
        // attempted, because we're the leader as well. req4 is not attempted as we're not leader.
        let to_attempt2 = pending_requests.get_requests_to_attempt(&mut setup.tracker);
        assert_eq!(to_attempt2.len(), 1);
        assert_eq!(to_attempt2[0].request.id, req3.id);

        setup.advance(Duration::seconds(2));
        assert_eq!(
            pending_requests
                .get_requests_to_attempt(&mut setup.tracker)
                .len(),
            0
        );

        // Drop the attempt on req2. It should not immediately retry, because we need to wait
        // for at least a second before retrying anything.
        drop(to_attempt1);
        assert_eq!(
            pending_requests
                .get_requests_to_attempt(&mut setup.tracker)
                .len(),
            0
        );
        setup.advance(CHECK_EACH_REQUEST_INTERVAL);
        let to_attempt3 = pending_requests.get_requests_to_attempt(&mut setup.tracker);
        assert_eq!(to_attempt3.len(), 1);
        assert_eq!(to_attempt3[0].request.id, req2.id);

        // This attempt submits a response, but it is not yet recorded on the blockchain.
        to_attempt3[0]
            .computation_progress
            .lock()
            .unwrap()
            .last_response_submission = Some(setup.clock.now());
        drop(to_attempt3);
        setup.advance(CHECK_EACH_REQUEST_INTERVAL);
        assert_eq!(
            pending_requests
                .get_requests_to_attempt(&mut setup.tracker)
                .len(),
            0
        );

        // The response doesn't get recorded on the blockchain. It should try again.
        setup.advance(MAX_LATENCY_BEFORE_EXPECTING_TRANSACTION_TO_FINALIZE);
        let to_attempt4 = pending_requests.get_requests_to_attempt(&mut setup.tracker);
        assert_eq!(to_attempt4.len(), 1);
        assert_eq!(to_attempt4[0].request.id, req2.id);

        // This time it gets onto the blockchain, but the block isn't finalized yet, so we should still retry.
        drop(to_attempt4);
        let b = setup
            .block_builder::<CKDRequest>()
            .with_completed(vec![req2.id]);
        pending_requests.notify_new_block(b.build(&mut setup));
        setup.advance(CHECK_EACH_REQUEST_INTERVAL);
        assert_eq!(
            pending_requests
                .get_requests_to_attempt(&mut setup.tracker)
                .len(),
            1
        );

        // Make b3 final, so the response is recorded, removing the request.
        pending_requests.notify_new_block(setup.block_builder::<CKDRequest>().build(&mut setup));
        pending_requests.notify_new_block(setup.block_builder::<CKDRequest>().build(&mut setup));
        setup.advance(CHECK_EACH_REQUEST_INTERVAL);
        assert_eq!(
            pending_requests
                .get_requests_to_attempt(&mut setup.tracker)
                .len(),
            0
        );
    }

    #[test_log::test]
    fn test_pending_signature_requests_leader_retry() {
        // Given
        let (mut setup, mut pending_requests) = TestSetup::builder()
            .with_participant_heights(100)
            .build::<SignatureRequest, ChainSignatureRespondArgs>(
        );

        let b = setup.block_builder();
        let (b, _req1) = b.with_request(&[setup.other_id]);
        let (b, req2) = b.with_request(&[setup.my_id]);
        pending_requests.notify_new_block(b.build(&mut setup));

        // req1 is not attempted because we're not the leader. req2 is attempted.
        let to_attempt1 = pending_requests.get_requests_to_attempt(&mut setup.tracker);
        assert_eq!(to_attempt1.len(), 1);
        assert_eq!(to_attempt1[0].request.id, req2.id);

        // Another attempt should not be issued while the first one is still ongoing.
        setup.advance(Duration::seconds(2));
        assert_eq!(
            pending_requests
                .get_requests_to_attempt(&mut setup.tracker)
                .len(),
            0
        );

        let b = setup.block_builder();
        let (b, req3) = b.with_request(&[setup.my_id]);
        let (b, _req4) = b.with_request(&[setup.participants[2]]);
        pending_requests.notify_new_block(b.build(&mut setup));

        // More signature requests came in while we're attempting the first. req3 should be
        // attempted, because we're the leader as well. req4 is not attempted as we're not leader.
        let to_attempt2 = pending_requests.get_requests_to_attempt(&mut setup.tracker);
        assert_eq!(to_attempt2.len(), 1);
        assert_eq!(to_attempt2[0].request.id, req3.id);

        setup.advance(Duration::seconds(2));
        assert_eq!(
            pending_requests
                .get_requests_to_attempt(&mut setup.tracker)
                .len(),
            0
        );

        // Drop the attempt on req2. It should not immediately retry, because we need to wait
        // for at least a second before retrying anything.
        drop(to_attempt1);
        assert_eq!(
            pending_requests
                .get_requests_to_attempt(&mut setup.tracker)
                .len(),
            0
        );
        setup.advance(CHECK_EACH_REQUEST_INTERVAL);
        let to_attempt3 = pending_requests.get_requests_to_attempt(&mut setup.tracker);
        assert_eq!(to_attempt3.len(), 1);
        assert_eq!(to_attempt3[0].request.id, req2.id);

        // This attempt submits a response, but it is not yet recorded on the blockchain.
        to_attempt3[0]
            .computation_progress
            .lock()
            .unwrap()
            .last_response_submission = Some(setup.clock.now());
        drop(to_attempt3);
        setup.advance(CHECK_EACH_REQUEST_INTERVAL);
        assert_eq!(
            pending_requests
                .get_requests_to_attempt(&mut setup.tracker)
                .len(),
            0
        );

        // The response doesn't get recorded on the blockchain. It should try again.
        setup.advance(MAX_LATENCY_BEFORE_EXPECTING_TRANSACTION_TO_FINALIZE);
        let to_attempt4 = pending_requests.get_requests_to_attempt(&mut setup.tracker);
        assert_eq!(to_attempt4.len(), 1);
        assert_eq!(to_attempt4[0].request.id, req2.id);

        // This time it gets onto the blockchain, but the block isn't finalized yet, so we should still retry.
        drop(to_attempt4);
        let b = setup
            .block_builder::<SignatureRequest>()
            .with_completed(vec![req2.id]);
        pending_requests.notify_new_block(b.build(&mut setup));
        setup.advance(CHECK_EACH_REQUEST_INTERVAL);
        assert_eq!(
            pending_requests
                .get_requests_to_attempt(&mut setup.tracker)
                .len(),
            1
        );

        // Make b3 final, so the response is recorded, removing the request.
        pending_requests
            .notify_new_block(setup.block_builder::<SignatureRequest>().build(&mut setup));
        pending_requests
            .notify_new_block(setup.block_builder::<SignatureRequest>().build(&mut setup));
        setup.advance(CHECK_EACH_REQUEST_INTERVAL);
        assert_eq!(
            pending_requests
                .get_requests_to_attempt(&mut setup.tracker)
                .len(),
            0
        );
    }

    #[test_log::test]
    fn test_pending_ckd_requests_abort_after_maximum_attempts() {
        // Given
        let (mut setup, mut pending_requests) = TestSetup::builder()
            .with_participant_heights(100)
            .build::<CKDRequest, ChainCKDRespondArgs>();

        let b = setup.block_builder();
        let (b, req1) = b.with_request(&[setup.my_id]);
        pending_requests.notify_new_block(b.build(&mut setup));

        // When / Then
        for i in 0..MAX_ATTEMPTS_PER_REQUEST_AS_LEADER {
            let to_attempt = pending_requests.get_requests_to_attempt(&mut setup.tracker);
            assert_eq!(to_attempt.len(), 1);
            assert_eq!(to_attempt[0].request.id, req1.id);
            assert_eq!(
                to_attempt[0].computation_progress.lock().unwrap().attempts,
                i + 1
            );
            drop(to_attempt);
            setup.advance(CHECK_EACH_REQUEST_INTERVAL);
        }
        assert_eq!(
            pending_requests
                .get_requests_to_attempt(&mut setup.tracker)
                .len(),
            0
        );
    }

    #[test_log::test]
    fn test_pending_signature_requests_abort_after_maximum_attempts() {
        // Given
        let (mut setup, mut pending_requests) = TestSetup::builder()
            .with_participant_heights(100)
            .build::<SignatureRequest, ChainSignatureRespondArgs>(
        );

        let b = setup.block_builder();
        let (b, req1) = b.with_request(&[setup.my_id]);
        pending_requests.notify_new_block(b.build(&mut setup));

        // When / Then
        for i in 0..MAX_ATTEMPTS_PER_REQUEST_AS_LEADER {
            let to_attempt = pending_requests.get_requests_to_attempt(&mut setup.tracker);
            assert_eq!(to_attempt.len(), 1);
            assert_eq!(to_attempt[0].request.id, req1.id);
            assert_eq!(
                to_attempt[0].computation_progress.lock().unwrap().attempts,
                i + 1
            );
            drop(to_attempt);
            setup.advance(CHECK_EACH_REQUEST_INTERVAL);
        }
        assert_eq!(
            pending_requests
                .get_requests_to_attempt(&mut setup.tracker)
                .len(),
            0
        );
    }

    #[test_log::test]
    fn test_pending_ckd_requests_discard_old_and_non_canonical_requests() {
        // Uses manual setup (fork-heavy test — deferred from TestSetup refactor).
        let clock = FakeClock::default();
        let participants = into_participant_ids(&generate_participants(4));
        let my_participant_id = participants[1];
        let network_api = Arc::new(TestNetworkAPI::new(&participants));

        let mut tracker = RecentBlocksTracker::new(REQUEST_EXPIRATION_BLOCKS);
        let mut pending_requests = PendingRequests::<CKDRequest, ChainCKDRespondArgs>::new(
            clock.clock(),
            participants.clone(),
            my_participant_id,
            network_api.clone(),
        );

        for participant in &participants {
            network_api.set_height(*participant, 350);
        }

        let t = TestBlockMaker::new();

        let req1 = CKDRequest::make(&participants, &[my_participant_id]);
        let req2 = CKDRequest::make(&participants, &[my_participant_id]);
        let b1 = t.block(100);
        let b2 = b1.child(200);
        tracker.add_block(&b1.to_block_view());
        pending_requests.notify_new_block(Requests {
            block: b1.to_block_ref(),
            requests: vec![req1.clone()],
            completed_requests: vec![],
        });
        tracker.add_block(&b2.to_block_view());
        pending_requests.notify_new_block(Requests {
            block: b2.to_block_ref(),
            requests: vec![req2.clone()],
            completed_requests: vec![],
        });

        // The first request expired, so only the second one is returned.
        let to_attempt1 = pending_requests.get_requests_to_attempt(&mut tracker);
        assert_eq!(to_attempt1.len(), 1);
        assert_eq!(to_attempt1[0].request.id, req2.id);

        drop(to_attempt1);
        clock.advance(CHECK_EACH_REQUEST_INTERVAL);

        // Set participants to a newer height, expiring the second request as well; it should not retry.
        for participant in &participants {
            network_api.set_height(*participant, 500);
        }
        assert_eq!(
            pending_requests.get_requests_to_attempt(&mut tracker).len(),
            0
        );

        clock.advance(CHECK_EACH_REQUEST_INTERVAL);
        let req3 = CKDRequest::make(&participants, &[my_participant_id]);
        let b3 = b2.child(350);
        tracker.add_block(&b3.to_block_view());
        pending_requests.notify_new_block(Requests {
            block: b3.to_block_ref(),
            requests: vec![req3.clone()],
            completed_requests: vec![],
        });

        // The third request is now recent enough.
        let to_attempt2 = pending_requests.get_requests_to_attempt(&mut tracker);
        assert_eq!(to_attempt2.len(), 1);
        assert_eq!(to_attempt2[0].request.id, req3.id);

        // Add a new request in a different fork that becomes the canonical chain.
        // Req3 is now on a non-canonical fork so should not be attempted.
        drop(to_attempt2);
        clock.advance(CHECK_EACH_REQUEST_INTERVAL);
        let b4 = b2.child(360);
        let req4 = CKDRequest::make(&participants, &[my_participant_id]);
        tracker.add_block(&b4.to_block_view());
        pending_requests.notify_new_block(Requests {
            block: b4.to_block_ref(),
            requests: vec![req4.clone()],
            completed_requests: vec![],
        });

        let to_attempt3 = pending_requests.get_requests_to_attempt(&mut tracker);
        assert_eq!(to_attempt3.len(), 1);
        assert_eq!(to_attempt3[0].request.id, req4.id);

        // Bring req3's block back to canonical; now we should attempt that instead.
        drop(to_attempt3);
        clock.advance(CHECK_EACH_REQUEST_INTERVAL);
        let b5 = b3.child(370);
        let req5 = CKDRequest::make(&participants, &[my_participant_id]);
        tracker.add_block(&b5.to_block_view());
        pending_requests.notify_new_block(Requests {
            block: b5.to_block_ref(),
            requests: vec![req5.clone()],
            completed_requests: vec![],
        });

        let to_attempt4 = pending_requests.get_requests_to_attempt(&mut tracker);
        assert_eq!(to_attempt4.len(), 2);
        assert!(set_equals(
            &to_attempt4.iter().map(|a| a.request.id).collect::<Vec<_>>(),
            &[req3.id, req5.id]
        ));
    }

    #[test_log::test]
    fn test_pending_signature_requests_discard_old_and_non_canonical_requests() {
        // Uses manual setup (fork-heavy test — deferred from TestSetup refactor).
        let clock = FakeClock::default();
        let participants = into_participant_ids(&generate_participants(4));
        let my_participant_id = participants[1];
        let network_api = Arc::new(TestNetworkAPI::new(&participants));

        let mut tracker = RecentBlocksTracker::new(REQUEST_EXPIRATION_BLOCKS);
        let mut pending_requests =
            PendingRequests::<SignatureRequest, ChainSignatureRespondArgs>::new(
                clock.clock(),
                participants.clone(),
                my_participant_id,
                network_api.clone(),
            );

        for participant in &participants {
            network_api.set_height(*participant, 350);
        }

        let t = TestBlockMaker::new();

        let req1 = SignatureRequest::make(&participants, &[my_participant_id]);
        let req2 = SignatureRequest::make(&participants, &[my_participant_id]);
        let b1 = t.block(100);
        let b2 = b1.child(200);
        tracker.add_block(&b1.to_block_view());
        pending_requests.notify_new_block(Requests {
            block: b1.to_block_ref(),
            requests: vec![req1.clone()],
            completed_requests: vec![],
        });
        tracker.add_block(&b2.to_block_view());
        pending_requests.notify_new_block(Requests {
            block: b2.to_block_ref(),
            requests: vec![req2.clone()],
            completed_requests: vec![],
        });

        // The first request expired, so only the second one is returned.
        let to_attempt1 = pending_requests.get_requests_to_attempt(&mut tracker);
        assert_eq!(to_attempt1.len(), 1);
        assert_eq!(to_attempt1[0].request.id, req2.id);

        drop(to_attempt1);
        clock.advance(CHECK_EACH_REQUEST_INTERVAL);

        // Set participants to a newer height, expiring the second request as well; it should not retry.
        for participant in &participants {
            network_api.set_height(*participant, 500);
        }
        assert_eq!(
            pending_requests.get_requests_to_attempt(&mut tracker).len(),
            0
        );

        clock.advance(CHECK_EACH_REQUEST_INTERVAL);
        let req3 = SignatureRequest::make(&participants, &[my_participant_id]);
        let b3 = b2.child(350);
        tracker.add_block(&b3.to_block_view());
        pending_requests.notify_new_block(Requests {
            block: b3.to_block_ref(),
            requests: vec![req3.clone()],
            completed_requests: vec![],
        });

        // The third request is now recent enough.
        let to_attempt2 = pending_requests.get_requests_to_attempt(&mut tracker);
        assert_eq!(to_attempt2.len(), 1);
        assert_eq!(to_attempt2[0].request.id, req3.id);

        // Add a new request in a different fork that becomes the canonical chain.
        // Req3 is now on a non-canonical fork so should not be attempted.
        drop(to_attempt2);
        clock.advance(CHECK_EACH_REQUEST_INTERVAL);
        let b4 = b2.child(360);
        let req4 = SignatureRequest::make(&participants, &[my_participant_id]);
        tracker.add_block(&b4.to_block_view());
        pending_requests.notify_new_block(Requests {
            block: b4.to_block_ref(),
            requests: vec![req4.clone()],
            completed_requests: vec![],
        });

        let to_attempt3 = pending_requests.get_requests_to_attempt(&mut tracker);
        assert_eq!(to_attempt3.len(), 1);
        assert_eq!(to_attempt3[0].request.id, req4.id);

        // Bring req3's block back to canonical; now we should attempt that instead.
        drop(to_attempt3);
        clock.advance(CHECK_EACH_REQUEST_INTERVAL);
        let b5 = b3.child(370);
        let req5 = SignatureRequest::make(&participants, &[my_participant_id]);
        tracker.add_block(&b5.to_block_view());
        pending_requests.notify_new_block(Requests {
            block: b5.to_block_ref(),
            requests: vec![req5.clone()],
            completed_requests: vec![],
        });

        let to_attempt4 = pending_requests.get_requests_to_attempt(&mut tracker);
        assert_eq!(to_attempt4.len(), 2);
        assert!(set_equals(
            &to_attempt4.iter().map(|a| a.request.id).collect::<Vec<_>>(),
            &[req3.id, req5.id]
        ));
    }

    #[test_log::test]
    fn test_pending_ckd_requests_fallback_leader() {
        // Given
        let (mut setup, mut pending_requests) = TestSetup::builder()
            .with_participant_heights(100)
            .build::<CKDRequest, ChainCKDRespondArgs>();

        // Indexer 0 is offline; indexer 2 is stale. We let indexer 0 have a higher height than
        // normal. This is to test a pathological case, in case some node reports an incorrectly high
        // height and we want to allow shutting down that node to be a mitigation.
        setup.set_participant_offline(0);
        setup.set_participant_height(0, 120); // ignored because offline
        setup.set_participant_height(2, 80); // stale

        let p0 = setup.participants[0];
        let p2 = setup.participants[2];
        let p3 = setup.participants[3];

        let b = setup.block_builder();
        let (b, req1) = b.with_request(&[p0, setup.my_id]);
        let (b, req2) = b.with_request(&[p2, p0, setup.my_id]);
        let (b, _req3) = b.with_request(&[p3, setup.my_id]);
        pending_requests.notify_new_block(b.build(&mut setup));

        // Since 0 and 2 are unavailable, and we are the first available leader for req1 and req2,
        // we should attempt these.
        let to_attempt1 = pending_requests.get_requests_to_attempt(&mut setup.tracker);
        assert_eq!(to_attempt1.len(), 2);
        assert!(set_equals(
            &to_attempt1.iter().map(|a| a.request.id).collect::<Vec<_>>(),
            &[req1.id, req2.id]
        ));

        drop(to_attempt1);
        setup.advance(CHECK_EACH_REQUEST_INTERVAL);

        // Bring up node 0. This causes node 1 to itself realize it is stale, so it should refuse to
        // attempt any ckds, even if it were the preferred leader.
        setup.set_participant_online(0);
        let b = setup.block_builder::<CKDRequest>();
        let (b, _req4) = b.with_request(&[setup.my_id]);
        let req4_id = _req4.id;
        pending_requests.notify_new_block(b.build(&mut setup));
        assert_eq!(
            pending_requests
                .get_requests_to_attempt(&mut setup.tracker)
                .len(),
            0
        );

        // Bring down node 0 again. Now, node 1 should retry req1, req2 again, as well as trying req4.
        setup.set_participant_offline(0);
        setup.advance(CHECK_EACH_REQUEST_INTERVAL);
        let to_attempt2 = pending_requests.get_requests_to_attempt(&mut setup.tracker);
        assert_eq!(to_attempt2.len(), 3);
        assert!(set_equals(
            &to_attempt2.iter().map(|a| a.request.id).collect::<Vec<_>>(),
            &[req1.id, req2.id, req4_id]
        ));

        // Node 0 actually manages to complete req1 and req4 somehow. Node 1 should not retry
        // these anymore.
        drop(to_attempt2);
        let b = setup
            .block_builder::<CKDRequest>()
            .with_completed(vec![req1.id, req4_id]);
        pending_requests.notify_new_block(b.build(&mut setup));
        pending_requests.notify_new_block(setup.block_builder::<CKDRequest>().build(&mut setup));
        pending_requests.notify_new_block(setup.block_builder::<CKDRequest>().build(&mut setup));
        setup.advance(CHECK_EACH_REQUEST_INTERVAL);

        let to_attempt3 = pending_requests.get_requests_to_attempt(&mut setup.tracker);
        assert_eq!(to_attempt3.len(), 1);
        assert_eq!(to_attempt3[0].request.id, req2.id);
    }

    #[test_log::test]
    fn test_pending_signature_requests_fallback_leader() {
        // Given
        let (mut setup, mut pending_requests) = TestSetup::builder()
            .with_participant_heights(100)
            .build::<SignatureRequest, ChainSignatureRespondArgs>(
        );

        // Indexer 0 is offline; indexer 2 is stale. We let indexer 0 have a higher height than
        // normal. This is to test a pathological case, in case some node reports an incorrectly high
        // height and we want to allow shutting down that node to be a mitigation.
        setup.set_participant_offline(0);
        setup.set_participant_height(0, 120); // ignored because offline
        setup.set_participant_height(2, 80); // stale

        let p0 = setup.participants[0];
        let p2 = setup.participants[2];
        let p3 = setup.participants[3];

        let b = setup.block_builder();
        let (b, req1) = b.with_request(&[p0, setup.my_id]);
        let (b, req2) = b.with_request(&[p2, p0, setup.my_id]);
        let (b, _req3) = b.with_request(&[p3, setup.my_id]);
        pending_requests.notify_new_block(b.build(&mut setup));

        // Since 0 and 2 are unavailable, and we are the first available leader for req1 and req2,
        // we should attempt these.
        let to_attempt1 = pending_requests.get_requests_to_attempt(&mut setup.tracker);
        assert_eq!(to_attempt1.len(), 2);
        assert!(set_equals(
            &to_attempt1.iter().map(|a| a.request.id).collect::<Vec<_>>(),
            &[req1.id, req2.id]
        ));

        drop(to_attempt1);
        setup.advance(CHECK_EACH_REQUEST_INTERVAL);

        // Bring up node 0. This causes node 1 to itself realize it is stale, so it should refuse to
        // attempt any signatures, even if it were the preferred leader.
        setup.set_participant_online(0);
        let b = setup.block_builder::<SignatureRequest>();
        let (b, _req4) = b.with_request(&[setup.my_id]);
        let req4_id = _req4.id;
        pending_requests.notify_new_block(b.build(&mut setup));
        assert_eq!(
            pending_requests
                .get_requests_to_attempt(&mut setup.tracker)
                .len(),
            0
        );

        // Bring down node 0 again. Now, node 1 should retry req1, req2 again, as well as trying req4.
        setup.set_participant_offline(0);
        setup.advance(CHECK_EACH_REQUEST_INTERVAL);
        let to_attempt2 = pending_requests.get_requests_to_attempt(&mut setup.tracker);
        assert_eq!(to_attempt2.len(), 3);
        assert!(set_equals(
            &to_attempt2.iter().map(|a| a.request.id).collect::<Vec<_>>(),
            &[req1.id, req2.id, req4_id]
        ));

        // Node 0 actually manages to complete req1 and req4 somehow. Node 1 should not retry
        // these anymore.
        drop(to_attempt2);
        let b = setup
            .block_builder::<SignatureRequest>()
            .with_completed(vec![req1.id, req4_id]);
        pending_requests.notify_new_block(b.build(&mut setup));
        pending_requests
            .notify_new_block(setup.block_builder::<SignatureRequest>().build(&mut setup));
        pending_requests
            .notify_new_block(setup.block_builder::<SignatureRequest>().build(&mut setup));
        setup.advance(CHECK_EACH_REQUEST_INTERVAL);

        let to_attempt3 = pending_requests.get_requests_to_attempt(&mut setup.tracker);
        assert_eq!(to_attempt3.len(), 1);
        assert_eq!(to_attempt3[0].request.id, req2.id);
    }

    #[test_log::test]
    fn test_ckd_request_latency_debug() {
        // Given
        let (mut setup, mut pending_requests) = TestSetup::builder()
            .with_participant_heights(100)
            .build::<CKDRequest, ChainCKDRespondArgs>();

        setup.advance(Duration::seconds(1));
        let b = setup.block_builder();
        let (b, req1) = b.with_request(&[setup.other_id]);
        pending_requests.notify_new_block(b.build(&mut setup));

        setup.advance(Duration::microseconds(2432123));
        let b = setup
            .block_builder::<CKDRequest>()
            .with_completed(vec![req1.id]);
        pending_requests.notify_new_block(b.build(&mut setup));

        setup.advance(Duration::seconds(1));
        pending_requests.notify_new_block(setup.block_builder::<CKDRequest>().build(&mut setup));

        setup.advance(Duration::seconds(1));
        pending_requests.notify_new_block(setup.block_builder::<CKDRequest>().build(&mut setup));

        setup.advance(Duration::seconds(1));
        // Completion detection now runs inside the tick loop, not notify_new_block.
        pending_requests.get_requests_to_attempt(&mut setup.tracker);

        // Then
        let debug = format!("{:?}", pending_requests);
        assert!(
            debug.contains("blk        100 ->        101 (+1, 2s432ms)"),
            "{}",
            debug
        );
    }

    #[test_log::test]
    fn test_signature_request_latency_debug() {
        // Given
        let (mut setup, mut pending_requests) = TestSetup::builder()
            .with_participant_heights(100)
            .build::<SignatureRequest, ChainSignatureRespondArgs>(
        );

        setup.advance(Duration::seconds(1));
        let b = setup.block_builder();
        let (b, req1) = b.with_request(&[setup.other_id]);
        pending_requests.notify_new_block(b.build(&mut setup));

        setup.advance(Duration::microseconds(2432123));
        let b = setup
            .block_builder::<SignatureRequest>()
            .with_completed(vec![req1.id]);
        pending_requests.notify_new_block(b.build(&mut setup));

        setup.advance(Duration::seconds(1));
        pending_requests
            .notify_new_block(setup.block_builder::<SignatureRequest>().build(&mut setup));

        setup.advance(Duration::seconds(1));
        pending_requests
            .notify_new_block(setup.block_builder::<SignatureRequest>().build(&mut setup));

        setup.advance(Duration::seconds(1));
        // Completion detection now runs inside the tick loop, not notify_new_block.
        pending_requests.get_requests_to_attempt(&mut setup.tracker);

        // Then
        let debug = format!("{:?}", pending_requests);
        assert!(
            debug.contains("blk        100 ->        101 (+1, 2s432ms)"),
            "{}",
            debug
        );
    }
}
