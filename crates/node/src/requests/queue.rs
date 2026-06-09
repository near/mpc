use super::debug::{CompletedRequest, CompletedRequests};
use crate::indexer::types::ChainRespondArgs;
use crate::primitives::ParticipantId;
use crate::requests::metrics;
use crate::types::{self, Request, RequestId, RequestsUpdate};
use chain_gateway::event_subscriber::recent_blocks_tracker::BlockStatusHandle;
use chain_gateway::types::BlockHeight;
use k256::sha2::Sha256;
use near_indexer_primitives::CryptoHash;
use near_indexer_primitives::types::NumBlocks;
use near_time::Duration;
use sha3::Digest;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, Weak};
use time::ext::InstantExt as _;

/// Thin API that the queue needs from the network.
pub trait NetworkAPIForRequests: Send + Sync + 'static {
    /// Returns the participants that are currently connected to us.
    fn alive_participants(&self) -> HashSet<ParticipantId>;
    /// Returns the height of each indexer, including us. This must return all
    /// participants, even those who are never connected.
    fn indexer_heights(&self) -> HashMap<ParticipantId, u64>;
}

/// The minimum time that must elapse before we'll consider each request for another attempt.
pub const CHECK_EACH_REQUEST_INTERVAL: Duration = Duration::seconds(1);
/// A participant is considered stale if its indexer's highest height is this many blocks behind
/// the highest height of all participants.
const STALE_PARTICIPANT_THRESHOLD: NumBlocks = 10;
/// The number of blocks after which a request is assumed to have timed out.
/// This is equal to the yield-resume timeout on the blockchain.
pub const REQUEST_EXPIRATION_BLOCKS: NumBlocks = 200;
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

/// All [`IndexedRespondTx`]s observed for one queued request, across the chain's forks.
#[derive(derive_more::Constructor)]
struct IndexedRespondTxs(Vec<IndexedRespondTx>);

/// An on-chain `respond` transaction observed in an indexed block.
#[derive(Clone)]
struct IndexedRespondTx {
    /// Live view of the finality status of the block this transaction was observed in.
    block_status: BlockStatusHandle,
    /// Wall-clock time at which our node observed the block containing the response.
    received_at: near_time::Instant,
    // TODO(#3318): We could share the `block_height` through the same guard as
    // `block_status`, however, that's a larger refactor and this change will only truly make sense
    // once we start improving the metrics with #3318, so we defer it to later and accept to hold a
    // `BlockHeight` for each response.
    block_height: BlockHeight,
}

impl Default for IndexedRespondTxs {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl IndexedRespondTxs {
    fn status(&self) -> AggregateResponseStatus {
        for respond_tx in &self.0 {
            match respond_tx.block_status.is_final() {
                // the block this response was included in was dropped by the tracker
                None => continue,
                Some(true) => {
                    return AggregateResponseStatus::Resolved {
                        received_at: respond_tx.received_at,
                        block_height: respond_tx.block_height,
                    };
                }
                Some(false) => {}
            }
            if respond_tx.block_status.is_canonical() == Some(true) {
                // We return early if the response is on the canonical chain.
                // This is appropriate, because it is not possible to have, simultaneously:
                // - a response that is final
                // - and a response that is not final, but canonical
                // for the same request.
                //
                // Reason for this is that we track `return_signature_and_clean_state_on_success`,
                // which is a private method on the MPC contract, which gets called
                // _exactly once_ per signature.
                //
                // BFT rules thus guarantee that there won't be a different final transaction response,
                // which makes this early return ok.
                return AggregateResponseStatus::MayBeResolved;
            }
        }
        AggregateResponseStatus::None
    }

    fn add(&mut self, indexed_respond_tx: IndexedRespondTx) {
        self.0.push(indexed_respond_tx);
    }
}

/// Aggregates block status of all blocks in IndexedRespondTxs
enum AggregateResponseStatus {
    /// Either there exists no response for this transaction, or the tracker has discarded the
    /// response, or the response sits on a non-canonical chain
    None,
    /// A response sits on the canonical chain. Likely to be resolved.
    MayBeResolved,
    /// Indicates that one of the responses is included in a block that was finalized on chain.
    Resolved {
        received_at: near_time::Instant,
        block_height: BlockHeight,
    },
}

/// The state of a single request in the queue.
pub(super) struct QueuedRequest<RequestType: Request, ChainRespondArgsType: ChainRespondArgs> {
    pub request: RequestType,

    /// Finality status of the block the request was included in.
    status: BlockStatusHandle,
    /// Respond transactions for this request observed in indexed blocks.
    indexed_respond_txs: IndexedRespondTxs,

    pub block_height: BlockHeight,

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

enum ComputationProgressStatus {
    NewAttempt,
    Pending,
    MaxAttemptsExceeded,
}

impl<ChainRespondArgsType: ChainRespondArgs> ComputationProgress<ChainRespondArgsType> {
    /// If [`Self::attempts`] is less than [`MAX_ATTEMPTS_PER_REQUEST_AS_LEADER`], then increments
    /// [`Self::attempts`] by one and returns [`ComputationProgressStatus::NewAttempt`].
    /// Otherwise returns [`ComputationProgressStatus::MaxAttemptsExceeded`] or
    /// [`ComputationProgressStatus::Pending`].
    fn update_computation_progress(
        &mut self,
        now: near_time::Instant,
    ) -> ComputationProgressStatus {
        if self.attempts >= MAX_ATTEMPTS_PER_REQUEST_AS_LEADER {
            ComputationProgressStatus::MaxAttemptsExceeded
        } else if self
            .last_response_submission
            .is_some_and(|t| now < t + MAX_LATENCY_BEFORE_EXPECTING_TRANSACTION_TO_FINALIZE)
        {
            ComputationProgressStatus::Pending
        } else {
            self.attempts += 1;
            ComputationProgressStatus::NewAttempt
        }
    }
}

impl<RequestType: Request, ChainRespondArgsType: ChainRespondArgs>
    QueuedRequest<RequestType, ChainRespondArgsType>
{
    pub fn new(
        clock: &near_time::Clock,
        request: RequestType,
        block_height: BlockHeight,
        status: BlockStatusHandle,
        all_participants: &[ParticipantId],
        time_indexed: near_time::Instant,
    ) -> Self {
        let leader_selection_order =
            Self::leader_selection_order(all_participants, request.get_id());
        tracing::debug!(target: "request", "Leader selection order for request {:?} from block {}: {:?}", request.get_id(), block_height, leader_selection_order);

        Self {
            request,
            block_height,
            status,
            indexed_respond_txs: IndexedRespondTxs::default(),
            leader_selection_order,
            computation_progress: Arc::new(Mutex::new(ComputationProgress::default())),
            next_check_due: clock.now(),
            active_attempt: Weak::new(),
            time_indexed,
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

    /// Returns true if this request is due for another check (i.e. [`Self::next_check_due`] is
    /// at or before `now`), and in that case bumps [`Self::next_check_due`] by
    /// [`CHECK_EACH_REQUEST_INTERVAL`].
    fn update_next_check_due(&mut self, now: near_time::Instant) -> bool {
        if self.next_check_due <= now {
            self.next_check_due = now + CHECK_EACH_REQUEST_INTERVAL;
            true
        } else {
            false
        }
    }

    fn has_active_attempt(&self) -> bool {
        self.active_attempt.strong_count() > 0
    }

    fn is_older_than(&self, cutoff_block: BlockHeight) -> bool {
        cutoff_block > self.block_height
    }

    fn add_indexed_respond_tx(&mut self, indexed_respond_tx: IndexedRespondTx) {
        self.indexed_respond_txs.add(indexed_respond_tx)
    }
}

impl<RequestType: Request + Clone, ChainRespondArgsType: ChainRespondArgs>
    QueuedRequest<RequestType, ChainRespondArgsType>
{
    fn process(
        &mut self,
        my_participant_id: ParticipantId,
        eligible_leaders: &HashSet<ParticipantId>,
        cutoff_block: BlockHeight,
        now: near_time::Instant,
    ) -> RequestStatus<RequestType, ChainRespondArgsType> {
        if !self.update_next_check_due(now) {
            return RequestStatus::Wait("check not due");
        }
        if self.has_active_attempt() {
            return RequestStatus::Wait("active attempt ongoing");
        }
        // Classify any observed respond txs before doing other timeout/leader work below.
        match self.indexed_respond_txs.status() {
            AggregateResponseStatus::None => {
                // Note that a response on the non-canonical chain is treated the same as no
                // response at all. We continue with the loop below and check whether or not the
                // request is still relevant.
            }
            AggregateResponseStatus::MayBeResolved => {
                return RequestStatus::Wait("response submitted, waiting to finalize");
            }
            AggregateResponseStatus::Resolved {
                received_at,
                block_height,
            } => {
                return RequestStatus::Resolve {
                    received_at,
                    block_height,
                };
            }
        }
        // check it against the network height
        if self.is_older_than(cutoff_block) {
            // This request is definitely not useful anymore, so discard it.
            return RequestStatus::Drop(DropReason::RequestTimedOut);
        }
        let Some(is_canonical) = self.status.is_canonical() else {
            return RequestStatus::Drop(DropReason::BlockNotFound);
        };
        if !is_canonical {
            return RequestStatus::Wait("request is not on canonical chain");
        }
        let Some(leader) = self.current_leader(eligible_leaders) else {
            return RequestStatus::Wait("no eligible leaders for this request");
        };
        let mut progress = self.computation_progress.lock().unwrap();
        progress.selected_leader = Some(leader);
        if leader == my_participant_id {
            match progress.update_computation_progress(now) {
                ComputationProgressStatus::MaxAttemptsExceeded => {
                    RequestStatus::Drop(DropReason::MaxAttemptsExceeded)
                }
                ComputationProgressStatus::Pending => RequestStatus::Wait("pending computation"),
                ComputationProgressStatus::NewAttempt => {
                    let attempt = Arc::new(GenerationAttempt {
                        request: self.request.clone(),
                        computation_progress: self.computation_progress.clone(),
                    });
                    self.active_attempt = Arc::downgrade(&attempt);
                    RequestStatus::Attempt(attempt)
                }
            }
        } else {
            RequestStatus::Wait("we are not leader")
        }
    }
}

enum RequestStatus<RequestType: Request, ChainRespondArgsType: ChainRespondArgs> {
    Drop(DropReason),
    Wait(&'static str),
    Attempt(Arc<GenerationAttempt<RequestType, ChainRespondArgsType>>),
    Resolve {
        received_at: near_time::Instant,
        block_height: BlockHeight,
    },
}

#[derive(derive_more::Display)]
enum DropReason {
    #[display("max attempts exceeded")]
    MaxAttemptsExceeded,
    #[display("tracker does not have block")]
    BlockNotFound,
    #[display("request timed out for at least one participant")]
    RequestTimedOut,
}

impl DropReason {
    /// Label used for the `MPC_CLUSTER_FAILED_SIGNATURES_COUNT` metric.
    fn metric_label(&self) -> &'static str {
        match self {
            DropReason::MaxAttemptsExceeded => "max_tries_exceeded",
            DropReason::BlockNotFound => "block_not_found",
            DropReason::RequestTimedOut => "timeout",
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

    /// This must be called for every block that comes from the indexer.
    /// These are the requests successfully submitted in the block, and the
    /// completed_requests are the requests whose responses are included in the block.
    pub(crate) fn notify_new_block(&mut self, update: RequestsUpdate<RequestType>) {
        let (
            mpc_pending_queue_responses_indexed,
            mpc_pending_queue_matching_responses_indexed,
            mpc_pending_requests_queue_requests_indexed,
        ) = match RequestType::get_type() {
            types::RequestType::CKD => (
                &metrics::MPC_PENDING_CKDS_QUEUE_RESPONSES_INDEXED,
                &metrics::MPC_PENDING_CKDS_QUEUE_MATCHING_RESPONSES_INDEXED,
                &metrics::MPC_PENDING_CKDS_QUEUE_REQUESTS_INDEXED,
            ),
            types::RequestType::Signature => (
                &metrics::MPC_PENDING_SIGNATURES_QUEUE_RESPONSES_INDEXED,
                &metrics::MPC_PENDING_SIGNATURES_QUEUE_MATCHING_RESPONSES_INDEXED,
                &metrics::MPC_PENDING_SIGNATURES_QUEUE_REQUESTS_INDEXED,
            ),
            types::RequestType::VerifyForeignTx => (
                &metrics::MPC_PENDING_VERIFY_FOREIGN_TXS_QUEUE_RESPONSES_INDEXED_TOTAL,
                &metrics::MPC_PENDING_VERIFY_FOREIGN_TXS_QUEUE_MATCHING_RESPONSES_INDEXED_TOTAL,
                &metrics::MPC_PENDING_VERIFY_FOREIGN_TXS_QUEUE_REQUESTS_INDEXED_TOTAL,
            ),
        };
        let RequestsUpdate::<RequestType> {
            requests,
            completed_requests,
            block_status,
            block_height,
        } = update;

        mpc_pending_requests_queue_requests_indexed.inc_by(requests.len() as u64);
        let now = self.clock.now();
        for request in requests {
            self.requests
                .entry(request.get_id())
                .or_insert(QueuedRequest::new(
                    &self.clock,
                    request.clone(),
                    block_height,
                    block_status.clone(),
                    &self.all_participants,
                    now,
                ));
        }
        mpc_pending_queue_responses_indexed.inc_by(completed_requests.len() as u64);
        let indexed_respond_tx = IndexedRespondTx {
            block_status: block_status.clone(),
            received_at: now,
            block_height,
        };
        for request_id in completed_requests {
            self.requests
                .entry(request_id)
                .and_modify(|queued_request| {
                    queued_request.add_indexed_respond_tx(indexed_respond_tx.clone());
                    mpc_pending_queue_matching_responses_indexed.inc();
                });
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
    ) -> Vec<Arc<GenerationAttempt<RequestType, ChainRespondArgsType>>> {
        let (
            mpc_pending_queue_finalized_responses,
            request_response_latency_blocks,
            request_response_latency_seconds,
        ) = match RequestType::get_type() {
            types::RequestType::CKD => (
                &metrics::MPC_PENDING_CKDS_QUEUE_FINALIZED_RESPONSES_INDEXED,
                &metrics::CKD_REQUEST_RESPONSE_LATENCY_BLOCKS,
                &metrics::CKD_REQUEST_RESPONSE_LATENCY_SECONDS,
            ),
            types::RequestType::Signature => (
                &metrics::MPC_PENDING_SIGNATURES_QUEUE_FINALIZED_RESPONSES_INDEXED,
                &metrics::SIGNATURE_REQUEST_RESPONSE_LATENCY_BLOCKS,
                &metrics::SIGNATURE_REQUEST_RESPONSE_LATENCY_SECONDS,
            ),
            types::RequestType::VerifyForeignTx => (
                &metrics::MPC_PENDING_VERIFY_FOREIGN_TXS_QUEUE_FINALIZED_RESPONSES_INDEXED_TOTAL,
                &metrics::VERIFY_FOREIGN_TXS_REQUEST_RESPONSE_LATENCY_BLOCKS,
                &metrics::VERIFY_FOREIGN_TXS_REQUEST_RESPONSE_LATENCY_SECONDS,
            ),
        };
        let now = self.clock.now();

        let (eligible_leaders, maximum_height) = self.eligible_leaders_and_maximum_height();
        tracing::debug!(target: "request", "Eligible leaders: {:?}", eligible_leaders);

        let mut result = Vec::new();

        // Tag each removal so the post-loop knows whether to record a `completion_delay`
        // for the corresponding `CompletedRequest`. Previously the Resolve arm both
        // added a delay row inside the loop AND let the post-loop add a `None`-delay
        // row, double-counting every resolved request in `recently_completed_requests`.
        enum Removal {
            Dropped,
            Resolved {
                latency_blocks: NumBlocks,
                latency_duration: near_time::Duration,
            },
        }
        let mut requests_to_remove: Vec<(RequestId, Removal)> = Vec::new();

        // any request strictly older than `cutoff_block` will be considered expired
        let cutoff_block: BlockHeight =
            (maximum_height.saturating_sub(REQUEST_EXPIRATION_BLOCKS) + 1).into();

        for (id, request) in &mut self.requests {
            let _span = tracing::debug_span!(
                target: "request",
                "process_request",
                request_type = %RequestType::get_type(),
                request_id = %request.request.get_id(),
                block_height = %request.block_height,
            )
            .entered();
            match request.process(self.my_participant_id, &eligible_leaders, cutoff_block, now) {
                RequestStatus::Drop(reason) => {
                    tracing::debug!(target: "request", reason = %reason, "removing request");
                    if matches!(RequestType::get_type(), types::RequestType::Signature) {
                        metrics::MPC_CLUSTER_FAILED_SIGNATURES_COUNT
                            .with_label_values(&[reason.metric_label()])
                            .inc();
                    }
                    requests_to_remove.push((*id, Removal::Dropped));
                }
                RequestStatus::Wait(reason) => {
                    tracing::debug!(target: "request", reason, "skipping request");
                }
                RequestStatus::Attempt(attempt) => {
                    result.push(attempt);
                }
                RequestStatus::Resolve {
                    received_at,
                    block_height,
                } => {
                    mpc_pending_queue_finalized_responses.inc();
                    // Response block ≥ request block by construction; saturate just in case.
                    let latency_blocks = block_height.blocks_since(request.block_height);
                    let latency_duration = received_at.signed_duration_since(request.time_indexed);

                    request_response_latency_blocks.observe(latency_blocks as f64);
                    request_response_latency_seconds.observe(latency_duration.as_seconds_f64());

                    requests_to_remove.push((
                        *id,
                        Removal::Resolved {
                            latency_blocks,
                            latency_duration,
                        },
                    ));
                }
            }
        }
        for (id, removal) in requests_to_remove {
            if let Some(request) = self.requests.remove(&id) {
                let completion_delay = match removal {
                    Removal::Dropped => None,
                    Removal::Resolved {
                        latency_blocks,
                        latency_duration,
                    } => Some((latency_blocks, latency_duration)),
                };
                self.recently_completed_requests
                    .add_completed_request(CompletedRequest {
                        indexed_block_height: request.block_height.into(),
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
    use super::{NetworkAPIForRequests, PendingRequests, QueuedRequest};
    use crate::indexer::types::ChainSignatureRespondArgs;
    use crate::primitives::ParticipantId;
    use crate::requests::queue::{
        CHECK_EACH_REQUEST_INTERVAL, MAX_ATTEMPTS_PER_REQUEST_AS_LEADER,
        MAX_LATENCY_BEFORE_EXPECTING_TRANSACTION_TO_FINALIZE, REQUEST_EXPIRATION_BLOCKS,
    };
    use crate::tests::into_participant_ids;
    use crate::types::{RequestsUpdate, SignatureRequest};
    use chain_gateway::event_subscriber::recent_blocks_tracker::RecentBlocksTracker;
    use chain_gateway::event_subscriber::recent_blocks_tracker::test_utils::{
        TestBlock, TestBlockMaker,
    };
    use mpc_primitives::domain::DomainId;
    use near_indexer_primitives::CryptoHash;
    use near_mpc_contract_interface::types::{Payload, Tweak};
    use near_time::{Duration, FakeClock};
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};
    use threshold_signatures::test_utils::generate_participants;

    /// Generates a signature request for testing, brute-forcing the signature ID until the leader
    /// selection order starts with the given.
    fn make_request(participants: &[ParticipantId], desired_leader_order: &[usize]) -> TestRequest {
        let desired_leader_order = desired_leader_order
            .iter()
            .map(|i| participants[*i])
            .collect::<Vec<_>>();
        loop {
            let request = SignatureRequest {
                id: CryptoHash(rand::random()),
                // All other fields are irrelevant for the test.
                receipt_id: CryptoHash([0; 32]),
                entropy: [0; 32],
                payload: Payload::from_legacy_ecdsa([0; 32]),
                timestamp_nanosec: 0,
                tweak: Tweak::new([0; 32]),
                domain: DomainId::legacy_ecdsa_id(),
            };
            let leader_selection_order =
                QueuedRequest::<SignatureRequest, TestRequestRespondArgs>::leader_selection_order(
                    participants,
                    request.id,
                );
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

    type TestRequest = SignatureRequest;
    type TestRequestRespondArgs = ChainSignatureRespondArgs;

    struct TestSetup {
        clock: FakeClock,
        participant_ids: Vec<ParticipantId>,
        network_api: Arc<TestNetworkAPI>,
        head: Arc<TestBlock>,
        fork: Option<Arc<TestBlock>>,
        requests_to_submit: Vec<TestRequest>,
        responses_to_submit: Vec<CryptoHash>,
        rng: rand::rngs::StdRng,
        /// Test-side counterpart to the shared tracker that mpc_client owns in production.
        /// Each `update*` adds a block to it; the resulting `BlockStatusHandle` ends up
        /// inside the returned `RequestsUpdate`.
        tracker: RecentBlocksTracker,
    }

    impl TestSetup {
        const MY_INDEX: usize = 1;
        fn new() -> (PendingRequests<TestRequest, TestRequestRespondArgs>, Self) {
            let clock = FakeClock::default();
            let participants = into_participant_ids(&generate_participants(4));
            let my_participant_id = participants[Self::MY_INDEX];
            let network_api = Arc::new(TestNetworkAPI::new(&participants));

            let pending_requests = PendingRequests::<SignatureRequest, TestRequestRespondArgs>::new(
                clock.clock(),
                participants.clone(),
                my_participant_id,
                network_api.clone(),
            );
            for participant in &participants {
                network_api.set_height(*participant, 100);
            }

            let t = TestBlockMaker::new();
            let genesis = t.block(100);

            (
                pending_requests,
                Self {
                    clock,
                    participant_ids: participants,
                    network_api,
                    head: genesis,
                    fork: None,
                    responses_to_submit: Vec::new(),
                    requests_to_submit: Vec::new(),
                    rng: <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0),
                    tracker: RecentBlocksTracker::new(REQUEST_EXPIRATION_BLOCKS),
                },
            )
        }

        fn set_participant_network_height(&mut self, height: u64) {
            for participant in &self.participant_ids {
                self.network_api.set_height(*participant, height);
            }
        }

        fn add_request_leader(&mut self) -> TestRequest {
            let request = make_request(&self.participant_ids, &[TestSetup::MY_INDEX]);
            self.requests_to_submit.push(request.clone());
            request
        }

        fn add_request_follower(&mut self) -> TestRequest {
            let n = self.participant_ids.len();
            let r = <rand::rngs::StdRng as rand::Rng>::gen_range(&mut self.rng, 0..n - 1);
            let leader_idx = if r >= TestSetup::MY_INDEX { r + 1 } else { r };
            let request = make_request(&self.participant_ids, &[leader_idx]);
            self.requests_to_submit.push(request.clone());
            request
        }

        fn add_request_leader_order(&mut self, leader_order: &[usize]) -> TestRequest {
            let request = make_request(&self.participant_ids, leader_order);
            self.requests_to_submit.push(request.clone());
            request
        }

        fn add_indexed_respond_tx(&mut self, hash: CryptoHash) {
            self.responses_to_submit.push(hash);
        }

        /// Highest block height across all known heads. Each new block (canonical or fork)
        /// is built strictly above this so that the most-recently-added block always wins
        /// the canonical-chain tie-break inside `RecentBlocksTracker`.
        fn max_known_height(&self) -> u64 {
            let fork_height = self
                .fork
                .as_ref()
                .map(|fork_head| fork_head.height())
                .unwrap_or(0);
            self.head.height().max(fork_height)
        }

        /// Builds the next canonical block, adds it to the shared tracker, and delivers
        /// the resulting update to `pending`. Returns the new block height.
        fn update(
            &mut self,
            pending: &mut PendingRequests<TestRequest, TestRequestRespondArgs>,
        ) -> u64 {
            let new_height = self.max_known_height() + 1;
            let new_block = self.head.descendant(new_height);
            let block_status = self
                .tracker
                .add_block(&new_block.to_block_view())
                .block_status;
            let update = RequestsUpdate {
                requests: self.requests_to_submit.clone(),
                completed_requests: self.responses_to_submit.clone(),
                block_height: new_height.into(),
                block_status,
            };
            self.requests_to_submit = Vec::new();
            self.responses_to_submit = Vec::new();
            self.head = new_block;
            pending.notify_new_block(update);
            new_height
        }

        /// Like [`update`] but forks the current head, making a new canonical chain.
        fn update_canonical_fork(
            &mut self,
            pending: &mut PendingRequests<TestRequest, TestRequestRespondArgs>,
        ) -> u64 {
            let new_height = self.max_known_height() + 1;
            if self.fork.is_none() {
                self.fork = self.head.parent.clone();
            }
            let new_block = self.fork.as_ref().unwrap().descendant(new_height);
            let block_status = self
                .tracker
                .add_block(&new_block.to_block_view())
                .block_status;
            let update = RequestsUpdate {
                requests: self.requests_to_submit.clone(),
                completed_requests: self.responses_to_submit.clone(),
                block_height: new_height.into(),
                block_status,
            };
            self.requests_to_submit = Vec::new();
            self.responses_to_submit = Vec::new();
            self.fork = Some(new_block);
            pending.notify_new_block(update);
            new_height
        }

        fn advance_clock(&self, duration: Duration) {
            self.clock.advance(duration);
        }
    }

    #[test_log::test]
    #[expect(non_snake_case)]
    fn test_pending_requests__requests_leader_should_retry() {
        // Given: a request queue
        let (mut pending_requests, mut setup) = TestSetup::new();

        // When: a request is added for which we are a follower
        let _req1 = setup.add_request_follower();
        // and a request is added for which we are a leader
        let req2 = setup.add_request_leader();
        setup.update(&mut pending_requests);

        // Then: req1 is not attempted because we're not the leader. req2 is attempted.
        let to_attempt1 = pending_requests.get_requests_to_attempt();
        assert_eq!(to_attempt1.len(), 1);
        assert_eq!(to_attempt1[0].request.id, req2.id);

        // Then: `get_requests_to_attempt()` does not return the same request again
        // Another attempt should not be issued while the first one is still ongoing.
        setup.advance_clock(2 * CHECK_EACH_REQUEST_INTERVAL);
        assert_eq!(pending_requests.get_requests_to_attempt().len(), 0);

        // When: a new request is issues for which we are a leader
        let req3 = setup.add_request_leader();
        let _req4 = setup.add_request_follower();
        setup.update(&mut pending_requests);

        // Then: req3 should be attempted, while request 4 should be ignored, as we're not leader.
        let to_attempt2 = pending_requests.get_requests_to_attempt();
        assert_eq!(to_attempt2.len(), 1);
        assert_eq!(to_attempt2[0].request.id, req3.id);

        // Then: `get_requests_to_attempt()` does not return the same request again
        // Another attempt should not be issued while the first one is still ongoing.
        setup.advance_clock(2 * CHECK_EACH_REQUEST_INTERVAL);
        assert_eq!(pending_requests.get_requests_to_attempt().len(), 0);

        // When: we drop the attempt for req2
        drop(to_attempt1);
        // Then: It should not immediately retry, because we need to wait
        // for at least a second before retrying anything.
        assert_eq!(pending_requests.get_requests_to_attempt().len(), 0);
        // Then: we should retry after the interval passed
        setup.advance_clock(CHECK_EACH_REQUEST_INTERVAL);
        let to_attempt3 = pending_requests.get_requests_to_attempt();
        assert_eq!(to_attempt3.len(), 1);
        assert_eq!(to_attempt3[0].request.id, req2.id);
    }

    #[test_log::test]
    #[expect(non_snake_case)]
    fn test_pending_requests__should_wait_for_response_to_finalize() {
        // Given: a leader request that has been attempted once and dropped.
        let (mut pending_requests, mut setup) = TestSetup::new();
        let req = setup.add_request_leader();
        setup.update(&mut pending_requests);
        let to_attempt1 = pending_requests.get_requests_to_attempt();
        assert_eq!(to_attempt1.len(), 1);
        assert_eq!(to_attempt1[0].request.id, req.id);

        // When: the attempt records that a response has been submitted to the chain,
        // but the chain has not yet acknowledged it.
        to_attempt1[0]
            .computation_progress
            .lock()
            .unwrap()
            .last_response_submission = Some(setup.clock.now());
        drop(to_attempt1);

        // Then: no retry within `MAX_LATENCY_BEFORE_EXPECTING_TRANSACTION_TO_FINALIZE`,
        // because we're still waiting for the chain to ack the submission.
        setup.advance_clock(CHECK_EACH_REQUEST_INTERVAL);
        assert_eq!(pending_requests.get_requests_to_attempt().len(), 0);
        // Then: retry once that window elapses, because the chain still doesn't show our response.
        setup.advance_clock(MAX_LATENCY_BEFORE_EXPECTING_TRANSACTION_TO_FINALIZE);
        let to_attempt2 = pending_requests.get_requests_to_attempt();
        assert_eq!(to_attempt2.len(), 1);
        assert_eq!(to_attempt2[0].request.id, req.id);

        // When: the response now lands on the canonical chain, but is not yet final.
        drop(to_attempt2);
        setup.add_indexed_respond_tx(req.id);
        setup.update(&mut pending_requests);

        // Then: we do NOT re-attempt — the response is on the canonical chain, so we wait for
        // it to finalize.
        setup.advance_clock(CHECK_EACH_REQUEST_INTERVAL);
        assert_eq!(pending_requests.get_requests_to_attempt().len(), 0);

        // When: enough subsequent blocks arrive to finalize the response.
        setup.update(&mut pending_requests);
        setup.update(&mut pending_requests);

        // Then: we still don't re-attempt — the request is resolved.
        setup.advance_clock(CHECK_EACH_REQUEST_INTERVAL);
        assert_eq!(pending_requests.get_requests_to_attempt().len(), 0);
    }

    #[test_log::test]
    #[expect(non_snake_case)]
    fn test_pending_requests__should_reattempt_when_response_is_non_canonical() {
        // Given: a request queue with one leader request, attempted once and dropped.
        let (mut pending_requests, mut setup) = TestSetup::new();
        let req = setup.add_request_leader();
        setup.update(&mut pending_requests);
        let to_attempt1 = pending_requests.get_requests_to_attempt();
        assert_eq!(to_attempt1.len(), 1);
        assert_eq!(to_attempt1[0].request.id, req.id);
        drop(to_attempt1);

        // When: a response lands in a canonical block.
        setup.advance_clock(CHECK_EACH_REQUEST_INTERVAL);
        setup.add_indexed_respond_tx(req.id);
        setup.update(&mut pending_requests);

        // And: the chain forks and the new fork becomes canonical, leaving the response block
        // (and the response it carries) on the non-canonical branch.
        setup.update_canonical_fork(&mut pending_requests);

        // Then: the queue should re-attempt the request — a non-canonical response does NOT
        // short-circuit `process()`, so the request flows through the normal leader path.
        setup.advance_clock(CHECK_EACH_REQUEST_INTERVAL);
        let to_attempt2 = pending_requests.get_requests_to_attempt();
        assert_eq!(to_attempt2.len(), 1);
        assert_eq!(to_attempt2[0].request.id, req.id);
    }

    #[test_log::test]
    #[expect(non_snake_case)]
    fn test_pending_requests__should_abort_after_maximum_attempts() {
        // Given: a request queue
        let (mut pending_requests, mut setup) = TestSetup::new();

        // When: we have a request as leader
        let req1 = setup.add_request_leader();
        setup.update(&mut pending_requests);
        // then: attempt exactly `MAX_ATTEMPTS_PER_REQUEST_AS_LEADER
        for i in 0..MAX_ATTEMPTS_PER_REQUEST_AS_LEADER {
            let to_attempt = pending_requests.get_requests_to_attempt();
            assert_eq!(to_attempt.len(), 1);
            assert_eq!(to_attempt[0].request.id, req1.id);
            assert_eq!(
                to_attempt[0].computation_progress.lock().unwrap().attempts,
                i + 1
            );
            drop(to_attempt);
            setup.advance_clock(CHECK_EACH_REQUEST_INTERVAL);
        }
        assert_eq!(pending_requests.get_requests_to_attempt().len(), 0);
    }

    #[test_log::test]
    #[expect(non_snake_case)]
    fn test_pending_requests__should_discard_old_and_non_canonical_requests() {
        // Given: a request queue with two request from two different blocks
        let (mut pending_requests, mut setup) = TestSetup::new();
        let _req1 = setup.add_request_leader();
        let block_height_req_1 = setup.update(&mut pending_requests);
        let req2 = setup.add_request_leader();
        let block_height_req_2 = setup.update(&mut pending_requests);

        // When: we set the network height past the expiry of the first, but before expiry of the
        // second signature
        setup.set_participant_network_height(block_height_req_1 + REQUEST_EXPIRATION_BLOCKS);

        // Then: The first request expired, so only the second one is returned.
        let to_attempt1 = pending_requests.get_requests_to_attempt();
        assert_eq!(to_attempt1.len(), 1);
        assert_eq!(to_attempt1[0].request.id, req2.id);

        // When: we set participants to a newer height, expiring the second request as well;
        drop(to_attempt1);
        setup.advance_clock(CHECK_EACH_REQUEST_INTERVAL);
        setup.set_participant_network_height(block_height_req_2 + REQUEST_EXPIRATION_BLOCKS);
        // Then: it should not retry.
        assert_eq!(pending_requests.get_requests_to_attempt().len(), 0);

        // When: we get a third request that is now recent enough
        setup.advance_clock(CHECK_EACH_REQUEST_INTERVAL);
        let req3 = setup.add_request_leader();
        setup.update(&mut pending_requests);

        // Then: we should attempt it
        let to_attempt2 = pending_requests.get_requests_to_attempt();
        assert_eq!(to_attempt2.len(), 1);
        assert_eq!(to_attempt2[0].request.id, req3.id);

        // When: we drop the attempt and have a fork in the chain
        // When: Add a new request in a different fork that becomes the canonical chain.
        drop(to_attempt2);
        setup.advance_clock(CHECK_EACH_REQUEST_INTERVAL);
        let req4 = setup.add_request_leader();
        setup.update_canonical_fork(&mut pending_requests);

        // Then: Req3 is now on a non-canonical fork so should not be attempted.
        let to_attempt3 = pending_requests.get_requests_to_attempt();
        assert_eq!(to_attempt3.len(), 1);
        assert_eq!(to_attempt3[0].request.id, req4.id);

        // When: Bring req3's block back to canonical;
        drop(to_attempt3);
        setup.advance_clock(CHECK_EACH_REQUEST_INTERVAL);
        let req5 = setup.add_request_leader();
        setup.update(&mut pending_requests);

        // Then: we should attempt that instead.
        let to_attempt4 = pending_requests.get_requests_to_attempt();
        assert_eq!(to_attempt4.len(), 2);
        assert!(set_equals(
            &to_attempt4.iter().map(|a| a.request.id).collect::<Vec<_>>(),
            &[req3.id, req5.id]
        ));
    }

    #[test_log::test]
    #[expect(non_snake_case)]
    fn test_pending_requests__should_fallback_leader() {
        // Given: a request queue
        let (mut pending_requests, mut setup) = TestSetup::new();

        // Indexer 0 is offline; indexer 2 is stale. We let indexer 0 have a higher height than
        // normal. This is to test a pathological case, in case some node reports an incorrectly high
        // height and we want to allow shutting down that node to be a mitigation.
        setup.network_api.bring_down(setup.participant_ids[0]);
        setup.network_api.set_height(setup.participant_ids[0], 120); // ignored because offline
        setup.network_api.set_height(setup.participant_ids[1], 100);
        setup.network_api.set_height(setup.participant_ids[2], 80); // stale
        setup.network_api.set_height(setup.participant_ids[3], 100);

        let req1 = setup.add_request_leader_order(&[0, 1]);
        let req2 = setup.add_request_leader_order(&[2, 0, 1]);
        let _req3 = setup.add_request_leader_order(&[3, 1]);
        setup.update(&mut pending_requests);

        // Then: Since 0 and 2 are unavailable, and we are the first available leader for req1 and req2,
        // we should attempt these.
        let to_attempt1 = pending_requests.get_requests_to_attempt();
        assert_eq!(to_attempt1.len(), 2);
        assert!(set_equals(
            &to_attempt1.iter().map(|a| a.request.id).collect::<Vec<_>>(),
            &[req1.id, req2.id]
        ));

        drop(to_attempt1);
        setup.advance_clock(CHECK_EACH_REQUEST_INTERVAL);

        // Bring up node 0. This causes node 1 to itself realize it is stale, so it should refuse to
        // attempt any signatures, even if it were the preferred leader.
        setup.network_api.bring_up(setup.participant_ids[0]);
        let req4 = setup.add_request_leader_order(&[1]);
        setup.update(&mut pending_requests);
        assert_eq!(pending_requests.get_requests_to_attempt().len(), 0);

        // Bring down node 0 again. Now, node 1 should retry req1, req2 again, as well as trying req4.
        setup.network_api.bring_down(setup.participant_ids[0]);
        setup.advance_clock(CHECK_EACH_REQUEST_INTERVAL);
        let to_attempt2 = pending_requests.get_requests_to_attempt();
        assert_eq!(to_attempt2.len(), 3);
        assert!(set_equals(
            &to_attempt2.iter().map(|a| a.request.id).collect::<Vec<_>>(),
            &[req1.id, req2.id, req4.id]
        ));

        // Node 0 actually manages to complete req1 and req4 somehow. Node 1 should not retry
        // these anymore.
        drop(to_attempt2);
        setup.add_indexed_respond_tx(req1.id);
        setup.add_indexed_respond_tx(req4.id);
        setup.update(&mut pending_requests);
        setup.update(&mut pending_requests);
        setup.update(&mut pending_requests);
        setup.advance_clock(CHECK_EACH_REQUEST_INTERVAL);

        let to_attempt3 = pending_requests.get_requests_to_attempt();
        assert_eq!(to_attempt3.len(), 1);
        assert_eq!(to_attempt3[0].request.id, req2.id);
    }

    #[test_log::test]
    #[expect(non_snake_case)]
    fn test_request__latency_debug_should_display_time() {
        // Given: a request queue with a request as leader
        let (mut pending_requests, mut setup) = TestSetup::new();
        setup.advance_clock(Duration::seconds(1));
        let req1 = setup.add_request_leader();
        setup.update(&mut pending_requests);
        // When: we are lagging behind
        setup.advance_clock(Duration::microseconds(2432123));
        // When: we have a response in the subsequent block
        setup.add_indexed_respond_tx(req1.id);
        setup.update(&mut pending_requests);
        setup.advance_clock(Duration::seconds(1));
        // When: we finalize request and response
        setup.update(&mut pending_requests);
        setup.update(&mut pending_requests);
        setup.advance_clock(Duration::seconds(1));
        // Poll so the queue notices the response is final and records latency into
        // `recently_completed_requests` via the `Resolve` arm.
        let _ = pending_requests.get_requests_to_attempt();

        // Then: we expect to see the time delay reflected in the debug message
        let debug = format!("{:?}", pending_requests);
        assert!(
            debug.contains("blk        101 ->        102 (+1, 2s432ms)"),
            "{}",
            debug
        );
        // And: the resolved request appears exactly once in `recently_completed_requests`
        // (regression guard — the Resolve arm used to double-record by both adding a
        // delay row inside the loop and letting the post-loop add a `None`-delay row.)
        assert_eq!(
            debug.matches("[completed]").count(),
            1,
            "expected exactly one completed-request row, got duplicates:\n{}",
            debug
        );
    }

    #[test_log::test]
    #[expect(non_snake_case)]
    fn get_requests_to_attempt__should_not_expire_request_at_expiration_boundary() {
        // Given: one leader request at block height H
        let (mut pending_requests, mut setup) = TestSetup::new();
        let req1 = setup.add_request_leader();
        let block_height = setup.update(&mut pending_requests);

        // When: set network height to H + REQUEST_EXPIRATION_BLOCKS - 1
        setup.set_participant_network_height(block_height + REQUEST_EXPIRATION_BLOCKS - 1);

        // Then: request is NOT expired (returned by get_requests_to_attempt)
        let to_attempt = pending_requests.get_requests_to_attempt();
        assert_eq!(to_attempt.len(), 1);
        assert_eq!(to_attempt[0].request.id, req1.id);
    }

    #[test_log::test]
    #[expect(non_snake_case)]
    fn get_requests_to_attempt__should_expire_request_past_expiration_boundary() {
        // Given: one leader request at block height H
        let (mut pending_requests, mut setup) = TestSetup::new();
        let req1 = setup.add_request_leader();
        let block_height = setup.update(&mut pending_requests);
        assert!(
            pending_requests.requests.contains_key(&req1.id),
            "request should be in the queue"
        );

        // When: set network height to H + REQUEST_EXPIRATION_BLOCKS
        setup.set_participant_network_height(block_height + REQUEST_EXPIRATION_BLOCKS);

        // Then: request IS expired, not returned by get_requests_to_attempt and removed from
        // queue.
        let to_attempt = pending_requests.get_requests_to_attempt();
        assert_eq!(to_attempt.len(), 0);
        assert!(
            !pending_requests.requests.contains_key(&req1.id),
            "expired request should be removed from the queue"
        );
    }
}
