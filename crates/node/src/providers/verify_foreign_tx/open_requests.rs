use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use std::time::Duration;

use chain_gateway::event_subscriber::recent_blocks_tracker::BlockStatusHandle;
use near_contract_transport::BlockHeight;
use near_mpc_contract_interface::types::YieldId;
use near_time::{Clock, Instant};
use tokio::sync::Notify;
use tokio::sync::futures::Notified;

use crate::requests::queue::REQUEST_EXPIRATION_BLOCKS;
use crate::types::{RequestsUpdate, VerifyForeignTxId, VerifyForeignTxRequestV2};

/// The maximum number of signing rounds a signer joins per request and leader, for verdicts and
/// inconclusives together. It bounds the assets one leader can use up on a request.
pub(crate) const MAX_ROUNDS_PER_LEADER: usize = 3;

/// The V2 requests this node indexed, to tell the open ones: indexed on the canonical chain,
/// without a completion on the canonical chain, and inside the [`REQUEST_EXPIRATION_BLOCKS`]
/// window of the request. A node signs only for an open request.
///
/// A completion closes every request with its yield id. A request or completion on a fork that
/// loses counts only while its block stays canonical.
///
/// The requests live in memory: after a restart the node knows only the requests it indexes
/// again.
pub(crate) struct OpenVerifyForeignTxRequestsV2 {
    clock: Clock,
    requests: Mutex<Requests>,
    changed: Notify,
}

/// The tracked requests, with an index from each yield id to its requests. Requests on two
/// forks can share a yield id.
#[derive(Default)]
struct Requests {
    by_id: HashMap<VerifyForeignTxId, IndexedRequest>,
    ids_by_yield: HashMap<YieldId, BTreeSet<VerifyForeignTxId>>,
}

struct IndexedRequest {
    request: VerifyForeignTxRequestV2,
    block: BlockStatusHandle,
    /// The time this node first indexed the request.
    #[cfg_attr(not(test), expect(dead_code))]
    indexed_at: Instant,
    /// The blocks of the completions of this request or of another request with its yield id.
    completions: Vec<BlockStatusHandle>,
    /// Set once [`OpenVerifyForeignTxRequestsV2::take_final_uninspected`] handed the request out.
    inspected: bool,
}

impl Default for OpenVerifyForeignTxRequestsV2 {
    fn default() -> Self {
        Self::new(Clock::real())
    }
}

impl OpenVerifyForeignTxRequestsV2 {
    pub(crate) fn new(clock: Clock) -> Self {
        Self {
            clock,
            requests: Mutex::default(),
            changed: Notify::new(),
        }
    }

    /// Adds the requests and completions of a newly indexed block. Returns the yield ids it no
    /// longer tracks, after a final completion, the end of the window or the pruning of a fork.
    /// A request indexed again keeps its first index time.
    pub(crate) fn notify_new_block(
        &self,
        update: &RequestsUpdate<VerifyForeignTxRequestV2>,
    ) -> Vec<YieldId> {
        let now = self.clock.now();
        let mut requests = self.requests.lock().unwrap();
        for request in &update.requests {
            requests.insert_new(IndexedRequest {
                request: request.clone(),
                block: update.block_status.clone(),
                indexed_at: now,
                completions: Vec::new(),
                inspected: false,
            });
        }
        let completed_yields: Vec<YieldId> = update
            .completed_requests
            .iter()
            .filter_map(|id| {
                requests
                    .by_id
                    .get(id)
                    .map(|indexed| indexed.request.yield_id)
            })
            .collect();
        for indexed in requests.by_id.values_mut() {
            if completed_yields.contains(&indexed.request.yield_id) {
                indexed.completions.push(update.block_status.clone());
            }
            indexed
                .completions
                .retain(|completion| completion.is_canonical().is_some());
        }
        let settled = requests.remove_settled_at(update.block_height);
        drop(requests);
        self.changed.notify_waiters();
        settled
    }

    /// True while the request `id` may still open or close.
    pub(crate) fn tracks(&self, id: VerifyForeignTxId) -> bool {
        self.requests.lock().unwrap().by_id.contains_key(&id)
    }

    /// True while a request with `yield_id` may still open or close.
    #[cfg(test)]
    pub(crate) fn tracks_yield(&self, yield_id: YieldId) -> bool {
        self.requests
            .lock()
            .unwrap()
            .ids_by_yield
            .contains_key(&yield_id)
    }

    /// The open requests whose block is final and that no earlier call returned. A node
    /// inspects each request once, and only once its block is final, so a fork cannot hand two
    /// requests the same yield id.
    pub(crate) fn take_final_uninspected(&self) -> Vec<VerifyForeignTxRequestV2> {
        self.requests
            .lock()
            .unwrap()
            .by_id
            .values_mut()
            .filter(|indexed| {
                !indexed.inspected && indexed.is_open() && indexed.block.is_final() == Some(true)
            })
            .map(|indexed| {
                indexed.inspected = true;
                indexed.request.clone()
            })
            .collect()
    }

    pub(crate) fn get(&self, id: VerifyForeignTxId) -> Option<VerifyForeignTxRequestV2> {
        self.requests
            .lock()
            .unwrap()
            .by_id
            .get(&id)
            .filter(|indexed| indexed.is_open())
            .map(|indexed| indexed.request.clone())
    }

    /// Completes after the next indexed block. Call [`Notified::enable`] before reading the
    /// requests, so no block between the read and the wait gets lost.
    pub(crate) fn changed(&self) -> Notified<'_> {
        self.changed.notified()
    }

    /// The time since this node first indexed the open request `id`.
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn time_since_indexed(&self, id: VerifyForeignTxId) -> Option<Duration> {
        let indexed_at = self
            .requests
            .lock()
            .unwrap()
            .by_id
            .get(&id)
            .filter(|indexed| indexed.is_open())?
            .indexed_at;
        Some(self.clock.now().saturating_duration_since(indexed_at))
    }

    /// Returns an open request with `yield_id` once there is one. A peer may start a signing
    /// round before this node indexed the request, so callers bound the wait.
    pub(crate) async fn wait_for_yield(&self, yield_id: YieldId) -> VerifyForeignTxRequestV2 {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let open = self.requests.lock().unwrap().open_with_yield(yield_id);
            if let Some(request) = open {
                return request;
            }
            changed.await;
        }
    }
}

impl Requests {
    /// Adds `indexed` unless a request with its id is tracked already.
    fn insert_new(&mut self, indexed: IndexedRequest) {
        let id = indexed.request.id;
        let yield_id = indexed.request.yield_id;
        if self.by_id.contains_key(&id) {
            return;
        }
        self.by_id.insert(id, indexed);
        self.ids_by_yield.entry(yield_id).or_default().insert(id);
    }

    /// Drops the requests settled at `height`. Returns the yield ids no request tracks anymore.
    fn remove_settled_at(&mut self, height: BlockHeight) -> Vec<YieldId> {
        let settled: Vec<(VerifyForeignTxId, YieldId)> = self
            .by_id
            .values()
            .filter(|indexed| indexed.is_settled_at(height))
            .map(|indexed| (indexed.request.id, indexed.request.yield_id))
            .collect();
        let mut untracked_yields = Vec::new();
        for (id, yield_id) in settled {
            self.by_id.remove(&id);
            let Some(ids) = self.ids_by_yield.get_mut(&yield_id) else {
                continue;
            };
            ids.remove(&id);
            if ids.is_empty() {
                self.ids_by_yield.remove(&yield_id);
                untracked_yields.push(yield_id);
            }
        }
        untracked_yields
    }

    fn open_with_yield(&self, yield_id: YieldId) -> Option<VerifyForeignTxRequestV2> {
        self.ids_by_yield
            .get(&yield_id)?
            .iter()
            .filter_map(|id| self.by_id.get(id))
            .find(|indexed| indexed.is_open())
            .map(|indexed| indexed.request.clone())
    }
}

impl IndexedRequest {
    fn is_open(&self) -> bool {
        self.block.is_canonical() == Some(true)
            && !self
                .completions
                .iter()
                .any(|completion| completion.is_canonical() == Some(true))
    }

    /// True once the request can never be open again at `height`.
    fn is_settled_at(&self, height: BlockHeight) -> bool {
        let expired = self
            .request
            .request_block_height
            .saturating_add(REQUEST_EXPIRATION_BLOCKS)
            <= height;
        let pruned = self.block.is_canonical().is_none();
        let finally_completed = self
            .completions
            .iter()
            .any(|completion| completion.is_final() == Some(true));
        expired || pruned || finally_completed
    }
}

#[cfg(test)]
pub(crate) mod test_chain {
    use std::sync::Arc;

    use chain_gateway::event_subscriber::recent_blocks_tracker::RecentBlocksTracker;
    use chain_gateway::event_subscriber::recent_blocks_tracker::test_utils::{
        TestBlock, TestBlockMaker,
    };
    use near_contract_transport::BlockHeight;

    use crate::requests::queue::REQUEST_EXPIRATION_BLOCKS;
    use crate::types::{RequestsUpdate, VerifyForeignTxId, VerifyForeignTxRequestV2};

    /// Indexed blocks. A [`RecentBlocksTracker`] keeps their status for as long as the
    /// chain lives.
    pub(crate) struct TestChain {
        tracker: RecentBlocksTracker,
        pub(crate) head: Arc<TestBlock>,
    }

    impl TestChain {
        /// A chain whose first block is at `height`.
        pub(crate) fn starting_at(height: BlockHeight) -> Self {
            let mut tracker = RecentBlocksTracker::new(REQUEST_EXPIRATION_BLOCKS);
            let head = TestBlockMaker::new().block(u64::from(height));
            tracker.add_block(&head.to_block_view());
            Self { tracker, head }
        }

        /// Adds the child of the head as the new head.
        pub(crate) fn extend(
            &mut self,
            requests: Vec<VerifyForeignTxRequestV2>,
            completed_requests: Vec<VerifyForeignTxId>,
        ) -> RequestsUpdate<VerifyForeignTxRequestV2> {
            let parent = self.head.clone();
            self.add(&parent, parent.height() + 1, requests, completed_requests)
        }

        /// Adds a block at `height` on top of `parent`. The highest block becomes canonical.
        pub(crate) fn add(
            &mut self,
            parent: &Arc<TestBlock>,
            height: u64,
            requests: Vec<VerifyForeignTxRequestV2>,
            completed_requests: Vec<VerifyForeignTxId>,
        ) -> RequestsUpdate<VerifyForeignTxRequestV2> {
            let block = parent.descendant(height);
            let block_status = self.tracker.add_block(&block.to_block_view()).block_status;
            if height > self.head.height() {
                self.head = block;
            }
            RequestsUpdate {
                requests,
                completed_requests,
                block_height: BlockHeight::new(height),
                block_status,
            }
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::test_chain::TestChain;
    use super::*;
    use mpc_primitives::domain::DomainId;
    use near_contract_transport::BlockCount;
    use near_indexer_primitives::CryptoHash;
    use near_mpc_contract_interface::types as dtos;
    use near_time::FakeClock;

    const START_HEIGHT: BlockHeight = BlockHeight::new(999);
    const REQUEST_HEIGHT: BlockHeight = BlockHeight::new(1000);

    fn request_with_yield(id: u8, yield_id: u8) -> VerifyForeignTxRequestV2 {
        VerifyForeignTxRequestV2 {
            id: CryptoHash([id; 32]),
            receipt_id: CryptoHash([0; 32]),
            yield_id: dtos::YieldId([yield_id; 32]),
            request_block_height: REQUEST_HEIGHT,
            request: dtos::ForeignChainRpcRequest::Bitcoin(dtos::BitcoinRpcRequest {
                tx_id: dtos::BitcoinTxId([0; 32]),
                confirmations: dtos::BlockConfirmations(1),
                extractors: [dtos::BitcoinExtractor::BlockHash].into(),
            }),
            domain_id: DomainId(0),
            expected_values_hash: dtos::Hash256([id; 32]),
            entropy: [0; 32],
            timestamp_nanosec: 0,
        }
    }

    fn request(id: u8) -> VerifyForeignTxRequestV2 {
        request_with_yield(id, id)
    }

    #[test]
    fn open_requests__should_keep_an_indexed_request_open() {
        // Given
        let open = OpenVerifyForeignTxRequestsV2::default();
        let mut chain = TestChain::starting_at(START_HEIGHT);

        // When
        open.notify_new_block(&chain.extend(vec![request(1)], vec![]));

        // Then
        assert_eq!(open.get(request(1).id), Some(request(1)));
    }

    #[test]
    fn open_requests__should_close_a_completed_request() {
        // Given
        let open = OpenVerifyForeignTxRequestsV2::default();
        let mut chain = TestChain::starting_at(START_HEIGHT);
        open.notify_new_block(&chain.extend(vec![request(1), request(2)], vec![]));

        // When
        open.notify_new_block(&chain.extend(vec![], vec![request(1).id]));

        // Then
        assert_eq!(open.get(request(1).id), None);
        assert_eq!(open.get(request(2).id), Some(request(2)));
    }

    #[test]
    fn open_requests__should_settle_a_request_once_its_completion_is_final() {
        // Given
        let open = OpenVerifyForeignTxRequestsV2::default();
        let mut chain = TestChain::starting_at(START_HEIGHT);
        open.notify_new_block(&chain.extend(vec![request(1)], vec![]));
        let settled_by_the_completion =
            open.notify_new_block(&chain.extend(vec![], vec![request(1).id]));
        let settled_while_not_final = open.notify_new_block(&chain.extend(vec![], vec![]));

        // When
        let settled_once_final = open.notify_new_block(&chain.extend(vec![], vec![]));

        // Then
        assert_eq!(settled_by_the_completion, vec![]);
        assert_eq!(settled_while_not_final, vec![]);
        assert_eq!(settled_once_final, vec![request(1).yield_id]);
        assert!(!open.tracks_yield(request(1).yield_id));
    }

    #[test]
    fn open_requests__should_close_every_request_with_the_yield_id_of_a_completion() {
        // Given
        let open = OpenVerifyForeignTxRequestsV2::default();
        let mut chain = TestChain::starting_at(START_HEIGHT);
        let (first, second) = (request_with_yield(1, 9), request_with_yield(2, 9));
        open.notify_new_block(&chain.extend(vec![first.clone(), second.clone()], vec![]));

        // When
        open.notify_new_block(&chain.extend(vec![], vec![second.id]));

        // Then
        assert_eq!(open.get(first.id), None);
        assert_eq!(open.get(second.id), None);
    }

    #[test]
    fn open_requests__should_reopen_a_request_whose_completion_lost_its_fork() {
        // Given
        let open = OpenVerifyForeignTxRequestsV2::default();
        let mut chain = TestChain::starting_at(START_HEIGHT);
        open.notify_new_block(&chain.extend(vec![request(1)], vec![]));
        let fork_point = chain.head.clone();
        open.notify_new_block(&chain.extend(vec![], vec![request(1).id]));
        let closed_on_the_fork = open.get(request(1).id);

        // When
        let other_fork_height = fork_point.height() + 2;
        open.notify_new_block(&chain.add(&fork_point, other_fork_height, vec![], vec![]));

        // Then
        assert_eq!(closed_on_the_fork, None);
        assert_eq!(open.get(request(1).id), Some(request(1)));
    }

    #[test]
    fn open_requests__should_not_open_a_request_whose_fork_lost() {
        // Given
        let open = OpenVerifyForeignTxRequestsV2::default();
        let mut chain = TestChain::starting_at(START_HEIGHT);
        let fork_point = chain.head.clone();
        open.notify_new_block(&chain.extend(vec![request(1)], vec![]));
        let open_on_the_fork = open.get(request(1).id);

        // When
        let other_fork_height = fork_point.height() + 2;
        open.notify_new_block(&chain.add(&fork_point, other_fork_height, vec![], vec![]));

        // Then
        assert_eq!(open_on_the_fork, Some(request(1)));
        assert_eq!(open.get(request(1).id), None);
    }

    #[test]
    fn open_requests__should_close_a_request_once_its_window_ends() {
        // Given
        let open = OpenVerifyForeignTxRequestsV2::default();
        let mut chain = TestChain::starting_at(START_HEIGHT);
        open.notify_new_block(&chain.extend(vec![request(1)], vec![]));
        let last_open_height =
            REQUEST_HEIGHT + BlockCount::new(u64::from(REQUEST_EXPIRATION_BLOCKS) - 1);
        let fork_point = chain.head.clone();
        open.notify_new_block(&chain.add(&fork_point, u64::from(last_open_height), vec![], vec![]));
        let open_in_last_block = open.get(request(1).id);

        // When
        let settled = open.notify_new_block(&chain.extend(vec![], vec![]));

        // Then
        assert_eq!(open_in_last_block, Some(request(1)));
        assert_eq!(open.get(request(1).id), None);
        assert_eq!(settled, vec![request(1).yield_id]);
    }

    #[test]
    fn open_requests_take_final_uninspected__should_hand_out_a_request_once_its_block_is_final() {
        // Given
        let open = OpenVerifyForeignTxRequestsV2::default();
        let mut chain = TestChain::starting_at(START_HEIGHT);
        open.notify_new_block(&chain.extend(vec![request(1)], vec![]));
        let before_final = open.take_final_uninspected();
        open.notify_new_block(&chain.extend(vec![], vec![]));
        open.notify_new_block(&chain.extend(vec![], vec![]));

        // When
        let once_final = open.take_final_uninspected();
        let again = open.take_final_uninspected();

        // Then
        assert_eq!(before_final, vec![]);
        assert_eq!(once_final, vec![request(1)]);
        assert_eq!(again, vec![]);
    }

    #[test]
    fn open_requests_take_final_uninspected__should_skip_a_closed_request() {
        // Given
        let open = OpenVerifyForeignTxRequestsV2::default();
        let mut chain = TestChain::starting_at(START_HEIGHT);
        open.notify_new_block(&chain.extend(vec![request(1)], vec![]));
        open.notify_new_block(&chain.extend(vec![], vec![request(1).id]));
        open.notify_new_block(&chain.extend(vec![], vec![]));

        // When
        let to_inspect = open.take_final_uninspected();

        // Then
        assert_eq!(to_inspect, vec![]);
    }

    #[test]
    fn open_requests_time_since_indexed__should_count_from_the_first_index() {
        // Given
        let clock = FakeClock::default();
        let open = OpenVerifyForeignTxRequestsV2::new(clock.clock());
        let mut chain = TestChain::starting_at(START_HEIGHT);
        open.notify_new_block(&chain.extend(vec![request(1)], vec![]));
        clock.advance(near_time::Duration::seconds(4));

        // When
        open.notify_new_block(&chain.extend(vec![request(1)], vec![]));
        clock.advance(near_time::Duration::seconds(1));

        // Then
        assert_eq!(
            open.time_since_indexed(request(1).id),
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn open_requests_time_since_indexed__should_ignore_a_closed_request() {
        // Given
        let open = OpenVerifyForeignTxRequestsV2::default();
        let mut chain = TestChain::starting_at(START_HEIGHT);
        open.notify_new_block(&chain.extend(vec![request(1)], vec![]));

        // When
        open.notify_new_block(&chain.extend(vec![], vec![request(1).id]));

        // Then
        assert_eq!(open.time_since_indexed(request(1).id), None);
    }

    #[tokio::test]
    async fn open_requests_wait_for_yield__should_return_a_request_indexed_after_the_wait_started()
    {
        // Given
        let open = OpenVerifyForeignTxRequestsV2::default();
        let mut chain = TestChain::starting_at(START_HEIGHT);
        let waiting = open.wait_for_yield(request(1).yield_id);

        // When
        let (found, _) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(5), waiting),
            async { open.notify_new_block(&chain.extend(vec![request(1)], vec![])) }
        );

        // Then
        assert_eq!(found.unwrap(), request(1));
    }

    #[tokio::test]
    async fn open_requests_wait_for_yield__should_return_the_open_request_of_a_yield_two_forks_share()
     {
        // Given
        let open = OpenVerifyForeignTxRequestsV2::default();
        let mut chain = TestChain::starting_at(START_HEIGHT);
        let (lost, kept) = (request_with_yield(1, 9), request_with_yield(2, 9));
        let fork_point = chain.head.clone();
        open.notify_new_block(&chain.extend(vec![lost.clone()], vec![]));
        let other_fork_height = fork_point.height() + 2;
        open.notify_new_block(&chain.add(
            &fork_point,
            other_fork_height,
            vec![kept.clone()],
            vec![],
        ));

        // When
        let found =
            tokio::time::timeout(Duration::from_secs(5), open.wait_for_yield(kept.yield_id)).await;

        // Then
        assert_eq!(found.unwrap(), kept);
        assert_eq!(open.get(lost.id), None);
    }
}
