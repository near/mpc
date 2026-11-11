use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Context;
use near_contract_transport::BlockHeight;
use near_time::{Clock, Instant};
use tokio::sync::Notify;

use crate::primitives::ParticipantId;
use crate::requests::queue::REQUEST_EXPIRATION_BLOCKS;
use crate::types::{RequestsUpdate, VerifyForeignTxId, VerifyForeignTxRequestV2};

/// The maximum number of attempts a follower joins per request and leader. It bounds the assets
/// one leader can use up on a request.
const MAX_JOINED_ATTEMPTS_PER_LEADER: usize = 3;

/// The V2 requests this node indexed that are still open: not completed and inside the
/// [`REQUEST_EXPIRATION_BLOCKS`] window of the request. A node signs only for an open request.
///
/// The requests live in memory: after a restart the node knows only the requests it indexes
/// again.
pub(crate) struct OpenVerifyForeignTxRequestsV2 {
    clock: Clock,
    requests: Mutex<HashMap<VerifyForeignTxId, OpenRequest>>,
    added: Notify,
}

struct OpenRequest {
    request: VerifyForeignTxRequestV2,
    indexed_at: Instant,
    /// The number of attempts this node joined, per leader.
    joined_attempts: HashMap<ParticipantId, usize>,
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
            added: Notify::new(),
        }
    }

    /// Adds the requests of a newly indexed block, and drops the ones that completed or expired
    /// at its height. A request indexed again keeps its first index time.
    pub(crate) fn notify_new_block(&self, update: &RequestsUpdate<VerifyForeignTxRequestV2>) {
        let now = self.clock.now();
        let mut requests = self.requests.lock().unwrap();
        for request in &update.requests {
            requests
                .entry(request.id)
                .and_modify(|open| open.request = request.clone())
                .or_insert_with(|| OpenRequest {
                    request: request.clone(),
                    indexed_at: now,
                    joined_attempts: HashMap::new(),
                });
        }
        for completed in &update.completed_requests {
            requests.remove(completed);
        }
        requests.retain(|_, open| is_open_at(&open.request, update.block_height));
        drop(requests);
        self.added.notify_waiters();
    }

    pub(crate) fn get(&self, id: VerifyForeignTxId) -> Option<VerifyForeignTxRequestV2> {
        self.requests
            .lock()
            .unwrap()
            .get(&id)
            .map(|open| open.request.clone())
    }

    /// The time since this node indexed the open request `id`.
    pub(crate) fn time_since_indexed(&self, id: VerifyForeignTxId) -> Option<Duration> {
        let indexed_at = self.requests.lock().unwrap().get(&id)?.indexed_at;
        Some(self.clock.now().saturating_duration_since(indexed_at))
    }

    /// Counts an attempt of `leader` at the open request `id` that this node joins. Fails when
    /// the request is closed, or when this node already joined
    /// [`MAX_JOINED_ATTEMPTS_PER_LEADER`] attempts of `leader` at it.
    pub(crate) fn join_attempt(
        &self,
        id: VerifyForeignTxId,
        leader: ParticipantId,
    ) -> anyhow::Result<()> {
        let mut requests = self.requests.lock().unwrap();
        let open = requests
            .get_mut(&id)
            .context("the V2 request is not open")?;
        let joined = open.joined_attempts.entry(leader).or_default();
        anyhow::ensure!(
            *joined < MAX_JOINED_ATTEMPTS_PER_LEADER,
            "already joined {MAX_JOINED_ATTEMPTS_PER_LEADER} attempts of leader {leader} at the V2 request"
        );
        *joined = joined.saturating_add(1);
        Ok(())
    }

    /// Returns the request once it is open. A peer may start an attempt before this node indexed
    /// the request, so callers bound the wait.
    pub(crate) async fn wait_for(&self, id: VerifyForeignTxId) -> VerifyForeignTxRequestV2 {
        loop {
            let added = self.added.notified();
            tokio::pin!(added);
            added.as_mut().enable();
            if let Some(request) = self.get(id) {
                return request;
            }
            added.await;
        }
    }
}

fn is_open_at(request: &VerifyForeignTxRequestV2, height: BlockHeight) -> bool {
    request
        .request_block_height
        .saturating_add(REQUEST_EXPIRATION_BLOCKS)
        > height
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use chain_gateway::event_subscriber::recent_blocks_tracker::RecentBlocksTracker;
    use chain_gateway::event_subscriber::recent_blocks_tracker::test_utils::TestBlockMaker;
    use mpc_primitives::domain::DomainId;
    use near_contract_transport::BlockCount;
    use near_indexer_primitives::CryptoHash;
    use near_mpc_contract_interface::types as dtos;
    use near_time::FakeClock;

    const REQUEST_HEIGHT: BlockHeight = BlockHeight::new(1000);

    fn request(id: u8) -> VerifyForeignTxRequestV2 {
        VerifyForeignTxRequestV2 {
            id: CryptoHash([id; 32]),
            receipt_id: CryptoHash([0; 32]),
            yield_id: dtos::YieldId([id; 32]),
            request_block_height: REQUEST_HEIGHT,
            request: dtos::VerifyForeignTransactionRequestV2 {
                request: dtos::ForeignChainRpcRequest::Bitcoin(dtos::BitcoinRpcRequest {
                    tx_id: dtos::BitcoinTxId([0; 32]),
                    confirmations: dtos::BlockConfirmations(1),
                    extractors: [dtos::BitcoinExtractor::BlockHash].into(),
                }),
                domain_id: DomainId(0),
                expected_values: vec![],
            },
            entropy: [0; 32],
            timestamp_nanosec: 0,
        }
    }

    fn update(
        height: BlockHeight,
        requests: Vec<VerifyForeignTxRequestV2>,
        completed_requests: Vec<VerifyForeignTxId>,
    ) -> RequestsUpdate<VerifyForeignTxRequestV2> {
        let mut tracker = RecentBlocksTracker::new(REQUEST_EXPIRATION_BLOCKS);
        let block = TestBlockMaker::new().block(u64::from(height));
        let block_status = tracker.add_block(&block.to_block_view()).block_status;
        RequestsUpdate {
            requests,
            completed_requests,
            block_height: height,
            block_status,
        }
    }

    #[test]
    fn open_requests__should_keep_an_indexed_request_open() {
        // Given
        let open = OpenVerifyForeignTxRequestsV2::default();

        // When
        open.notify_new_block(&update(REQUEST_HEIGHT, vec![request(1)], vec![]));

        // Then
        assert_eq!(open.get(request(1).id), Some(request(1)));
    }

    #[test]
    fn open_requests__should_close_a_completed_request() {
        // Given
        let open = OpenVerifyForeignTxRequestsV2::default();
        open.notify_new_block(&update(
            REQUEST_HEIGHT,
            vec![request(1), request(2)],
            vec![],
        ));

        // When
        open.notify_new_block(&update(
            REQUEST_HEIGHT + BlockCount::new(1),
            vec![],
            vec![request(1).id],
        ));

        // Then
        assert_eq!(open.get(request(1).id), None);
        assert_eq!(open.get(request(2).id), Some(request(2)));
    }

    #[test]
    fn open_requests__should_close_a_request_once_its_window_ends() {
        // Given
        let open = OpenVerifyForeignTxRequestsV2::default();
        open.notify_new_block(&update(REQUEST_HEIGHT, vec![request(1)], vec![]));
        let last_open_height =
            REQUEST_HEIGHT + BlockCount::new(u64::from(REQUEST_EXPIRATION_BLOCKS) - 1);

        // When
        open.notify_new_block(&update(last_open_height, vec![], vec![]));
        let open_in_last_block = open.get(request(1).id);
        open.notify_new_block(&update(
            last_open_height + BlockCount::new(1),
            vec![],
            vec![],
        ));

        // Then
        assert_eq!(open_in_last_block, Some(request(1)));
        assert_eq!(open.get(request(1).id), None);
    }

    #[test]
    fn open_requests_time_since_indexed__should_count_from_the_first_index() {
        // Given
        let clock = FakeClock::default();
        let open = OpenVerifyForeignTxRequestsV2::new(clock.clock());
        open.notify_new_block(&update(REQUEST_HEIGHT, vec![request(1)], vec![]));
        clock.advance(near_time::Duration::seconds(4));

        // When
        open.notify_new_block(&update(
            REQUEST_HEIGHT + BlockCount::new(1),
            vec![request(1)],
            vec![],
        ));
        clock.advance(near_time::Duration::seconds(1));

        // Then
        assert_eq!(
            open.time_since_indexed(request(1).id),
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn open_requests_join_attempt__should_refuse_an_attempt_past_the_limit_per_leader() {
        // Given
        let open = OpenVerifyForeignTxRequestsV2::default();
        open.notify_new_block(&update(REQUEST_HEIGHT, vec![request(1)], vec![]));
        let leader = ParticipantId::from_raw(1);
        let other_leader = ParticipantId::from_raw(2);

        // When
        let joined: Vec<_> = (0..3)
            .map(|_| open.join_attempt(request(1).id, leader))
            .collect();
        let past_the_limit = open.join_attempt(request(1).id, leader);
        let other = open.join_attempt(request(1).id, other_leader);

        // Then
        assert!(joined.iter().all(Result::is_ok), "{joined:?}");
        let error = past_the_limit.unwrap_err().to_string();
        assert!(error.contains("already joined 3 attempts"), "{error}");
        other.unwrap();
    }

    #[test]
    fn open_requests_join_attempt__should_refuse_a_completed_request() {
        // Given
        let open = OpenVerifyForeignTxRequestsV2::default();
        open.notify_new_block(&update(REQUEST_HEIGHT, vec![request(1)], vec![]));
        let leader = ParticipantId::from_raw(1);
        open.join_attempt(request(1).id, leader).unwrap();

        // When
        open.notify_new_block(&update(
            REQUEST_HEIGHT + BlockCount::new(1),
            vec![],
            vec![request(1).id],
        ));

        // Then
        let error = open
            .join_attempt(request(1).id, leader)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not open"), "{error}");
    }

    #[tokio::test]
    async fn open_requests_wait_for__should_return_a_request_indexed_after_the_wait_started() {
        // Given
        let open = OpenVerifyForeignTxRequestsV2::default();
        let waiting = open.wait_for(request(1).id);

        // When
        let (found, ()) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(5), waiting),
            async { open.notify_new_block(&update(REQUEST_HEIGHT, vec![request(1)], vec![])) }
        );

        // Then
        assert_eq!(found.unwrap(), request(1));
    }
}
