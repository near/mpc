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

#[test]
fn open_requests_join_round__should_refuse_a_round_past_the_limit_per_leader() {
    // Given
    let open = OpenVerifyForeignTxRequestsV2::default();
    let mut chain = TestChain::starting_at(START_HEIGHT);
    open.notify_new_block(&chain.extend(vec![request(1)], vec![]));
    let leader = ParticipantId::from_raw(1);
    let other_leader = ParticipantId::from_raw(2);
    for _ in 0..MAX_ROUNDS_PER_LEADER {
        open.join_round(ActingLeader::assumed(request(1).id, leader))
            .unwrap();
    }

    // When
    let past_the_limit = open.join_round(ActingLeader::assumed(request(1).id, leader));
    let other = open.join_round(ActingLeader::assumed(request(1).id, other_leader));

    // Then
    assert_eq!(past_the_limit, Err(JoinRoundRefusal::RoundLimit(leader)));
    assert_eq!(other, Ok(()));
}

#[test]
fn open_requests_join_round__should_count_rounds_per_request() {
    // Given
    let open = OpenVerifyForeignTxRequestsV2::default();
    let mut chain = TestChain::starting_at(START_HEIGHT);
    open.notify_new_block(&chain.extend(vec![request(1), request(2)], vec![]));
    let leader = ParticipantId::from_raw(1);
    for _ in 0..MAX_ROUNDS_PER_LEADER {
        open.join_round(ActingLeader::assumed(request(1).id, leader))
            .unwrap();
    }

    // When
    let other_request = open.join_round(ActingLeader::assumed(request(2).id, leader));

    // Then
    assert_eq!(other_request, Ok(()));
}

#[test]
fn open_requests_join_round__should_refuse_a_closed_request() {
    // Given
    let open = OpenVerifyForeignTxRequestsV2::default();
    let mut chain = TestChain::starting_at(START_HEIGHT);
    open.notify_new_block(&chain.extend(vec![request(1)], vec![]));
    let leader = ActingLeader::assumed(request(1).id, ParticipantId::from_raw(1));

    // When
    open.notify_new_block(&chain.extend(vec![], vec![request(1).id]));

    // Then
    assert_eq!(
        open.join_round(leader),
        Err(JoinRoundRefusal::RequestClosed)
    );
}

#[tokio::test]
async fn open_requests_wait_for_yield__should_return_a_request_indexed_after_the_wait_started() {
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
async fn open_requests_wait_for_yield__should_return_the_open_request_of_a_yield_two_forks_share() {
    // Given
    let open = OpenVerifyForeignTxRequestsV2::default();
    let mut chain = TestChain::starting_at(START_HEIGHT);
    let (lost, kept) = (request_with_yield(1, 9), request_with_yield(2, 9));
    let fork_point = chain.head.clone();
    open.notify_new_block(&chain.extend(vec![lost.clone()], vec![]));
    let other_fork_height = fork_point.height() + 2;
    open.notify_new_block(&chain.add(&fork_point, other_fork_height, vec![kept.clone()], vec![]));

    // When
    let found =
        tokio::time::timeout(Duration::from_secs(5), open.wait_for_yield(kept.yield_id)).await;

    // Then
    assert_eq!(found.unwrap(), kept);
    assert_eq!(open.get(lost.id), None);
}
