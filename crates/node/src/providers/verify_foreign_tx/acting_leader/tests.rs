use super::*;
use crate::network::testing::new_test_client;
use crate::providers::verify_foreign_tx::open_requests::test_chain::TestChain;
use crate::providers::verify_foreign_tx::testing::{TestProvider, bitcoin_request, open_with};
use crate::requests::queue::{LEADER_FAILOVER_INTERVAL, MAX_LEADER_FAILOVER_DEPTH};
use near_time::FakeClock;
use std::sync::Arc;

fn participants() -> Vec<ParticipantId> {
    (0..6).map(ParticipantId::from_raw).collect()
}

fn all_eligible() -> HashSet<ParticipantId> {
    participants().into_iter().collect()
}

fn failover_interval() -> Duration {
    LEADER_FAILOVER_INTERVAL.unsigned_abs()
}

#[test]
fn is_acting_leader__should_accept_the_first_eligible_leader_at_once() {
    // Given
    let order = participants();
    let eligible: HashSet<_> = order[1..].iter().copied().collect();

    // When
    let acting = is_acting_leader(order[1], &order, &eligible, Duration::ZERO);

    // Then
    assert!(acting);
}

#[test]
fn is_acting_leader__should_refuse_a_participant_that_is_not_eligible() {
    // Given
    let order = participants();
    let eligible: HashSet<_> = order[1..].iter().copied().collect();

    // When
    let acting = is_acting_leader(order[0], &order, &eligible, 10 * failover_interval());

    // Then
    assert!(!acting);
}

#[test]
fn is_acting_leader__should_refuse_a_backup_more_than_the_margin_before_its_turn() {
    // Given
    let order = participants();
    let since_indexed =
        failover_interval() - BACKUP_LEADER_EARLY_ACCEPTANCE - Duration::from_millis(1);

    // When
    let acting = is_acting_leader(order[1], &order, &all_eligible(), since_indexed);

    // Then
    assert!(!acting);
}

#[test]
fn is_acting_leader__should_accept_a_backup_up_to_the_margin_before_its_turn() {
    // Given
    let order = participants();
    let since_indexed = failover_interval() - BACKUP_LEADER_EARLY_ACCEPTANCE;

    // When
    let acting = is_acting_leader(order[1], &order, &all_eligible(), since_indexed);

    // Then
    assert!(acting);
}

#[test]
fn is_acting_leader__should_accept_a_backup_once_its_turn_started() {
    // Given
    let order = participants();

    // When
    let acting = is_acting_leader(order[2], &order, &all_eligible(), 2 * failover_interval());

    // Then
    assert!(acting);
}

#[test]
fn is_acting_leader__should_time_a_backup_by_its_rank_among_eligible_leaders() {
    // Given
    let order = participants();
    let eligible: HashSet<_> = order[1..].iter().copied().collect();

    // When
    let acting = is_acting_leader(order[2], &order, &eligible, failover_interval());

    // Then
    assert!(acting);
}

#[test]
fn is_acting_leader__should_refuse_a_participant_past_the_failover_depth() {
    // Given
    let order = participants();

    // When
    let acting = is_acting_leader(
        order[MAX_LEADER_FAILOVER_DEPTH],
        &order,
        &all_eligible(),
        10 * failover_interval(),
    );

    // Then
    assert!(!acting);
}

/// Three participants in their leader selection order for [`bitcoin_request`].
fn order_for_request() -> Vec<ParticipantId> {
    let participants: Vec<_> = (0..3).map(ParticipantId::from_raw).collect();
    leader_selection_order(&participants, bitcoin_request().id)
}

/// The last participant in [`order_for_request`], which indexed [`bitcoin_request`]
/// `since_indexed` ago and sees `supporters` support its chain.
struct CheckingNode {
    node: TestProvider,
    _chain: TestChain,
}

impl CheckingNode {
    fn new(since_indexed: near_time::Duration, supporters: HashSet<ParticipantId>) -> Self {
        let order = order_for_request();
        let clock = FakeClock::default();
        let (open_requests, chain) = open_with(bitcoin_request(), clock.clock());
        clock.advance(since_indexed);
        let node = TestProvider::new(
            new_test_client(order.clone(), order[2]),
            open_requests,
            bitcoin_request().request.chain(),
            supporters,
        );
        Self {
            node,
            _chain: chain,
        }
    }

    fn check(&self, leader: ParticipantId) -> Result<ActingLeader, LeaderRefusal> {
        self.node
            .provider
            .ensure_acting_leader(&bitcoin_request(), leader)
    }
}

fn all_support() -> HashSet<ParticipantId> {
    order_for_request().into_iter().collect()
}

#[test]
fn ensure_acting_leader__should_accept_the_first_leader_at_once() {
    // Given
    let order = order_for_request();
    let node = CheckingNode::new(near_time::Duration::ZERO, all_support());

    // When
    let checked = node.check(order[0]);

    // Then
    assert_eq!(checked, Ok(ActingLeader(order[0])));
}

#[test]
fn ensure_acting_leader__should_refuse_a_backup_before_its_turn() {
    // Given
    let order = order_for_request();
    let node = CheckingNode::new(near_time::Duration::ZERO, all_support());

    // When
    let checked = node.check(order[1]);

    // Then
    assert_eq!(checked, Err(LeaderRefusal::NotActing(order[1])));
}

#[test]
fn ensure_acting_leader__should_accept_a_backup_from_the_margin_before_its_turn() {
    // Given
    let order = order_for_request();
    let margin = near_time::Duration::try_from(BACKUP_LEADER_EARLY_ACCEPTANCE).unwrap();
    let node = CheckingNode::new(LEADER_FAILOVER_INTERVAL - margin, all_support());

    // When
    let checked = node.check(order[1]);

    // Then
    assert_eq!(checked, Ok(ActingLeader(order[1])));
}

#[test]
fn ensure_acting_leader__should_refuse_a_leader_that_does_not_support_the_chain() {
    // Given
    let order = order_for_request();
    let supporters = order[1..].iter().copied().collect();
    let node = CheckingNode::new(near_time::Duration::ZERO, supporters);

    // When
    let first_in_order = node.check(order[0]);
    let first_supporter = node.check(order[1]);

    // Then
    assert_eq!(first_in_order, Err(LeaderRefusal::NotActing(order[0])));
    assert_eq!(first_supporter, Ok(ActingLeader(order[1])));
}

#[test]
fn ensure_acting_leader__should_refuse_a_request_that_is_not_open() {
    // Given
    let order = order_for_request();
    let node = TestProvider::new(
        new_test_client(order.clone(), order[2]),
        Arc::default(),
        bitcoin_request().request.chain(),
        all_support(),
    );

    // When
    let checked = node
        .provider
        .ensure_acting_leader(&bitcoin_request(), order[0]);

    // Then
    assert_eq!(checked, Err(LeaderRefusal::RequestClosed));
}
