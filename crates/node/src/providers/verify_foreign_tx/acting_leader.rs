use std::collections::HashSet;
use std::time::Duration;

use anyhow::Context;

use crate::primitives::ParticipantId;
use crate::providers::verify_foreign_tx::VerifyForeignTxProvider;
use crate::requests::queue::{
    RefineEligibleLeaders, eligible_leaders_and_heights, leader_rank, leader_selection_order,
    leader_turn_start,
};
use crate::types::VerifyForeignTxRequestV2;

/// The margin by which a signer accepts a backup leader before its turn. A backup times its
/// turn from its own index time, and that may come this much before the signer's.
const BACKUP_LEADER_EARLY_ACCEPTANCE: Duration = Duration::from_secs(3);

impl VerifyForeignTxProvider {
    /// Fails unless `leader` is an acting leader of the open `request` in the view of this node:
    /// the first eligible leader of the request, or a backup whose turn has started.
    pub(crate) fn ensure_acting_leader(
        &self,
        request: &VerifyForeignTxRequestV2,
        leader: ParticipantId,
    ) -> anyhow::Result<()> {
        let since_indexed = self
            .v2
            .open_requests
            .time_since_indexed(request.id)
            .context("the V2 request is not open")?;
        let network = self.v2.network.as_ref();
        let participants = network.all_participant_ids();
        let eligible_leaders = self.new_eligible_leaders_refiner().refine(
            request,
            &eligible_leaders_and_heights(network, &participants, network.my_participant_id())
                .eligible_leaders,
        );
        anyhow::ensure!(
            is_acting_leader(
                leader,
                &leader_selection_order(&participants, request.id),
                &eligible_leaders,
                since_indexed,
            ),
            "{leader} is not an acting leader of the V2 request"
        );
        Ok(())
    }
}

fn is_acting_leader(
    candidate: ParticipantId,
    leader_selection_order: &[ParticipantId],
    eligible_leaders: &HashSet<ParticipantId>,
    since_indexed: Duration,
) -> bool {
    leader_rank(leader_selection_order, eligible_leaders, candidate)
        .and_then(leader_turn_start)
        .is_some_and(|turn_start| {
            since_indexed.saturating_add(BACKUP_LEADER_EARLY_ACCEPTANCE)
                >= turn_start.unsigned_abs()
        })
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::requests::queue::{LEADER_FAILOVER_INTERVAL, MAX_LEADER_FAILOVER_DEPTH};

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
}
