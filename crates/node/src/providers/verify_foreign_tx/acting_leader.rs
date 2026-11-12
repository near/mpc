use std::collections::HashSet;
use std::time::Duration;

use crate::primitives::ParticipantId;
use crate::providers::verify_foreign_tx::VerifyForeignTxProvider;
use crate::requests::queue::{
    RefineEligibleLeaders, eligible_leaders_and_heights, leader_rank, leader_selection_order,
    leader_turn_start,
};
use crate::types::{VerifyForeignTxId, VerifyForeignTxRequestV2};

/// The margin by which a signer accepts a backup leader before its turn. A backup times its
/// turn from its own index time, and that may come this much before the signer's.
const BACKUP_LEADER_EARLY_ACCEPTANCE: Duration = Duration::from_secs(3);

/// A participant that [`VerifyForeignTxProvider::ensure_acting_leader`] accepted as an acting
/// leader of the V2 request [`Self::request`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActingLeader {
    request: VerifyForeignTxId,
    participant: ParticipantId,
}

impl ActingLeader {
    pub(crate) fn request(self) -> VerifyForeignTxId {
        self.request
    }

    pub(crate) fn participant(self) -> ParticipantId {
        self.participant
    }

    #[cfg(test)]
    pub(crate) fn assumed(request: VerifyForeignTxId, participant: ParticipantId) -> Self {
        Self {
            request,
            participant,
        }
    }
}

/// The reasons a signer does not accept a participant as the leader of a V2 signing round.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum LeaderRefusal {
    #[error("the V2 request is not open")]
    RequestClosed,
    #[error("{0} is not an acting leader of the V2 request")]
    NotActing(ParticipantId),
}

impl VerifyForeignTxProvider {
    /// Accepts `leader` only when it is an acting leader of the open `request` in the view of
    /// this node: the first eligible leader of the request, or a backup whose turn has started.
    pub(crate) fn ensure_acting_leader(
        &self,
        request: &VerifyForeignTxRequestV2,
        leader: ParticipantId,
    ) -> Result<ActingLeader, LeaderRefusal> {
        let since_indexed = self
            .v2
            .open_requests
            .time_since_indexed(request.id)
            .ok_or(LeaderRefusal::RequestClosed)?;
        let network = self.v2.network.as_ref();
        let participants = network.all_participant_ids();
        let eligible_leaders = self.new_eligible_leaders_refiner().refine(
            request,
            &eligible_leaders_and_heights(network, &participants, network.my_participant_id())
                .eligible_leaders,
        );
        if is_acting_leader(
            leader,
            &leader_selection_order(&participants, request.id),
            &eligible_leaders,
            since_indexed,
        ) {
            Ok(ActingLeader {
                request: request.id,
                participant: leader,
            })
        } else {
            Err(LeaderRefusal::NotActing(leader))
        }
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
mod tests;
