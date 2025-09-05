use near_sdk::AccountId;

use crate::primitives::participants::{ParticipantId, ParticipantInfo};

pub struct RecoveryProcess {
    account_id: AccountId,
    participant_id: ParticipantId,
    new_participant_details: ParticipantInfo,
}
