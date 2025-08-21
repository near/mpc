use std::collections::HashMap;

use crate::primitives::ParticipantId;

/// Maps public keys to participant IDs. Used to identify incoming connections.
#[derive(Default)]
pub(crate) struct ParticipantIdentities {
    pub key_to_participant_id: HashMap<near_crypto::PublicKey, ParticipantId>,
}
