use borsh::{BorshDeserialize, BorshSerialize};

use crate::types::CommunicatorPeerId;

pub(crate) const MAX_MESSAGE_LEN: u32 = 64; // todo: adjust
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Messages {
    KEEPALIVE,
    Secrets(String),
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct PeerMessage {
    pub peer_id: CommunicatorPeerId,
    pub message: Messages,
}
