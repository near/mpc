use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct ParticipantId(pub u32);

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MpcMessage {
    pub task_id: MpcTaskId,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MpcPeerMessage {
    pub from: ParticipantId,
    pub message: MpcMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum MpcTaskId {
    Generating,
    Triple(u64),
}
