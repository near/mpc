use crate::metrics;
use crate::providers::eddsa::EddsaTaskId;
use crate::providers::EcdsaTaskId;
use borsh::{BorshDeserialize, BorshSerialize};
use cait_sith::ecdsa::triples::TripleGenerationOutput;
use cait_sith::protocol::{internal, Participant};
use k256::Secp256k1;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct ParticipantId(u32);

impl From<Participant> for ParticipantId {
    fn from(participant: Participant) -> Self {
        ParticipantId(participant.into())
    }
}
impl From<mpc_contract::primitives::participants::ParticipantId> for ParticipantId {
    fn from(participant: mpc_contract::primitives::participants::ParticipantId) -> Self {
        ParticipantId(participant.get())
    }
}
impl From<ParticipantId> for Participant {
    fn from(participant_id: ParticipantId) -> Self {
        Participant::from(participant_id.0)
    }
}

impl ParticipantId {
    pub fn raw(self) -> u32 {
        self.0
    }

    pub fn from_raw(raw: u32) -> Self {
        ParticipantId(raw)
    }
}

impl Display for ParticipantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Debug for ParticipantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A batched list of multiple cait-sith protocol messages.
pub type BatchedMessages = Vec<Vec<u8>>;

#[derive(Debug, PartialEq, Eq, BorshSerialize)]
pub struct MpcMessage {
    task_id: MpcTaskId,
    kind: MpcMessageKind,
}

impl borsh::de::BorshDeserialize for MpcMessage {
    fn deserialize_reader<__R: borsh::io::Read>(
        reader: &mut __R,
    ) -> ::core::result::Result<Self, borsh::io::Error> {
        internal::CAIT_SITH_ALLOCATIONS_ALIVE
            .with_label_values(&["MpcMessage"])
            .inc();
        let res = Self {
            task_id: borsh::BorshDeserialize::deserialize_reader(reader)?,
            kind: borsh::BorshDeserialize::deserialize_reader(reader)?,
        };
        metrics::MPC_MESSAGE_ALIVE_BYTES.add(res.size() as i64);
        Ok(res)
    }
}

impl Drop for MpcMessage {
    fn drop(&mut self) {
        internal::CAIT_SITH_ALLOCATIONS_ALIVE
            .with_label_values(&["MpcMessage"])
            .dec();
        metrics::MPC_MESSAGE_ALIVE_BYTES.sub(self.size() as i64);
    }
}

impl MpcMessage {
    pub fn new(task_id: MpcTaskId, kind: MpcMessageKind) -> Self {
        internal::CAIT_SITH_ALLOCATIONS_ALIVE
            .with_label_values(&["MpcMessage"])
            .inc();
        let ret = Self { task_id, kind };
        metrics::MPC_MESSAGE_ALIVE_BYTES.add(ret.size() as i64);
        ret
    }

    pub fn task_id(&self) -> MpcTaskId {
        self.task_id
    }

    pub fn kind(&self) -> &MpcMessageKind {
        &self.kind
    }

    fn size(&self) -> usize {
        let mut total = size_of::<MpcTaskId>();
        match &self.kind {
            MpcMessageKind::Start(msg) => total += msg.participants.len() * 8,
            MpcMessageKind::Computation(msg) => total += msg.iter().map(|v| v.len()).sum::<usize>(),
            MpcMessageKind::Abort(msg) => total += msg.len(),
            MpcMessageKind::Success => {}
        }
        total
    }
}

impl Clone for MpcMessage {
    fn clone(&self) -> Self {
        internal::CAIT_SITH_ALLOCATIONS_ALIVE
            .with_label_values(&["MpcMessage"])
            .inc();
        metrics::MPC_MESSAGE_ALIVE_BYTES.add(self.size() as i64);
        Self {
            task_id: self.task_id,
            kind: self.kind.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum MpcMessageKind {
    Start(MpcStartMessage),
    Computation(Vec<Vec<u8>>),
    Abort(String),
    Success,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MpcStartMessage {
    pub participants: Vec<ParticipantId>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MpcPeerMessage {
    pub from: ParticipantId,
    pub message: MpcMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum MpcTaskId {
    EcdsaTaskId(EcdsaTaskId),
    EddsaTaskId(EddsaTaskId),
}

pub fn participants_from_triples(
    triple0: &TripleGenerationOutput<Secp256k1>,
    triple1: &TripleGenerationOutput<Secp256k1>,
) -> Vec<ParticipantId> {
    triple0
        .1
        .participants
        .iter()
        .copied()
        .filter(|p| triple1.1.participants.contains(p))
        .map(|p| p.into())
        .collect()
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct IndexerHeightMessage {
    pub height: u64,
}

pub struct PeerIndexerHeightMessage {
    pub from: ParticipantId,
    pub message: IndexerHeightMessage,
}

pub enum PeerMessage {
    Mpc(MpcPeerMessage),
    IndexerHeight(PeerIndexerHeightMessage),
}
