//! Types whose Borsh encoding is part of the P2P wire format.
//!
//! A discriminant, once assigned, is never reused or given to another variant. Retiring one is
//! only safe once no deployed node can still send it, which the handshake's
//! [`NetworkProtocolVersion`] check decides.

use crate::primitives::{
    ConnectedPeersInfo, IndexerHeightMessage, MpcMessage, MpcStartMessage, UniqueId,
};
use crate::protocol_version::{NetworkProtocolVersion, V2_FOREIGN_TX_MIN_PROTOCOL_VERSION};
use crate::providers::verify_foreign_tx::node_outcome_statement::SignedNodeOutcome;
use crate::types::{CKDId, SignatureId, VerifyForeignTxId};
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_primitives::domain::DomainId;
use near_mpc_contract_interface::types::{KeyEventId, YieldId};
use std::fmt::Debug;

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum Packet {
    Ping = 0,
    MpcMessage(MpcMessage) = 1,
    IndexerHeight(IndexerHeightMessage) = 2,
    ConnectedPeersInfo(ConnectedPeersInfo) = 3,
}

impl Packet {
    /// Lowest handshake version that can parse this packet.
    pub fn min_protocol_version(&self) -> NetworkProtocolVersion {
        match self {
            Packet::MpcMessage(message) => message.kind.min_protocol_version(),
            Packet::Ping | Packet::IndexerHeight(_) => NetworkProtocolVersion::Dec2025,
            Packet::ConnectedPeersInfo(_) => NetworkProtocolVersion::Oct2026,
        }
    }
}

#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum MpcMessageKind {
    Start(MpcStartMessage) = 0,
    Computation(Vec<Vec<u8>>) = 1,
    Abort(String) = 2,
    Success = 3,
    /// Signed node outcomes of a V2 foreign tx request. A follower sends its own outcome of an
    /// attempt before its share, and also after the attempt ended. The leader of a
    /// [`VerifyForeignTxTaskId::Inconclusive`] round sends its evidence right after the Start.
    NodeOutcomes(Vec<SignedNodeOutcome>) = 4,
}

impl MpcMessageKind {
    pub fn variant_name(&self) -> &'static str {
        match self {
            MpcMessageKind::Start(_) => "Start",
            MpcMessageKind::Computation(_) => "Computation",
            MpcMessageKind::Abort(_) => "Abort",
            MpcMessageKind::Success => "Success",
            MpcMessageKind::NodeOutcomes(_) => "NodeOutcomes",
        }
    }

    fn min_protocol_version(&self) -> NetworkProtocolVersion {
        match self {
            MpcMessageKind::Start(MpcStartMessage {
                task_id:
                    MpcTaskId::VerifyForeignTxTaskId(
                        VerifyForeignTxTaskId::Inconclusive { .. }
                        | VerifyForeignTxTaskId::VerifyForeignTxV2 { .. },
                    ),
                ..
            })
            | MpcMessageKind::NodeOutcomes(_) => V2_FOREIGN_TX_MIN_PROTOCOL_VERSION,
            MpcMessageKind::Start(_)
            | MpcMessageKind::Computation(_)
            | MpcMessageKind::Abort(_)
            | MpcMessageKind::Success => NetworkProtocolVersion::Dec2025,
        }
    }
}

/// Redacts the raw bytes in Computation messages.
/// These bytes contain serialized protocol round data (commitments, encrypted shares, proofs)
/// which must not be leaked to logs. NodeOutcomes shows only its length, because a peer can fill a
/// whole frame with outcomes and every received message is logged.
impl Debug for MpcMessageKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MpcMessageKind::Start(msg) => f.debug_tuple("Start").field(msg).finish(),
            MpcMessageKind::Computation(chunks) => f
                .debug_tuple("Computation")
                .field(&format_args!(
                    "[{} chunks, {} bytes]",
                    chunks.len(),
                    chunks.iter().map(|c| c.len()).sum::<usize>()
                ))
                .finish(),
            MpcMessageKind::Abort(err) => f.debug_tuple("Abort").field(err).finish(),
            MpcMessageKind::Success => write!(f, "Success"),
            MpcMessageKind::NodeOutcomes(outcomes) => f
                .debug_tuple("NodeOutcomes")
                .field(&format_args!("[{} outcomes]", outcomes.len()))
                .finish(),
        }
    }
}

#[expect(
    clippy::enum_variant_names,
    reason = "each variant is named after the task id type it wraps"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum MpcTaskId {
    EcdsaTaskId(EcdsaTaskId) = 0,
    EddsaTaskId(EddsaTaskId) = 1,
    CKDTaskId(CKDTaskId) = 2,
    RobustEcdsaTaskId(RobustEcdsaTaskId) = 3,
    VerifyForeignTxTaskId(VerifyForeignTxTaskId) = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum EcdsaTaskId {
    KeyGeneration {
        key_event: KeyEventId,
    } = 0,
    KeyResharing {
        key_event: KeyEventId,
    } = 1,
    ManyTriples {
        start: UniqueId,
        count: u32,
    } = 2,
    /// Retired with the stored presignatures, and only decoded: a peer that predates the
    /// retirement still sends it, and a [`Packet`] that fails to decode closes the whole
    /// connection rather than failing just this computation.
    // TODO(#4999): remove once every node runs a release without stored presignatures.
    Presignature {
        id: UniqueId,
        domain_id: DomainId,
        paired_triple_id: UniqueId,
    } = 3,
    /// Retired and only decoded, as [`Self::Presignature`].
    // TODO(#4999): remove once every node runs a release without stored presignatures.
    Signature {
        id: SignatureId,
        presignature_id: UniqueId,
    } = 4,
    OnlinePresignSignature {
        id: SignatureId,
        paired_triple_id: UniqueId,
    } = 5,
}

impl From<EcdsaTaskId> for MpcTaskId {
    fn from(val: EcdsaTaskId) -> Self {
        MpcTaskId::EcdsaTaskId(val)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum EddsaTaskId {
    KeyGeneration { key_event: KeyEventId } = 0,
    KeyResharing { key_event: KeyEventId } = 1,
    Signature { id: SignatureId } = 2,
}

impl From<EddsaTaskId> for MpcTaskId {
    fn from(val: EddsaTaskId) -> Self {
        MpcTaskId::EddsaTaskId(val)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum CKDTaskId {
    KeyGeneration { key_event: KeyEventId } = 0,
    KeyResharing { key_event: KeyEventId } = 1,
    Ckd { id: CKDId } = 2,
}

impl From<CKDTaskId> for MpcTaskId {
    fn from(value: CKDTaskId) -> Self {
        MpcTaskId::CKDTaskId(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum RobustEcdsaTaskId {
    KeyGeneration { key_event: KeyEventId } = 0,
    KeyResharing { key_event: KeyEventId } = 1,
    Signature { id: SignatureId } = 2,
}

impl From<RobustEcdsaTaskId> for MpcTaskId {
    fn from(val: RobustEcdsaTaskId) -> Self {
        MpcTaskId::RobustEcdsaTaskId(val)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum VerifyForeignTxTaskId {
    /// Retired and only decoded, as [`EcdsaTaskId::Presignature`].
    // TODO(#4999): remove once every node runs a release without stored presignatures.
    VerifyForeignTx {
        id: VerifyForeignTxId,
        presignature_id: UniqueId,
    } = 0,
    // TODO(#4793): rename back to `VerifyForeignTx` once the stored-presignature variant is gone.
    VerifyForeignTxOnlinePresign {
        id: VerifyForeignTxId,
        paired_triple_id: UniqueId,
    } = 1,
    /// A round that signs an inconclusive outcome for the V2 request waiting on `yield_id`.
    /// Each round uses its own triple pair, so `paired_triple_id` makes the id unique per round.
    Inconclusive {
        yield_id: YieldId,
        paired_triple_id: UniqueId,
    } = 2,
    /// An attempt at a V2 request: each node inspects the transaction and signs its node outcome,
    /// and the shares follow only if every node finds the same verdict.
    VerifyForeignTxV2 {
        id: VerifyForeignTxId,
        paired_triple_id: UniqueId,
    } = 3,
}

impl From<VerifyForeignTxTaskId> for MpcTaskId {
    fn from(value: VerifyForeignTxTaskId) -> Self {
        MpcTaskId::VerifyForeignTxTaskId(value)
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests;
