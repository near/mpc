//! Types whose Borsh encoding is part of the P2P wire format.
//!
//! Every enum here sets `#[borsh(use_discriminant = true)]` and spells its discriminants out, so
//! peers agree on the numbers rather than on declaration order. A number, once assigned, is never
//! reused or given to another variant. Appending is always safe. Reordering variants leaves the
//! wire untouched, but makes the next free number harder to spot, so keep them in numeric order.
//! Retiring a variant is allowed once no deployed node can still send it; the handshake's
//! [`NetworkProtocolVersion`](crate::protocol_version::NetworkProtocolVersion) check is what
//! rules those nodes out.

use crate::primitives::{IndexerHeightMessage, MpcMessage, MpcStartMessage, UniqueId};
use crate::types::{CKDId, SignatureId, VerifyForeignTxId};
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_primitives::domain::DomainId;
use near_mpc_contract_interface::types::KeyEventId;
use std::fmt::Debug;

#[derive(BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum Packet {
    Ping = 0,
    MpcMessage(MpcMessage) = 1,
    IndexerHeight(IndexerHeightMessage) = 2,
}

#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum MpcMessageKind {
    Start(MpcStartMessage) = 0,
    Computation(Vec<Vec<u8>>) = 1,
    Abort(String) = 2,
    Success = 3,
}

impl MpcMessageKind {
    pub fn variant_name(&self) -> &'static str {
        match self {
            MpcMessageKind::Start(_) => "Start",
            MpcMessageKind::Computation(_) => "Computation",
            MpcMessageKind::Abort(_) => "Abort",
            MpcMessageKind::Success => "Success",
        }
    }
}

/// Redacts the raw bytes in Computation messages.
/// These bytes contain serialized protocol round data (commitments, encrypted shares, proofs)
/// which must not be leaked to logs.
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
        }
    }
}

/// An encoded task id carries two discriminants: this one, then the provider's.
#[expect(
    clippy::enum_variant_names,
    reason = "each variant is named after the per-provider task id it wraps"
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
    Presignature {
        id: UniqueId,
        domain_id: DomainId,
        paired_triple_id: UniqueId,
    } = 3,
    Signature {
        id: SignatureId,
        presignature_id: UniqueId,
    } = 4,
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
    KeyGeneration {
        key_event: KeyEventId,
    } = 0,
    KeyResharing {
        key_event: KeyEventId,
    } = 1,
    Presignature {
        id: UniqueId,
        domain_id: DomainId,
    } = 2,
    Signature {
        id: SignatureId,
        presignature_id: UniqueId,
    } = 3,
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
    VerifyForeignTx {
        id: VerifyForeignTxId,
        presignature_id: UniqueId,
    } = 0,
}

impl From<VerifyForeignTxTaskId> for MpcTaskId {
    fn from(value: VerifyForeignTxTaskId) -> Self {
        MpcTaskId::VerifyForeignTxTaskId(value)
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::primitives::{ChannelId, ParticipantId};
    use mpc_primitives::{AttemptId, EpochId};
    use near_indexer_primitives::CryptoHash;

    fn uid() -> UniqueId {
        UniqueId::new(ParticipantId::from_raw(0), 1, 0)
    }

    fn key_event() -> KeyEventId {
        KeyEventId::new(EpochId::new(0), DomainId(0), AttemptId(0))
    }

    fn wire_prefix(value: &impl BorshSerialize, bytes: usize) -> String {
        borsh::to_vec(value).unwrap()[..bytes]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn task_id_prefix(task_id: impl Into<MpcTaskId>) -> String {
        wire_prefix(&task_id.into(), 2)
    }

    fn start_message() -> MpcStartMessage {
        MpcStartMessage {
            task_id: EcdsaTaskId::ManyTriples {
                start: uid(),
                count: 64,
            }
            .into(),
            participants: Vec::new(),
        }
    }

    /// Every variant that crosses the wire, with the discriminant bytes it encodes to. A changed
    /// byte is a breaking wire change; a new line is an append.
    #[test]
    fn wire_format__should_keep_borsh_discriminants_stable() {
        let rows = [
            ("Packet::Ping", wire_prefix(&Packet::Ping, 1)),
            (
                "Packet::MpcMessage",
                wire_prefix(
                    &Packet::MpcMessage(MpcMessage {
                        channel_id: ChannelId(uid()),
                        kind: MpcMessageKind::Success,
                    }),
                    1,
                ),
            ),
            (
                "Packet::IndexerHeight",
                wire_prefix(
                    &Packet::IndexerHeight(IndexerHeightMessage { height: 0 }),
                    1,
                ),
            ),
            (
                "MpcMessageKind::Start",
                wire_prefix(&MpcMessageKind::Start(start_message()), 1),
            ),
            (
                "MpcMessageKind::Computation",
                wire_prefix(&MpcMessageKind::Computation(Vec::new()), 1),
            ),
            (
                "MpcMessageKind::Abort",
                wire_prefix(&MpcMessageKind::Abort(String::new()), 1),
            ),
            (
                "MpcMessageKind::Success",
                wire_prefix(&MpcMessageKind::Success, 1),
            ),
            (
                "MpcTaskId::EcdsaTaskId(KeyGeneration)",
                task_id_prefix(EcdsaTaskId::KeyGeneration {
                    key_event: key_event(),
                }),
            ),
            (
                "MpcTaskId::EcdsaTaskId(KeyResharing)",
                task_id_prefix(EcdsaTaskId::KeyResharing {
                    key_event: key_event(),
                }),
            ),
            (
                "MpcTaskId::EcdsaTaskId(ManyTriples)",
                task_id_prefix(EcdsaTaskId::ManyTriples {
                    start: uid(),
                    count: 64,
                }),
            ),
            (
                "MpcTaskId::EcdsaTaskId(Presignature)",
                task_id_prefix(EcdsaTaskId::Presignature {
                    id: uid(),
                    domain_id: DomainId(0),
                    paired_triple_id: uid(),
                }),
            ),
            (
                "MpcTaskId::EcdsaTaskId(Signature)",
                task_id_prefix(EcdsaTaskId::Signature {
                    id: CryptoHash::default(),
                    presignature_id: uid(),
                }),
            ),
            (
                "MpcTaskId::EddsaTaskId(KeyGeneration)",
                task_id_prefix(EddsaTaskId::KeyGeneration {
                    key_event: key_event(),
                }),
            ),
            (
                "MpcTaskId::EddsaTaskId(KeyResharing)",
                task_id_prefix(EddsaTaskId::KeyResharing {
                    key_event: key_event(),
                }),
            ),
            (
                "MpcTaskId::EddsaTaskId(Signature)",
                task_id_prefix(EddsaTaskId::Signature {
                    id: CryptoHash::default(),
                }),
            ),
            (
                "MpcTaskId::CKDTaskId(KeyGeneration)",
                task_id_prefix(CKDTaskId::KeyGeneration {
                    key_event: key_event(),
                }),
            ),
            (
                "MpcTaskId::CKDTaskId(KeyResharing)",
                task_id_prefix(CKDTaskId::KeyResharing {
                    key_event: key_event(),
                }),
            ),
            (
                "MpcTaskId::CKDTaskId(Ckd)",
                task_id_prefix(CKDTaskId::Ckd {
                    id: CryptoHash::default(),
                }),
            ),
            (
                "MpcTaskId::RobustEcdsaTaskId(KeyGeneration)",
                task_id_prefix(RobustEcdsaTaskId::KeyGeneration {
                    key_event: key_event(),
                }),
            ),
            (
                "MpcTaskId::RobustEcdsaTaskId(KeyResharing)",
                task_id_prefix(RobustEcdsaTaskId::KeyResharing {
                    key_event: key_event(),
                }),
            ),
            (
                "MpcTaskId::RobustEcdsaTaskId(Presignature)",
                task_id_prefix(RobustEcdsaTaskId::Presignature {
                    id: uid(),
                    domain_id: DomainId(0),
                }),
            ),
            (
                "MpcTaskId::RobustEcdsaTaskId(Signature)",
                task_id_prefix(RobustEcdsaTaskId::Signature {
                    id: CryptoHash::default(),
                    presignature_id: uid(),
                }),
            ),
            (
                "MpcTaskId::VerifyForeignTxTaskId(VerifyForeignTx)",
                task_id_prefix(VerifyForeignTxTaskId::VerifyForeignTx {
                    id: CryptoHash::default(),
                    presignature_id: uid(),
                }),
            ),
        ];

        let table = rows
            .into_iter()
            .map(|(variant, bytes)| format!("{variant:<52} {bytes}"))
            .collect::<Vec<_>>()
            .join("\n");

        insta::assert_snapshot!(table);
    }

    #[test]
    fn mpc_message_kind_debug__should_redact_computation_payload() {
        // given
        let secret_data = b"SECRET_SHARE_DATA_THAT_MUST_NOT_LEAK".to_vec();
        let kind = MpcMessageKind::Computation(vec![secret_data]);

        // when
        let debug_output = format!("{:?}", kind);

        // then
        assert!(
            !debug_output.contains("SECRET_SHARE_DATA"),
            "Debug output must not contain raw computation bytes, got: {}",
            debug_output
        );
        assert!(
            debug_output.contains("Computation"),
            "Debug output should identify the message kind, got: {}",
            debug_output
        );
        assert!(
            debug_output.contains("1 chunks"),
            "Debug output should show chunk count, got: {}",
            debug_output
        );
    }

    #[test]
    fn mpc_message_kind_debug__should_show_chunk_count_and_total_bytes() {
        // given
        let kind = MpcMessageKind::Computation(vec![vec![0u8; 100], vec![0u8; 200], vec![0u8; 50]]);

        // when
        let debug_output = format!("{:?}", kind);

        // then
        assert!(
            debug_output.contains("3 chunks"),
            "Debug output should show 3 chunks, got: {}",
            debug_output
        );
        assert!(
            debug_output.contains("350 bytes"),
            "Debug output should show 350 total bytes, got: {}",
            debug_output
        );
    }

    #[test]
    fn mpc_message_kind_debug__should_show_non_sensitive_variants_normally() {
        // given
        let start = MpcMessageKind::Start(MpcStartMessage {
            task_id: MpcTaskId::EcdsaTaskId(EcdsaTaskId::ManyTriples {
                start: UniqueId::new(ParticipantId::from_raw(0), 42, 0),
                count: 1,
            }),
            participants: vec![ParticipantId::from_raw(0)],
        });
        let abort = MpcMessageKind::Abort("some error".into());
        let success = MpcMessageKind::Success;

        // when
        let start_debug = format!("{:?}", start);
        let abort_debug = format!("{:?}", abort);
        let success_debug = format!("{:?}", success);

        // then
        assert!(start_debug.contains("Start"), "got: {}", start_debug);
        assert!(
            abort_debug.contains("some error"),
            "Abort debug should show the error string, got: {}",
            abort_debug
        );
        assert_eq!(success_debug, "Success");
    }
}
