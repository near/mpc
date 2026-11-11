//! Types whose Borsh encoding is part of the P2P wire format.
//!
//! A discriminant, once assigned, is never reused or given to another variant. Retiring one is
//! only safe once no deployed node can still send it, which the handshake's
//! [`NetworkProtocolVersion`] check decides.

use crate::primitives::{
    ConnectedPeersInfo, IndexerHeightMessage, MpcMessage, MpcStartMessage, UniqueId,
};
use crate::protocol_version::NetworkProtocolVersion;
use crate::providers::verify_foreign_tx::V2_FOREIGN_TX_MIN_PROTOCOL_VERSION;
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
                    MpcTaskId::VerifyForeignTxTaskId(VerifyForeignTxTaskId::Inconclusive { .. }),
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
            MpcMessageKind::NodeOutcomes(outcomes) => {
                f.debug_tuple("NodeOutcomes").field(outcomes).finish()
            }
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
}

impl From<VerifyForeignTxTaskId> for MpcTaskId {
    fn from(value: VerifyForeignTxTaskId) -> Self {
        MpcTaskId::VerifyForeignTxTaskId(value)
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{
        CKDTaskId, EcdsaTaskId, EddsaTaskId, MpcMessageKind, MpcTaskId, NetworkProtocolVersion,
        Packet, RobustEcdsaTaskId, VerifyForeignTxTaskId,
    };
    use crate::config::PersistentSecrets;
    use crate::primitives::{
        ChannelId, ConnectedPeersInfo, IndexerHeightMessage, MpcMessage, MpcStartMessage,
        ParticipantId, UniqueId,
    };
    use crate::providers::verify_foreign_tx::node_outcome::{NodeOutcome, NodeVerdict};
    use crate::providers::verify_foreign_tx::node_outcome_statement::{
        self, NodeOutcomeSigningKey, NodeOutcomeStatement, SignedNodeOutcome,
    };
    use borsh::BorshSerialize;
    use ed25519_dalek::SigningKey;
    use mpc_primitives::domain::DomainId;
    use mpc_primitives::{AttemptId, EpochId};
    use near_indexer_primitives::CryptoHash;
    use near_mpc_contract_interface::types::{
        ForeignTxVerificationNegativeVerdict, KeyEventId, YieldId,
    };
    use rstest::rstest;
    use std::assert_matches;
    use std::collections::BTreeMap;
    use std::fmt::Debug;

    fn uid(counter: u32) -> UniqueId {
        UniqueId::new(ParticipantId::from_raw(0), 1, counter)
    }

    fn hash(byte: u8) -> CryptoHash {
        CryptoHash([byte; 32])
    }

    fn key_event() -> KeyEventId {
        KeyEventId::new(EpochId::new(1), DomainId(2), AttemptId(3))
    }

    fn signed_node_outcome() -> SignedNodeOutcome {
        let signing_key = NodeOutcomeSigningKey::from(&PersistentSecrets {
            p2p_private_key: SigningKey::from_bytes(&[8; 32]),
            near_signer_key: SigningKey::from_bytes(&[9; 32]),
        });
        signing_key
            .sign(NodeOutcomeStatement {
                yield_id: YieldId([6; 32]),
                leader: ParticipantId::from_raw(5),
                attempt: node_outcome_statement::AttemptId(ChannelId(UniqueId::new(
                    ParticipantId::from_raw(5),
                    1,
                    1,
                ))),
                signer: ParticipantId::from_raw(7),
                outcome: NodeOutcome::Verdict(NodeVerdict::Negative(
                    ForeignTxVerificationNegativeVerdict::TransactionNotFound,
                )),
            })
            .unwrap()
    }

    fn inconclusive_task_id() -> MpcTaskId {
        VerifyForeignTxTaskId::Inconclusive {
            yield_id: YieldId([6; 32]),
            paired_triple_id: uid(2),
        }
        .into()
    }

    /// Fixed inputs are chosen so that neighbouring fields encode to visibly distinct bytes.
    fn rows(values: &[impl BorshSerialize + Debug]) -> String {
        values
            .iter()
            .map(|value| {
                let hex = borsh::to_vec(value)
                    .unwrap()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                format!("{value:?} => {hex}")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Every value that crosses the wire, with the bytes it encodes to. A changed byte is a
    /// breaking wire change; a new line is an append.
    #[test]
    fn wire_format__should_stay_stable() {
        let table = [
            rows(&[
                Packet::Ping,
                Packet::MpcMessage(MpcMessage {
                    channel_id: ChannelId(uid(1)),
                    kind: MpcMessageKind::Success,
                }),
                Packet::IndexerHeight(IndexerHeightMessage { height: 4 }),
                Packet::ConnectedPeersInfo(ConnectedPeersInfo {
                    peers: BTreeMap::from([
                        (ParticipantId::from_raw(5), 10),
                        (ParticipantId::from_raw(7), 20),
                    ]),
                }),
            ]),
            rows(&[
                MpcMessageKind::Start(MpcStartMessage {
                    task_id: EcdsaTaskId::ManyTriples {
                        start: uid(1),
                        count: 64,
                    }
                    .into(),
                    participants: vec![ParticipantId::from_raw(5)],
                }),
                MpcMessageKind::Computation(vec![vec![1, 2, 3]]),
                MpcMessageKind::Abort("err".to_owned()),
                MpcMessageKind::Success,
                MpcMessageKind::NodeOutcomes(vec![signed_node_outcome()]),
            ]),
            rows(&[
                EcdsaTaskId::KeyGeneration {
                    key_event: key_event(),
                }
                .into(),
                EcdsaTaskId::KeyResharing {
                    key_event: key_event(),
                }
                .into(),
                EcdsaTaskId::ManyTriples {
                    start: uid(1),
                    count: 64,
                }
                .into(),
                EcdsaTaskId::Presignature {
                    id: uid(1),
                    domain_id: DomainId(2),
                    paired_triple_id: uid(3),
                }
                .into(),
                EcdsaTaskId::Signature {
                    id: hash(1),
                    presignature_id: uid(2),
                }
                .into(),
                EcdsaTaskId::OnlinePresignSignature {
                    id: hash(1),
                    paired_triple_id: uid(2),
                }
                .into(),
                EddsaTaskId::KeyGeneration {
                    key_event: key_event(),
                }
                .into(),
                EddsaTaskId::KeyResharing {
                    key_event: key_event(),
                }
                .into(),
                EddsaTaskId::Signature { id: hash(1) }.into(),
                CKDTaskId::KeyGeneration {
                    key_event: key_event(),
                }
                .into(),
                CKDTaskId::KeyResharing {
                    key_event: key_event(),
                }
                .into(),
                CKDTaskId::Ckd { id: hash(1) }.into(),
                RobustEcdsaTaskId::KeyGeneration {
                    key_event: key_event(),
                }
                .into(),
                RobustEcdsaTaskId::KeyResharing {
                    key_event: key_event(),
                }
                .into(),
                RobustEcdsaTaskId::Signature { id: hash(1) }.into(),
                MpcTaskId::from(VerifyForeignTxTaskId::VerifyForeignTx {
                    id: hash(1),
                    presignature_id: uid(2),
                }),
                MpcTaskId::from(VerifyForeignTxTaskId::VerifyForeignTxOnlinePresign {
                    id: hash(1),
                    paired_triple_id: uid(2),
                }),
                inconclusive_task_id(),
            ]),
        ]
        .join("\n\n");

        insta::assert_snapshot!(table);
    }

    #[rstest]
    #[case::node_outcomes(MpcMessageKind::NodeOutcomes(vec![signed_node_outcome()]))]
    #[case::inconclusive_start(MpcMessageKind::Start(MpcStartMessage {
        task_id: inconclusive_task_id(),
        participants: vec![ParticipantId::from_raw(5), ParticipantId::from_raw(7)],
    }))]
    fn packet__should_decode_a_v2_foreign_tx_message_to_the_message_it_encodes(
        #[case] kind: MpcMessageKind,
    ) {
        // Given
        let message = MpcMessage {
            channel_id: ChannelId(uid(1)),
            kind,
        };
        let bytes = borsh::to_vec(&Packet::MpcMessage(message.clone())).unwrap();

        // When
        let decoded: Packet = borsh::from_slice(&bytes).unwrap();

        // Then
        assert_matches!(decoded, Packet::MpcMessage(decoded) if decoded == message);
    }

    #[rstest]
    #[case::node_outcomes(MpcMessageKind::NodeOutcomes(vec![signed_node_outcome()]), NetworkProtocolVersion::Nov2026)]
    #[case::inconclusive_start(
        MpcMessageKind::Start(MpcStartMessage {
            task_id: inconclusive_task_id(),
            participants: vec![ParticipantId::from_raw(5)],
        }),
        NetworkProtocolVersion::Nov2026
    )]
    #[case::other_start(
        MpcMessageKind::Start(MpcStartMessage {
            task_id: VerifyForeignTxTaskId::VerifyForeignTxOnlinePresign {
                id: hash(1),
                paired_triple_id: uid(2),
            }
            .into(),
            participants: vec![ParticipantId::from_raw(5)],
        }),
        NetworkProtocolVersion::Dec2025
    )]
    #[case::computation(MpcMessageKind::Computation(vec![vec![1]]), NetworkProtocolVersion::Dec2025)]
    #[case::abort(MpcMessageKind::Abort("err".to_owned()), NetworkProtocolVersion::Dec2025)]
    #[case::success(MpcMessageKind::Success, NetworkProtocolVersion::Dec2025)]
    fn packet_min_protocol_version__should_require_nov2026_only_for_v2_foreign_tx_messages(
        #[case] kind: MpcMessageKind,
        #[case] expected: NetworkProtocolVersion,
    ) {
        // Given
        let packet = Packet::MpcMessage(MpcMessage {
            channel_id: ChannelId(uid(1)),
            kind,
        });

        // When
        let version = packet.min_protocol_version();

        // Then
        assert_eq!(version, expected);
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
