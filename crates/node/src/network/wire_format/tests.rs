use super::{
    CKDTaskId, EcdsaTaskId, EddsaTaskId, MpcMessageKind, MpcTaskId, NetworkProtocolVersion, Packet,
    RobustEcdsaTaskId, VerifyForeignTxTaskId,
};
use crate::primitives::{
    ChannelId, ConnectedPeersInfo, IndexerHeightMessage, MpcMessage, MpcStartMessage,
    ParticipantId, UniqueId,
};
use crate::providers::verify_foreign_tx::node_outcome::{
    NoVerdictReason, NodeOutcome, NodeVerdict, RoundOutcome,
};
use crate::providers::verify_foreign_tx::node_outcome_statement::{SignedNodeOutcome, testing};
use borsh::BorshSerialize;
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
    testing::signed_node_outcome(not_found())
}

fn not_found() -> NodeOutcome {
    NodeOutcome::Verdict(NodeVerdict::Negative(
        ForeignTxVerificationNegativeVerdict::TransactionNotFound,
    ))
}

const NEGATIVE_VERDICTS: [ForeignTxVerificationNegativeVerdict; 6] = [
    ForeignTxVerificationNegativeVerdict::TransactionFailed,
    ForeignTxVerificationNegativeVerdict::LogIndexOutOfBounds,
    ForeignTxVerificationNegativeVerdict::TransactionNotFound,
    ForeignTxVerificationNegativeVerdict::AccountNotFound,
    ForeignTxVerificationNegativeVerdict::NonCanonicalBlock,
    ForeignTxVerificationNegativeVerdict::ValuesMismatch,
];

fn round_outcomes() -> Vec<RoundOutcome> {
    std::iter::once(RoundOutcome::Verdict(NodeVerdict::Verified))
        .chain(
            NEGATIVE_VERDICTS
                .into_iter()
                .map(|verdict| RoundOutcome::Verdict(NodeVerdict::Negative(verdict))),
        )
        .chain(std::iter::once(RoundOutcome::Inconclusive))
        .collect()
}

fn sign_outcome_task_id(outcome: RoundOutcome) -> MpcTaskId {
    VerifyForeignTxTaskId::SignOutcome {
        yield_id: YieldId([6; 32]),
        outcome,
        paired_triple_id: uid(2),
    }
    .into()
}

fn sign_verified_task_id() -> MpcTaskId {
    sign_outcome_task_id(RoundOutcome::Verdict(NodeVerdict::Verified))
}

fn mpc_message(kind: MpcMessageKind) -> Packet {
    Packet::MpcMessage(MpcMessage {
        channel_id: ChannelId(uid(1)),
        kind,
    })
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
            Packet::NodeOutcome(signed_node_outcome()),
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
            MpcMessageKind::Evidence(vec![signed_node_outcome()]),
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
        ]),
        rows(
            &round_outcomes()
                .into_iter()
                .map(sign_outcome_task_id)
                .collect::<Vec<_>>(),
        ),
        rows(&[
            testing::signed_node_outcome(NodeOutcome::Verdict(NodeVerdict::Verified)),
            testing::signed_node_outcome(not_found()),
            testing::signed_node_outcome(NodeOutcome::NoVerdict(NoVerdictReason::Transient)),
            testing::signed_node_outcome(NodeOutcome::NoVerdict(
                NoVerdictReason::InspectorsDisagree,
            )),
        ]),
    ]
    .join("\n\n");

    insta::assert_snapshot!(table);
}

#[rstest]
#[case::evidence(MpcMessageKind::Evidence(vec![signed_node_outcome()]))]
#[case::sign_outcome_start(MpcMessageKind::Start(MpcStartMessage {
    task_id: sign_verified_task_id(),
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

#[test]
fn packet__should_decode_a_node_outcome_to_the_outcome_it_encodes() {
    // Given
    let outcome = signed_node_outcome();
    let bytes = borsh::to_vec(&Packet::NodeOutcome(outcome.clone())).unwrap();

    // When
    let decoded: Packet = borsh::from_slice(&bytes).unwrap();

    // Then
    assert_matches!(decoded, Packet::NodeOutcome(decoded) if decoded == outcome);
}

#[rstest]
#[case::node_outcome(
    Packet::NodeOutcome(signed_node_outcome()),
    NetworkProtocolVersion::Nov2026
)]
#[case::evidence(
    mpc_message(MpcMessageKind::Evidence(vec![signed_node_outcome()])),
    NetworkProtocolVersion::Nov2026
)]
#[case::sign_verified_start(
    mpc_message(MpcMessageKind::Start(MpcStartMessage {
        task_id: sign_verified_task_id(),
        participants: vec![ParticipantId::from_raw(5)],
    })),
    NetworkProtocolVersion::Nov2026
)]
#[case::sign_inconclusive_start(
    mpc_message(MpcMessageKind::Start(MpcStartMessage {
        task_id: sign_outcome_task_id(RoundOutcome::Inconclusive),
        participants: vec![ParticipantId::from_raw(5)],
    })),
    NetworkProtocolVersion::Nov2026
)]
#[case::other_start(
    mpc_message(MpcMessageKind::Start(MpcStartMessage {
        task_id: EcdsaTaskId::Signature {
            id: hash(1),
            presignature_id: uid(2),
        }
        .into(),
        participants: vec![ParticipantId::from_raw(5)],
    })),
    NetworkProtocolVersion::Dec2025
)]
#[case::computation(mpc_message(MpcMessageKind::Computation(vec![vec![1]])), NetworkProtocolVersion::Dec2025)]
#[case::abort(mpc_message(MpcMessageKind::Abort("err".to_owned())), NetworkProtocolVersion::Dec2025)]
#[case::success(mpc_message(MpcMessageKind::Success), NetworkProtocolVersion::Dec2025)]
fn packet_min_protocol_version__should_require_nov2026_only_for_v2_foreign_tx_messages(
    #[case] packet: Packet,
    #[case] expected: NetworkProtocolVersion,
) {
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
fn mpc_message_kind_debug__should_show_only_the_number_of_outcomes_in_evidence() {
    // Given
    let kind = MpcMessageKind::Evidence(vec![signed_node_outcome(), signed_node_outcome()]);

    // When
    let debug_output = format!("{kind:?}");

    // Then
    assert_eq!(debug_output, "Evidence([2 outcomes])");
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
