use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use near_mpc_contract_interface::types::YieldId;

use crate::config::{ParticipantsConfig, PersistentSecrets};
use crate::primitives::{ChannelId, ParticipantId};
use crate::providers::verify_foreign_tx::node_outcome::NodeOutcome;

/// Starts every signed [`NodeOutcomeStatement`], so that a signature over a statement cannot
/// stand for any other message signed with the same key.
const NODE_OUTCOME_STATEMENT_PREFIX: &[u8] = b"near-mpc foreign tx v2 node outcome";

/// A [`SignedNodeOutcome`] whose signature matches the key that the participant set records for
/// its signer, and whose attempt belongs to the leader it names. It proves nothing else. A
/// consumer still checks that the leader is the node asking, that the yield is the one it serves,
/// and that the signer took part in the attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedNodeOutcome(SignedNodeOutcome);

/// A [`NodeOutcomeStatement`] with its signature, not yet verified. Its Borsh encoding is part of
/// the P2P wire format. That encoding includes [`ForeignTxVerificationNegativeVerdict`] from the
/// contract interface, so a change to that enum is a wire change.
///
/// [`ForeignTxVerificationNegativeVerdict`]: near_mpc_contract_interface::types::ForeignTxVerificationNegativeVerdict
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SignedNodeOutcome {
    statement: NodeOutcomeStatement,
    #[borsh(
        serialize_with = "serialize_signature",
        deserialize_with = "deserialize_signature"
    )]
    signature: Signature,
}

/// The [`NodeOutcome`] of one node in one attempt of a V2 foreign transaction request, in the
/// form the node signs.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub(crate) struct NodeOutcomeStatement {
    pub(crate) yield_id: YieldId,
    pub(crate) leader: ParticipantId,
    pub(crate) attempt: AttemptId,
    pub(crate) signer: ParticipantId,
    pub(crate) outcome: NodeOutcome,
}

/// The [`ChannelId`] the leader opens for the attempt. It names the leader, and the leader picks
/// a new one for each channel. An id repeats only if the leader restarts within the second of an
/// earlier id, or its clock goes back across a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub(crate) struct AttemptId(pub(crate) ChannelId);

/// The key a node signs its [`NodeOutcomeStatement`]s with. It is the node's TLS identity key,
/// so peers verify a statement against the key in the signer's [`ParticipantInfo`].
///
/// [`ParticipantInfo`]: crate::config::ParticipantInfo
pub(crate) struct NodeOutcomeSigningKey(SigningKey);

#[derive(Debug, thiserror::Error)]
pub(crate) enum NodeOutcomeVerificationError {
    #[error("node outcome signer {0} is not a participant")]
    SignerNotParticipant(ParticipantId),
    #[error("node outcome signature does not match the key of its signer")]
    BadSignature,
    #[error("node outcome attempt does not belong to its leader {0}")]
    AttemptOfAnotherLeader(ParticipantId),
    #[error("failed to encode the node outcome statement")]
    Encoding(#[from] std::io::Error),
}

impl VerifiedNodeOutcome {
    // TODO(#5123): read when the leader counts node outcomes.
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn statement(&self) -> &NodeOutcomeStatement {
        &self.0.statement
    }
}

impl SignedNodeOutcome {
    // TODO(#5123): verify the node outcomes of followers.
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn verify(
        self,
        participants: &ParticipantsConfig,
    ) -> Result<VerifiedNodeOutcome, NodeOutcomeVerificationError> {
        let NodeOutcomeStatement { leader, signer, .. } = self.statement;
        let signer_key = NodeOutcomeSigningKey::public_key(participants, signer)
            .ok_or(NodeOutcomeVerificationError::SignerNotParticipant(signer))?;
        signer_key
            .verify_strict(&signed_bytes(&self.statement)?, &self.signature)
            .map_err(|_| NodeOutcomeVerificationError::BadSignature)?;
        if self.statement.attempt.leader() != leader {
            return Err(NodeOutcomeVerificationError::AttemptOfAnotherLeader(leader));
        }
        Ok(VerifiedNodeOutcome(self))
    }
}

impl AttemptId {
    fn leader(self) -> ParticipantId {
        let ChannelId(id) = self.0;
        id.participant_id()
    }
}

impl From<&PersistentSecrets> for NodeOutcomeSigningKey {
    fn from(secrets: &PersistentSecrets) -> Self {
        Self(secrets.p2p_private_key.clone())
    }
}

impl NodeOutcomeSigningKey {
    // TODO(#5123): sign the node outcome of each attempt.
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn sign(
        &self,
        statement: NodeOutcomeStatement,
    ) -> std::io::Result<SignedNodeOutcome> {
        let signature = self.0.sign(&signed_bytes(&statement)?);
        Ok(SignedNodeOutcome {
            statement,
            signature,
        })
    }

    fn public_key(
        participants: &ParticipantsConfig,
        participant: ParticipantId,
    ) -> Option<&VerifyingKey> {
        participants
            .get_info(participant)
            .map(|info| &info.p2p_public_key)
    }
}

fn signed_bytes(statement: &NodeOutcomeStatement) -> std::io::Result<Vec<u8>> {
    let mut bytes = NODE_OUTCOME_STATEMENT_PREFIX.to_vec();
    statement.serialize(&mut bytes)?;
    Ok(bytes)
}

fn serialize_signature<W: borsh::io::Write>(
    signature: &Signature,
    writer: &mut W,
) -> borsh::io::Result<()> {
    signature.to_bytes().serialize(writer)
}

fn deserialize_signature<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Signature> {
    <[u8; Signature::BYTE_SIZE]>::deserialize_reader(reader)
        .map(|bytes| Signature::from_bytes(&bytes))
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::config::{ParticipantInfo, PersistentSecrets};
    use crate::primitives::UniqueId;
    use crate::providers::verify_foreign_tx::node_outcome::{NoVerdictReason, NodeVerdict};
    use near_mpc_contract_interface::types::ForeignTxVerificationNegativeVerdict;
    use rstest::rstest;
    use std::assert_matches;

    const LEADER: ParticipantId = ParticipantId::from_raw(1);
    const SIGNER: ParticipantId = ParticipantId::from_raw(2);
    const OTHER_PARTICIPANT: ParticipantId = ParticipantId::from_raw(3);
    const NON_PARTICIPANT: ParticipantId = ParticipantId::from_raw(4);

    fn tls_key(participant: ParticipantId) -> SigningKey {
        let seed = u8::try_from(participant.raw()).unwrap();
        SigningKey::from_bytes(&[seed; 32])
    }

    fn signing_key(participant: ParticipantId) -> NodeOutcomeSigningKey {
        NodeOutcomeSigningKey::from(&PersistentSecrets {
            p2p_private_key: tls_key(participant),
            near_signer_key: SigningKey::from_bytes(&[0xff; 32]),
        })
    }

    fn participants() -> ParticipantsConfig {
        let participants = [LEADER, SIGNER, OTHER_PARTICIPANT]
            .into_iter()
            .map(|id| ParticipantInfo {
                id,
                address: "127.0.0.1".to_string(),
                port: 3000,
                p2p_public_key: tls_key(id).verifying_key(),
                near_account_id: format!("p{}.near", id.raw()).parse().unwrap(),
            })
            .collect();
        ParticipantsConfig {
            threshold: 2,
            participants,
        }
    }

    fn attempt(counter: u32) -> AttemptId {
        attempt_of(LEADER, counter)
    }

    fn attempt_of(leader: ParticipantId, counter: u32) -> AttemptId {
        AttemptId(ChannelId(UniqueId::new(leader, 1_700_000_000, counter)))
    }

    fn statement() -> NodeOutcomeStatement {
        NodeOutcomeStatement {
            yield_id: YieldId([0xab; 32]),
            leader: LEADER,
            attempt: attempt(0),
            signer: SIGNER,
            outcome: NodeOutcome::Verdict(NodeVerdict::Negative(
                ForeignTxVerificationNegativeVerdict::TransactionNotFound,
            )),
        }
    }

    #[test]
    fn signed_node_outcome__should_verify_against_the_key_of_its_signer() {
        // Given
        let signed = signing_key(SIGNER).sign(statement()).unwrap();

        // When
        let verified = signed.verify(&participants()).unwrap();

        // Then
        assert_eq!(verified.statement(), &statement());
    }

    #[test]
    fn signed_node_outcome__should_reject_a_signature_by_another_participant() {
        // Given
        let signed = signing_key(OTHER_PARTICIPANT).sign(statement()).unwrap();

        // When
        let result = signed.verify(&participants());

        // Then
        assert_matches!(result, Err(NodeOutcomeVerificationError::BadSignature));
    }

    #[test]
    fn signed_node_outcome__should_reject_a_signer_that_is_not_a_participant() {
        // Given
        let statement = NodeOutcomeStatement {
            signer: NON_PARTICIPANT,
            ..statement()
        };
        let signed = signing_key(NON_PARTICIPANT).sign(statement).unwrap();

        // When
        let result = signed.verify(&participants());

        // Then
        assert_matches!(
            result,
            Err(NodeOutcomeVerificationError::SignerNotParticipant(
                NON_PARTICIPANT
            ))
        );
    }

    #[test]
    fn signed_node_outcome__should_reject_an_attempt_of_another_leader() {
        // Given
        let statement = NodeOutcomeStatement {
            attempt: attempt_of(OTHER_PARTICIPANT, 0),
            ..statement()
        };
        let signed = signing_key(SIGNER).sign(statement).unwrap();

        // When
        let result = signed.verify(&participants());

        // Then
        assert_matches!(
            result,
            Err(NodeOutcomeVerificationError::AttemptOfAnotherLeader(LEADER))
        );
    }

    #[test]
    fn signed_node_outcome__should_still_verify_after_a_borsh_round_trip() {
        // Given
        let signed = signing_key(SIGNER).sign(statement()).unwrap();

        // When
        let decoded: SignedNodeOutcome =
            borsh::from_slice(&borsh::to_vec(&signed).unwrap()).unwrap();

        // Then
        assert_eq!(decoded, signed);
        assert_eq!(
            decoded.verify(&participants()).unwrap().statement(),
            &statement()
        );
    }

    #[rstest]
    #[case::yield_id(NodeOutcomeStatement { yield_id: YieldId([0xcd; 32]), ..statement() })]
    #[case::leader(NodeOutcomeStatement { leader: OTHER_PARTICIPANT, ..statement() })]
    #[case::attempt(NodeOutcomeStatement { attempt: attempt(1), ..statement() })]
    #[case::signer(NodeOutcomeStatement { signer: OTHER_PARTICIPANT, ..statement() })]
    #[case::verdict(NodeOutcomeStatement {
        outcome: NodeOutcome::Verdict(NodeVerdict::Verified),
        ..statement()
    })]
    #[case::no_verdict(NodeOutcomeStatement {
        outcome: NodeOutcome::NoVerdict(NoVerdictReason::Transient),
        ..statement()
    })]
    fn signed_node_outcome__should_reject_a_signature_over_another_statement(
        #[case] other_statement: NodeOutcomeStatement,
    ) {
        // Given
        let signature = signing_key(SIGNER).sign(statement()).unwrap().signature;
        let signed = SignedNodeOutcome {
            statement: other_statement,
            signature,
        };

        // When
        let result = signed.verify(&participants());

        // Then
        assert_matches!(result, Err(NodeOutcomeVerificationError::BadSignature));
    }

    #[rstest]
    #[case::without_prefix(borsh::to_vec(&statement()).unwrap())]
    #[case::other_prefix(
        [b"near-mpc foreign tx v2 node outcomes".as_slice(), &borsh::to_vec(&statement()).unwrap()]
            .concat()
    )]
    fn signed_node_outcome__should_reject_a_signature_over_other_bytes(#[case] bytes: Vec<u8>) {
        // Given
        let signed = SignedNodeOutcome {
            statement: statement(),
            signature: tls_key(SIGNER).sign(&bytes),
        };

        // When
        let result = signed.verify(&participants());

        // Then
        assert_matches!(result, Err(NodeOutcomeVerificationError::BadSignature));
    }

    #[rstest]
    #[case::verified("signed_bytes_verified", NodeOutcome::Verdict(NodeVerdict::Verified))]
    #[case::transaction_failed(
        "signed_bytes_transaction_failed",
        NodeOutcome::Verdict(NodeVerdict::Negative(
            ForeignTxVerificationNegativeVerdict::TransactionFailed
        ))
    )]
    #[case::log_index_out_of_bounds(
        "signed_bytes_log_index_out_of_bounds",
        NodeOutcome::Verdict(NodeVerdict::Negative(
            ForeignTxVerificationNegativeVerdict::LogIndexOutOfBounds
        ))
    )]
    #[case::transaction_not_found(
        "signed_bytes_transaction_not_found",
        NodeOutcome::Verdict(NodeVerdict::Negative(
            ForeignTxVerificationNegativeVerdict::TransactionNotFound
        ))
    )]
    #[case::account_not_found(
        "signed_bytes_account_not_found",
        NodeOutcome::Verdict(NodeVerdict::Negative(
            ForeignTxVerificationNegativeVerdict::AccountNotFound
        ))
    )]
    #[case::non_canonical_block(
        "signed_bytes_non_canonical_block",
        NodeOutcome::Verdict(NodeVerdict::Negative(
            ForeignTxVerificationNegativeVerdict::NonCanonicalBlock
        ))
    )]
    #[case::values_mismatch(
        "signed_bytes_values_mismatch",
        NodeOutcome::Verdict(NodeVerdict::Negative(
            ForeignTxVerificationNegativeVerdict::ValuesMismatch
        ))
    )]
    #[case::transient(
        "signed_bytes_transient",
        NodeOutcome::NoVerdict(NoVerdictReason::Transient)
    )]
    #[case::inspectors_disagree(
        "signed_bytes_inspectors_disagree",
        NodeOutcome::NoVerdict(NoVerdictReason::InspectorsDisagree)
    )]
    fn signed_bytes__should_keep_their_encoding(
        #[case] snapshot: &str,
        #[case] outcome: NodeOutcome,
    ) {
        // Given
        let statement = NodeOutcomeStatement {
            outcome,
            ..statement()
        };

        // When
        let bytes = signed_bytes(&statement).unwrap();

        // Then
        insta::assert_snapshot!(snapshot, hex::encode(bytes));
    }
}
