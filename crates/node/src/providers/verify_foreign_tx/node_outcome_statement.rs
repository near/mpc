use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use near_mpc_contract_interface::types::{self as dtos, YieldId};

use crate::config::{ParticipantsConfig, PersistentSecrets};
use crate::primitives::ParticipantId;
use crate::providers::verify_foreign_tx::node_outcome::NodeOutcome;

/// Starts every signed [`NodeOutcomeStatement`], so that a signature over a statement cannot
/// stand for any other message signed with the same key.
const NODE_OUTCOME_STATEMENT_PREFIX: &[u8] = b"near-mpc foreign tx v2 node outcome";

/// A [`SignedNodeOutcome`] whose signature matches the outcome key its signer registered with
/// the contract. It proves nothing else. A consumer still checks that the yield is the one it
/// serves.
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

/// The [`NodeOutcome`] of one node for one V2 foreign transaction request, in the form the node
/// signs.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub(crate) struct NodeOutcomeStatement {
    pub(crate) yield_id: YieldId,
    pub(crate) signer: ParticipantId,
    pub(crate) outcome: NodeOutcome,
}

/// The outcome key of each participant that registered a valid one with the contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutcomePublicKeys(BTreeMap<ParticipantId, VerifyingKey>);

/// The key a node signs its [`NodeOutcomeStatement`]s with. It is independent of the node's TLS
/// key, and peers verify a statement against the [`OutcomePublicKeys`] on chain.
pub(crate) struct NodeOutcomeSigningKey(SigningKey);

#[derive(Debug, thiserror::Error)]
pub(crate) enum NodeOutcomeVerificationError {
    #[error("node outcome signer {0} has no registered outcome key")]
    NoOutcomeKey(ParticipantId),
    #[error("node outcome signature does not match the outcome key of its signer")]
    BadSignature,
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
    // TODO(#5123): verify the node outcomes other nodes send.
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn verify(
        self,
        outcome_keys: &OutcomePublicKeys,
    ) -> Result<VerifiedNodeOutcome, NodeOutcomeVerificationError> {
        let signer = self.statement.signer;
        let signer_key = outcome_keys
            .0
            .get(&signer)
            .ok_or(NodeOutcomeVerificationError::NoOutcomeKey(signer))?;
        signer_key
            .verify_strict(&signed_bytes(&self.statement)?, &self.signature)
            .map_err(|_| NodeOutcomeVerificationError::BadSignature)?;
        Ok(VerifiedNodeOutcome(self))
    }
}

impl OutcomePublicKeys {
    /// Keeps the keys of `participants` only, and drops a key that is not a valid Ed25519
    /// public key, so that its owner's statements do not verify.
    // TODO(#5123): build from the outcome keys the indexer reads.
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn new(participants: &ParticipantsConfig, registered: &dtos::OutcomeKeys) -> Self {
        let keys = participants
            .participants
            .iter()
            .filter_map(|participant| {
                let key = registered.get(&participant.near_account_id)?;
                VerifyingKey::try_from(key)
                    .inspect_err(|error| {
                        tracing::warn!(
                            participant = %participant.id,
                            %error,
                            "ignoring a registered outcome key that is not a valid Ed25519 public key"
                        );
                    })
                    .ok()
                    .map(|key| (participant.id, key))
            })
            .collect();
        Self(keys)
    }
}

impl From<&PersistentSecrets> for NodeOutcomeSigningKey {
    fn from(secrets: &PersistentSecrets) -> Self {
        Self(secrets.outcome_signing_key.clone())
    }
}

impl NodeOutcomeSigningKey {
    // TODO(#5123): sign the node outcome of each request.
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
pub(crate) mod testing {
    use ed25519_dalek::SigningKey;
    use near_mpc_contract_interface::types::YieldId;

    use super::{NodeOutcomeSigningKey, NodeOutcomeStatement, SignedNodeOutcome};
    use crate::primitives::ParticipantId;
    use crate::providers::verify_foreign_tx::node_outcome::NodeOutcome;

    /// A node outcome signed with a fixed key, so its bytes are stable across runs.
    pub(crate) fn signed_node_outcome(outcome: NodeOutcome) -> SignedNodeOutcome {
        NodeOutcomeSigningKey(SigningKey::from_bytes(&[10; 32]))
            .sign(NodeOutcomeStatement {
                yield_id: YieldId([6; 32]),
                signer: ParticipantId::from_raw(7),
                outcome,
            })
            .unwrap()
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::config::{ParticipantInfo, PersistentSecrets};
    use crate::providers::verify_foreign_tx::node_outcome::{NoVerdictReason, NodeVerdict};
    use near_mpc_contract_interface::types::ForeignTxVerificationNegativeVerdict;
    use rstest::rstest;
    use std::assert_matches;

    const SIGNER: ParticipantId = ParticipantId::from_raw(1);
    const OTHER_PARTICIPANT: ParticipantId = ParticipantId::from_raw(2);
    const UNREGISTERED_PARTICIPANT: ParticipantId = ParticipantId::from_raw(3);
    const NON_PARTICIPANT: ParticipantId = ParticipantId::from_raw(4);

    /// Encodes y = 2, and no point on the curve has this y coordinate.
    const INVALID_POINT: [u8; 32] = {
        let mut bytes = [0; 32];
        bytes[0] = 2;
        bytes
    };

    fn seed(participant: ParticipantId) -> u8 {
        u8::try_from(participant.raw()).unwrap()
    }

    fn tls_key(participant: ParticipantId) -> SigningKey {
        SigningKey::from_bytes(&[seed(participant); 32])
    }

    fn outcome_key(participant: ParticipantId) -> SigningKey {
        SigningKey::from_bytes(&[seed(participant) + 0x80; 32])
    }

    fn signing_key(participant: ParticipantId) -> NodeOutcomeSigningKey {
        NodeOutcomeSigningKey::from(&PersistentSecrets {
            p2p_private_key: tls_key(participant),
            near_signer_key: SigningKey::from_bytes(&[0xff; 32]),
            outcome_signing_key: outcome_key(participant),
        })
    }

    fn account(participant: ParticipantId) -> dtos::AccountId {
        format!("p{}.near", participant.raw()).parse().unwrap()
    }

    fn participants() -> ParticipantsConfig {
        let participants = [SIGNER, OTHER_PARTICIPANT, UNREGISTERED_PARTICIPANT]
            .into_iter()
            .map(|id| ParticipantInfo {
                id,
                address: "127.0.0.1".to_string(),
                port: 3000,
                p2p_public_key: tls_key(id).verifying_key(),
                near_account_id: account(id),
            })
            .collect();
        ParticipantsConfig {
            threshold: 2,
            participants,
        }
    }

    fn registered(participants: &[ParticipantId]) -> dtos::OutcomeKeys {
        participants
            .iter()
            .map(|participant| {
                (
                    account(*participant),
                    dtos::Ed25519PublicKey::from(&outcome_key(*participant).verifying_key()),
                )
            })
            .collect::<BTreeMap<_, _>>()
            .into()
    }

    fn outcome_keys() -> OutcomePublicKeys {
        OutcomePublicKeys::new(
            &participants(),
            &registered(&[SIGNER, OTHER_PARTICIPANT, NON_PARTICIPANT]),
        )
    }

    fn statement() -> NodeOutcomeStatement {
        NodeOutcomeStatement {
            yield_id: YieldId([0xab; 32]),
            signer: SIGNER,
            outcome: NodeOutcome::Verdict(NodeVerdict::Negative(
                ForeignTxVerificationNegativeVerdict::TransactionNotFound,
            )),
        }
    }

    #[test]
    fn outcome_public_keys_new__should_map_registered_participants_to_their_outcome_keys() {
        // Given
        let registered = registered(&[SIGNER, OTHER_PARTICIPANT]);

        // When
        let keys = OutcomePublicKeys::new(&participants(), &registered);

        // Then
        assert_eq!(
            keys,
            OutcomePublicKeys(BTreeMap::from([
                (SIGNER, outcome_key(SIGNER).verifying_key()),
                (
                    OTHER_PARTICIPANT,
                    outcome_key(OTHER_PARTICIPANT).verifying_key()
                ),
            ]))
        );
    }

    #[test]
    fn outcome_public_keys_new__should_skip_accounts_that_are_not_participants() {
        // Given
        let registered = registered(&[NON_PARTICIPANT]);

        // When
        let keys = OutcomePublicKeys::new(&participants(), &registered);

        // Then
        assert_eq!(keys, OutcomePublicKeys(BTreeMap::new()));
    }

    #[test]
    fn outcome_public_keys_new__should_drop_a_key_that_is_not_a_valid_point() {
        // Given
        let mut registered = registered(&[SIGNER]);
        registered.insert(
            account(OTHER_PARTICIPANT),
            dtos::Ed25519PublicKey::from(INVALID_POINT),
        );

        // When
        let keys = OutcomePublicKeys::new(&participants(), &registered);

        // Then
        assert_eq!(
            keys,
            OutcomePublicKeys(BTreeMap::from([(
                SIGNER,
                outcome_key(SIGNER).verifying_key()
            )]))
        );
    }

    #[test]
    fn signed_node_outcome__should_verify_against_the_outcome_key_of_its_signer() {
        // Given
        let signed = signing_key(SIGNER).sign(statement()).unwrap();

        // When
        let verified = signed.verify(&outcome_keys()).unwrap();

        // Then
        assert_eq!(verified.statement(), &statement());
    }

    #[test]
    fn signed_node_outcome__should_reject_a_signature_by_the_tls_key_of_its_signer() {
        // Given
        let signed = SignedNodeOutcome {
            statement: statement(),
            signature: tls_key(SIGNER).sign(&signed_bytes(&statement()).unwrap()),
        };

        // When
        let result = signed.verify(&outcome_keys());

        // Then
        assert_matches!(result, Err(NodeOutcomeVerificationError::BadSignature));
    }

    #[test]
    fn signed_node_outcome__should_reject_a_signature_by_another_participant() {
        // Given
        let signed = signing_key(OTHER_PARTICIPANT).sign(statement()).unwrap();

        // When
        let result = signed.verify(&outcome_keys());

        // Then
        assert_matches!(result, Err(NodeOutcomeVerificationError::BadSignature));
    }

    #[rstest]
    #[case::unregistered_participant(UNREGISTERED_PARTICIPANT)]
    #[case::non_participant(NON_PARTICIPANT)]
    fn signed_node_outcome__should_reject_a_signer_without_an_outcome_key(
        #[case] signer: ParticipantId,
    ) {
        // Given
        let statement = NodeOutcomeStatement {
            signer,
            ..statement()
        };
        let signed = signing_key(signer).sign(statement).unwrap();

        // When
        let result = signed.verify(&outcome_keys());

        // Then
        assert_matches!(
            result,
            Err(NodeOutcomeVerificationError::NoOutcomeKey(rejected)) if rejected == signer
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
            decoded.verify(&outcome_keys()).unwrap().statement(),
            &statement()
        );
    }

    #[rstest]
    #[case::yield_id(NodeOutcomeStatement { yield_id: YieldId([0xcd; 32]), ..statement() })]
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
        let result = signed.verify(&outcome_keys());

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
            signature: outcome_key(SIGNER).sign(&bytes),
        };

        // When
        let result = signed.verify(&outcome_keys());

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
