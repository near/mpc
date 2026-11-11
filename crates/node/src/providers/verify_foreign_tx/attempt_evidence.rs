use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use lru::LruCache;
use near_mpc_contract_interface::types::YieldId;
use tokio::sync::Notify;

use crate::config::ParticipantsConfig;
use crate::primitives::ParticipantId;
use crate::providers::verify_foreign_tx::node_outcome_statement::{
    AttemptId, NodeOutcomeVerificationError, SignedNodeOutcome, VerifiedNodeOutcome,
};

/// The number of led attempts whose node outcomes [`AttemptEvidence`] keeps. It drops the
/// attempts it opened first.
const MAX_ATTEMPTS_KEPT: NonZeroUsize = NonZeroUsize::new(1024).unwrap();

/// The signed node outcomes of the V2 attempts this node leads. They are the evidence a leader
/// shows when it asks for an inconclusive. An attempt keeps at most one node outcome per
/// participant, from the moment it reaches this node, also after the attempt ended.
pub(crate) struct AttemptEvidence {
    attempts: Mutex<LruCache<AttemptId, AttemptRecord>>,
    recorded: Notify,
}

struct AttemptRecord {
    attempt: LedAttempt,
    outcomes: BTreeMap<ParticipantId, VerifiedNodeOutcome>,
}

/// A V2 attempt this node leads. The node outcomes of its participants must name its id, its
/// yield and its leader.
#[derive(Clone)]
pub(crate) struct LedAttempt {
    pub(crate) id: AttemptId,
    pub(crate) yield_id: YieldId,
    pub(crate) leader: ParticipantId,
    pub(crate) participants: Vec<ParticipantId>,
    /// The participant set that holds the TLS key each node outcome is verified against.
    pub(crate) keys: Arc<ParticipantsConfig>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum NodeOutcomeRejection {
    #[error("expected exactly one node outcome per message, got {0}")]
    NotExactlyOne(usize),
    #[error("participant {0} is not in the attempt")]
    NotInAttempt(ParticipantId),
    #[error("participant {from} sent a node outcome signed by {signer}")]
    SignedByAnother {
        from: ParticipantId,
        signer: ParticipantId,
    },
    #[error("the node outcome names another leader {0}")]
    OtherLeader(ParticipantId),
    #[error("the node outcome names another attempt")]
    OtherAttempt,
    #[error("the node outcome names another yield")]
    OtherYield,
    #[error(transparent)]
    Verification(#[from] NodeOutcomeVerificationError),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ReceivedNodeOutcomeError {
    #[error("no led attempt {0:?} is kept")]
    UnknownAttempt(AttemptId),
    #[error("a node outcome of participant {0} is already kept")]
    AlreadyKept(ParticipantId),
    #[error(transparent)]
    Rejected(#[from] NodeOutcomeRejection),
}

impl AttemptEvidence {
    pub(crate) fn new() -> Self {
        Self {
            attempts: Mutex::new(LruCache::new(MAX_ATTEMPTS_KEPT)),
            recorded: Notify::new(),
        }
    }

    /// Starts keeping the node outcomes of `attempt`. Call it before the attempt's Start leaves,
    /// so no node outcome arrives before.
    pub(crate) fn open(&self, attempt: LedAttempt) {
        self.attempts.lock().unwrap().put(
            attempt.id,
            AttemptRecord {
                attempt,
                outcomes: BTreeMap::new(),
            },
        );
    }

    /// Keeps the leader's own node outcome.
    pub(crate) fn record(&self, outcome: VerifiedNodeOutcome) {
        let statement = outcome.statement();
        let (attempt, signer) = (statement.attempt, statement.signer);
        if let Some(record) = self.attempts.lock().unwrap().peek_mut(&attempt) {
            record.outcomes.entry(signer).or_insert(outcome);
        }
        self.recorded.notify_waiters();
    }

    /// Keeps a node outcome that `from` sent for `attempt`. A participant that already has one
    /// kept costs no signature check.
    pub(crate) fn record_received(
        &self,
        from: ParticipantId,
        attempt: AttemptId,
        outcomes: Vec<SignedNodeOutcome>,
    ) -> Result<(), ReceivedNodeOutcomeError> {
        let led_attempt = {
            let attempts = self.attempts.lock().unwrap();
            let record = attempts
                .peek(&attempt)
                .ok_or(ReceivedNodeOutcomeError::UnknownAttempt(attempt))?;
            if record.outcomes.contains_key(&from) {
                return Err(ReceivedNodeOutcomeError::AlreadyKept(from));
            }
            record.attempt.clone()
        };
        let outcome = led_attempt.accept(from, outcomes)?;
        self.record(outcome);
        Ok(())
    }

    /// The participants of `attempt`, its leader aside, without a kept node outcome.
    pub(crate) fn silent_followers(&self, attempt: AttemptId) -> BTreeSet<ParticipantId> {
        let attempts = self.attempts.lock().unwrap();
        let Some(record) = attempts.peek(&attempt) else {
            return BTreeSet::new();
        };
        record
            .attempt
            .participants
            .iter()
            .filter(|participant| {
                **participant != record.attempt.leader && !record.outcomes.contains_key(participant)
            })
            .copied()
            .collect()
    }

    /// The node outcomes kept for the attempts at `yield_id`.
    pub(crate) fn outcomes_for(&self, yield_id: YieldId) -> Vec<VerifiedNodeOutcome> {
        self.attempts
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, record)| record.attempt.yield_id == yield_id)
            .flat_map(|(_, record)| record.outcomes.values().cloned())
            .collect()
    }

    /// Returns the first value `find` returns for the node outcomes kept for the attempts at
    /// `yield_id`. `find` runs again on every node outcome this node keeps.
    pub(crate) async fn wait_for<T>(
        &self,
        yield_id: YieldId,
        find: impl Fn(&[VerifiedNodeOutcome]) -> Option<T>,
    ) -> T {
        loop {
            let recorded = self.recorded.notified();
            tokio::pin!(recorded);
            recorded.as_mut().enable();
            if let Some(found) = find(&self.outcomes_for(yield_id)) {
                return found;
            }
            recorded.await;
        }
    }
}

impl LedAttempt {
    /// Checks one node outcomes message that `from` sent for this attempt. Cheap checks come
    /// before the signature check.
    pub(crate) fn accept(
        &self,
        from: ParticipantId,
        outcomes: Vec<SignedNodeOutcome>,
    ) -> Result<VerifiedNodeOutcome, NodeOutcomeRejection> {
        let [outcome] = <[SignedNodeOutcome; 1]>::try_from(outcomes)
            .map_err(|outcomes| NodeOutcomeRejection::NotExactlyOne(outcomes.len()))?;
        let statement = outcome.unverified_statement();
        if !self.participants.contains(&from) {
            return Err(NodeOutcomeRejection::NotInAttempt(from));
        }
        if statement.signer != from {
            return Err(NodeOutcomeRejection::SignedByAnother {
                from,
                signer: statement.signer,
            });
        }
        if statement.leader != self.leader {
            return Err(NodeOutcomeRejection::OtherLeader(statement.leader));
        }
        if statement.attempt != self.id {
            return Err(NodeOutcomeRejection::OtherAttempt);
        }
        if statement.yield_id != self.yield_id {
            return Err(NodeOutcomeRejection::OtherYield);
        }
        Ok(outcome.verify(&self.keys)?)
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::config::{ParticipantInfo, PersistentSecrets};
    use crate::primitives::{ChannelId, UniqueId};
    use crate::providers::verify_foreign_tx::node_outcome::{NodeOutcome, NodeVerdict};
    use crate::providers::verify_foreign_tx::node_outcome_statement::{
        NodeOutcomeSigningKey, NodeOutcomeStatement,
    };
    use ed25519_dalek::SigningKey;
    use rstest::rstest;
    use std::assert_matches;

    const LEADER: ParticipantId = ParticipantId::from_raw(1);
    const FOLLOWER: ParticipantId = ParticipantId::from_raw(2);
    const OUTSIDER: ParticipantId = ParticipantId::from_raw(3);
    const YIELD: YieldId = YieldId([7; 32]);

    fn tls_key(participant: ParticipantId) -> SigningKey {
        SigningKey::from_bytes(&[u8::try_from(participant.raw()).unwrap(); 32])
    }

    fn keys() -> Arc<ParticipantsConfig> {
        let participants = [LEADER, FOLLOWER, OUTSIDER]
            .into_iter()
            .map(|id| ParticipantInfo {
                id,
                address: "127.0.0.1".to_string(),
                port: 3000,
                p2p_public_key: tls_key(id).verifying_key(),
                near_account_id: format!("p{}.near", id.raw()).parse().unwrap(),
            })
            .collect();
        Arc::new(ParticipantsConfig {
            threshold: 2,
            participants,
        })
    }

    fn attempt_id(counter: u32) -> AttemptId {
        AttemptId(ChannelId(UniqueId::new(LEADER, 1_700_000_000, counter)))
    }

    fn led_attempt(counter: u32) -> LedAttempt {
        LedAttempt {
            id: attempt_id(counter),
            yield_id: YIELD,
            leader: LEADER,
            participants: vec![LEADER, FOLLOWER],
            keys: keys(),
        }
    }

    fn statement(signer: ParticipantId) -> NodeOutcomeStatement {
        NodeOutcomeStatement {
            yield_id: YIELD,
            leader: LEADER,
            attempt: attempt_id(1),
            signer,
            outcome: NodeOutcome::Verdict(NodeVerdict::Verified),
        }
    }

    fn signed_by(key_owner: ParticipantId, statement: NodeOutcomeStatement) -> SignedNodeOutcome {
        NodeOutcomeSigningKey::from(&PersistentSecrets {
            p2p_private_key: tls_key(key_owner),
            near_signer_key: SigningKey::from_bytes(&[0xff; 32]),
        })
        .sign(statement)
        .unwrap()
    }

    fn signed(signer: ParticipantId) -> SignedNodeOutcome {
        signed_by(signer, statement(signer))
    }

    #[test]
    fn led_attempt_accept__should_accept_the_outcome_a_participant_signed_for_this_attempt() {
        // Given
        let attempt = led_attempt(1);

        // When
        let accepted = attempt.accept(FOLLOWER, vec![signed(FOLLOWER)]);

        // Then
        assert_eq!(accepted.unwrap().statement(), &statement(FOLLOWER));
    }

    #[rstest]
    #[case::none(vec![])]
    #[case::two(vec![signed(FOLLOWER), signed(FOLLOWER)])]
    fn led_attempt_accept__should_reject_a_message_without_exactly_one_outcome(
        #[case] outcomes: Vec<SignedNodeOutcome>,
    ) {
        // Given
        let attempt = led_attempt(1);

        // When
        let accepted = attempt.accept(FOLLOWER, outcomes);

        // Then
        assert_matches!(accepted, Err(NodeOutcomeRejection::NotExactlyOne(_)));
    }

    #[test]
    fn led_attempt_accept__should_reject_an_outcome_from_outside_the_attempt() {
        // Given
        let attempt = led_attempt(1);

        // When
        let accepted = attempt.accept(OUTSIDER, vec![signed(OUTSIDER)]);

        // Then
        assert_matches!(accepted, Err(NodeOutcomeRejection::NotInAttempt(OUTSIDER)));
    }

    #[test]
    fn led_attempt_accept__should_reject_an_outcome_another_participant_signed() {
        // Given
        let attempt = led_attempt(1);

        // When
        let accepted = attempt.accept(FOLLOWER, vec![signed(LEADER)]);

        // Then
        assert_matches!(
            accepted,
            Err(NodeOutcomeRejection::SignedByAnother {
                from: FOLLOWER,
                signer: LEADER
            })
        );
    }

    #[test]
    fn led_attempt_accept__should_reject_an_outcome_for_another_leader() {
        // Given
        let attempt = led_attempt(1);
        let outcome = signed_by(
            FOLLOWER,
            NodeOutcomeStatement {
                leader: OUTSIDER,
                ..statement(FOLLOWER)
            },
        );

        // When
        let accepted = attempt.accept(FOLLOWER, vec![outcome]);

        // Then
        assert_matches!(accepted, Err(NodeOutcomeRejection::OtherLeader(OUTSIDER)));
    }

    #[test]
    fn led_attempt_accept__should_reject_an_outcome_for_another_attempt() {
        // Given
        let attempt = led_attempt(2);

        // When
        let accepted = attempt.accept(FOLLOWER, vec![signed(FOLLOWER)]);

        // Then
        assert_matches!(accepted, Err(NodeOutcomeRejection::OtherAttempt));
    }

    #[test]
    fn led_attempt_accept__should_reject_an_outcome_for_another_yield() {
        // Given
        let attempt = led_attempt(1);
        let outcome = signed_by(
            FOLLOWER,
            NodeOutcomeStatement {
                yield_id: YieldId([8; 32]),
                ..statement(FOLLOWER)
            },
        );

        // When
        let accepted = attempt.accept(FOLLOWER, vec![outcome]);

        // Then
        assert_matches!(accepted, Err(NodeOutcomeRejection::OtherYield));
    }

    #[test]
    fn led_attempt_accept__should_reject_a_signature_from_another_key() {
        // Given
        let attempt = led_attempt(1);

        // When
        let accepted = attempt.accept(FOLLOWER, vec![signed_by(LEADER, statement(FOLLOWER))]);

        // Then
        assert_matches!(
            accepted,
            Err(NodeOutcomeRejection::Verification(
                NodeOutcomeVerificationError::BadSignature
            ))
        );
    }

    #[test]
    fn attempt_evidence_record_received__should_keep_one_outcome_per_participant() {
        // Given
        let evidence = AttemptEvidence::new();
        evidence.open(led_attempt(1));
        evidence
            .record_received(FOLLOWER, attempt_id(1), vec![signed(FOLLOWER)])
            .unwrap();

        // When
        let second = evidence.record_received(FOLLOWER, attempt_id(1), vec![signed(FOLLOWER)]);

        // Then
        assert_matches!(second, Err(ReceivedNodeOutcomeError::AlreadyKept(FOLLOWER)));
        let kept: Vec<_> = evidence
            .outcomes_for(YIELD)
            .iter()
            .map(|outcome| outcome.statement().clone())
            .collect();
        assert_eq!(kept, vec![statement(FOLLOWER)]);
    }

    #[test]
    fn attempt_evidence_record_received__should_reject_an_attempt_it_does_not_keep() {
        // Given
        let evidence = AttemptEvidence::new();

        // When
        let recorded = evidence.record_received(FOLLOWER, attempt_id(1), vec![signed(FOLLOWER)]);

        // Then
        assert_matches!(recorded, Err(ReceivedNodeOutcomeError::UnknownAttempt(_)));
        assert!(evidence.outcomes_for(YIELD).is_empty());
    }

    #[test]
    fn attempt_evidence_record_received__should_reject_an_outcome_the_attempt_rejects() {
        // Given
        let evidence = AttemptEvidence::new();
        evidence.open(led_attempt(1));

        // When
        let recorded = evidence.record_received(OUTSIDER, attempt_id(1), vec![signed(OUTSIDER)]);

        // Then
        assert_matches!(
            recorded,
            Err(ReceivedNodeOutcomeError::Rejected(
                NodeOutcomeRejection::NotInAttempt(OUTSIDER)
            ))
        );
        assert!(evidence.outcomes_for(YIELD).is_empty());
    }

    #[test]
    fn attempt_evidence_silent_followers__should_name_the_followers_without_a_kept_outcome() {
        // Given
        let evidence = AttemptEvidence::new();
        evidence.open(LedAttempt {
            participants: vec![LEADER, FOLLOWER, OUTSIDER],
            ..led_attempt(1)
        });
        evidence
            .record_received(FOLLOWER, attempt_id(1), vec![signed(FOLLOWER)])
            .unwrap();

        // When
        let silent = evidence.silent_followers(attempt_id(1));

        // Then
        assert_eq!(silent, BTreeSet::from([OUTSIDER]));
    }
}
