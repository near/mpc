use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use near_mpc_contract_interface::types::YieldId;
use tokio::sync::Notify;

use crate::config::ParticipantsConfig;
use crate::primitives::ParticipantId;
use crate::providers::verify_foreign_tx::node_outcome_statement::{
    AttemptId, NodeOutcomeVerificationError, SignedNodeOutcome, VerifiedNodeOutcome,
};

/// The number of led attempts per yield whose node outcomes [`AttemptEvidence`] keeps, above the
/// ten attempts a leader makes at one request. It drops the attempts it opened first.
const MAX_ATTEMPTS_KEPT_PER_YIELD: usize = 16;

/// The signed node outcomes of the V2 attempts this node leads. They are the evidence a leader
/// shows when it asks for an inconclusive. An attempt keeps at most one node outcome per
/// participant, from the moment it reaches this node, also after the attempt ended.
///
/// The bound is per yield, so many requests cannot push out the evidence of another open
/// request. [`Self::forget`] drops the evidence of a request that closed.
pub(crate) struct AttemptEvidence {
    attempts: Mutex<KeptAttempts>,
    recorded: Notify,
}

#[derive(Default)]
struct KeptAttempts {
    records: HashMap<AttemptId, AttemptRecord>,
    /// The kept attempts of each yield, oldest first.
    by_yield: HashMap<YieldId, VecDeque<AttemptId>>,
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
pub(crate) enum ReceivedNodeOutcomeError {
    #[error("no led attempt {0:?} is kept")]
    UnknownAttempt(AttemptId),
    #[error("a node outcome of participant {0} is already kept")]
    AlreadyKept(ParticipantId),
    #[error(transparent)]
    Rejected(#[from] NodeOutcomeRejection),
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

impl AttemptEvidence {
    pub(crate) fn new() -> Self {
        Self {
            attempts: Mutex::new(KeptAttempts::default()),
            recorded: Notify::new(),
        }
    }

    /// Starts keeping the node outcomes of `attempt`. Call it before the attempt's Start leaves,
    /// so no node outcome arrives before.
    pub(crate) fn open(&self, attempt: LedAttempt) {
        self.attempts.lock().unwrap().open(attempt);
    }

    /// Drops the evidence of the requests at `yield_ids`.
    pub(crate) fn forget(&self, yield_ids: &[YieldId]) {
        let mut attempts = self.attempts.lock().unwrap();
        for yield_id in yield_ids {
            attempts.forget(yield_id);
        }
    }

    /// Keeps the leader's own node outcome.
    pub(crate) fn record(&self, outcome: VerifiedNodeOutcome) {
        let statement = outcome.statement();
        let (attempt, signer) = (statement.attempt, statement.signer);
        if let Some(record) = self.attempts.lock().unwrap().records.get_mut(&attempt) {
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
                .records
                .get(&attempt)
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

    /// The node outcomes kept for the attempts at `yield_id`.
    // TODO(#5126): read as the evidence of an inconclusive.
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn outcomes_for(&self, yield_id: YieldId) -> Vec<VerifiedNodeOutcome> {
        let attempts = self.attempts.lock().unwrap();
        attempts
            .by_yield
            .get(&yield_id)
            .into_iter()
            .flatten()
            .filter_map(|id| attempts.records.get(id))
            .flat_map(|record| record.outcomes.values().cloned())
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn attempts_kept_for(&self, yield_id: YieldId) -> usize {
        self.attempts
            .lock()
            .unwrap()
            .by_yield
            .get(&yield_id)
            .map_or(0, VecDeque::len)
    }

    /// Returns once the attempts at `yield_id` keep at least `count` node outcomes.
    // TODO(#5126): wait for enough evidence of transient errors.
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) async fn wait_for_outcomes(&self, yield_id: YieldId, count: usize) {
        loop {
            let recorded = self.recorded.notified();
            tokio::pin!(recorded);
            recorded.as_mut().enable();
            if self.outcomes_for(yield_id).len() >= count {
                return;
            }
            recorded.await;
        }
    }
}

impl KeptAttempts {
    fn open(&mut self, attempt: LedAttempt) {
        let of_yield = self.by_yield.entry(attempt.yield_id).or_default();
        of_yield.push_back(attempt.id);
        if of_yield.len() > MAX_ATTEMPTS_KEPT_PER_YIELD
            && let Some(oldest) = of_yield.pop_front()
        {
            self.records.remove(&oldest);
        }
        self.records.insert(
            attempt.id,
            AttemptRecord {
                attempt,
                outcomes: BTreeMap::new(),
            },
        );
    }

    fn forget(&mut self, yield_id: &YieldId) {
        for id in self.by_yield.remove(yield_id).into_iter().flatten() {
            self.records.remove(&id);
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
mod tests;
