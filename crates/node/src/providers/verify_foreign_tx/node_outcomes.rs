use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use near_mpc_contract_interface::types::{self as dtos, YieldId};
use tokio::sync::futures::Notified;
use tokio::sync::{Notify, watch};
use tokio::time::{Duration, Instant};

use crate::config::ParticipantsConfig;
use crate::primitives::ParticipantId;
use crate::providers::verify_foreign_tx::node_outcome_statement::{
    NodeOutcomeVerificationError, OutcomePublicKeys, SignedNodeOutcome, VerifiedNodeOutcome,
};

/// The time a node keeps the outcomes of a yield it has not indexed yet.
const UNINDEXED_OUTCOME_LIFETIME: Duration = Duration::from_secs(3);

/// The number of yields this node has not indexed yet that it keeps outcomes for, per sender.
const MAX_UNINDEXED_YIELDS_PER_SENDER: usize = 256;

/// The verified node outcomes of the V2 requests this node knows of, its own included. It keeps
/// one entry per yield and signer, and forgets a yield once its request settles.
///
/// Statements live in memory only, so a node that restarts may sign its outcome again. When the
/// second differs, the signer counts for no outcome.
pub(crate) struct NodeOutcomes {
    state: Mutex<State>,
    changed: Notify,
}

#[derive(Default)]
struct State {
    outcome_keys: Arc<OutcomePublicKeys>,
    indexed: HashMap<YieldId, BTreeMap<ParticipantId, Held>>,
    unindexed: HashMap<ParticipantId, HashMap<YieldId, Unindexed>>,
}

/// The statements of one signer for one yield.
#[derive(Debug, Clone)]
enum Held {
    One(VerifiedNodeOutcome),
    Conflicting(VerifiedNodeOutcome, VerifiedNodeOutcome),
}

struct Unindexed {
    held: Held,
    received_at: Instant,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RejectedNodeOutcome {
    #[error("participant {from} sent a node outcome signed by {signer}")]
    SignedByAnother {
        from: ParticipantId,
        signer: ParticipantId,
    },
    #[error("participant {0} already sent outcomes for too many yields this node has not indexed")]
    TooManyUnindexedYields(ParticipantId),
    #[error(transparent)]
    Verification(#[from] NodeOutcomeVerificationError),
}

impl NodeOutcomes {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(State::default()),
            changed: Notify::new(),
        }
    }

    /// Replaces the keys that statements verify against. Kept statements stay.
    pub(crate) fn set_outcome_keys(&self, outcome_keys: OutcomePublicKeys) {
        self.state.lock().unwrap().outcome_keys = Arc::new(outcome_keys);
    }

    pub(crate) fn outcome_keys(&self) -> Arc<OutcomePublicKeys> {
        self.state.lock().unwrap().outcome_keys.clone()
    }

    /// Keeps a node outcome that `from` sent, once its signature verifies. A copy of a kept
    /// statement costs no signature check.
    pub(crate) fn receive(
        &self,
        from: ParticipantId,
        outcome: SignedNodeOutcome,
    ) -> Result<(), RejectedNodeOutcome> {
        let statement = outcome.unverified_statement();
        let (yield_id, signer) = (statement.yield_id, statement.signer);
        if signer != from {
            return Err(RejectedNodeOutcome::SignedByAnother { from, signer });
        }
        let outcome_keys = {
            let state = self.state.lock().unwrap();
            if state.holds(yield_id, signer, &outcome) {
                return Ok(());
            }
            state.outcome_keys.clone()
        };
        let verified = outcome.verify(&outcome_keys)?;
        self.state.lock().unwrap().keep(verified, Instant::now())?;
        self.changed.notify_waiters();
        Ok(())
    }

    /// Starts counting the outcomes of `yield_ids`, those that arrived before included.
    pub(crate) fn index(&self, yield_ids: impl IntoIterator<Item = YieldId>) {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap();
        for yield_id in yield_ids {
            state.index(yield_id, now);
        }
        drop(state);
        self.changed.notify_waiters();
    }

    /// Drops every outcome of `yield_ids`.
    pub(crate) fn forget(&self, yield_ids: &[YieldId]) {
        let mut state = self.state.lock().unwrap();
        for yield_id in yield_ids {
            state.indexed.remove(yield_id);
            for of_sender in state.unindexed.values_mut() {
                of_sender.remove(yield_id);
            }
        }
    }

    /// The outcomes kept for the indexed `yield_id`: one per signer, two for a signer of
    /// conflicting statements.
    pub(crate) fn outcomes_of(&self, yield_id: YieldId) -> Vec<VerifiedNodeOutcome> {
        let state = self.state.lock().unwrap();
        state
            .indexed
            .get(&yield_id)
            .into_iter()
            .flat_map(BTreeMap::values)
            .flat_map(|held| match held {
                Held::One(outcome) => vec![outcome.clone()],
                Held::Conflicting(first, second) => vec![first.clone(), second.clone()],
            })
            .collect()
    }

    /// Completes after the next change of the kept outcomes. Call [`Notified::enable`] before
    /// reading them, so no change between the read and the wait gets lost.
    pub(crate) fn changed(&self) -> Notified<'_> {
        self.changed.notified()
    }
}

/// Keeps the outcome keys of `node_outcomes` equal to the keys the contract lists for
/// `participants`, built once per change of `registered`. Returns once its sender is gone.
pub(crate) async fn follow_outcome_keys(
    node_outcomes: Arc<NodeOutcomes>,
    participants: ParticipantsConfig,
    mut registered: watch::Receiver<dtos::OutcomeKeys>,
) {
    loop {
        let outcome_keys = OutcomePublicKeys::new(&participants, &registered.borrow_and_update());
        node_outcomes.set_outcome_keys(outcome_keys);
        if registered.changed().await.is_err() {
            return;
        }
    }
}

impl State {
    fn holds(&self, yield_id: YieldId, signer: ParticipantId, outcome: &SignedNodeOutcome) -> bool {
        let held = match self.indexed.get(&yield_id) {
            Some(of_yield) => of_yield.get(&signer),
            None => self
                .unindexed
                .get(&signer)
                .and_then(|of_sender| of_sender.get(&yield_id))
                .map(|unindexed| &unindexed.held),
        };
        held.is_some_and(|held| held.contains(outcome))
    }

    fn keep(
        &mut self,
        outcome: VerifiedNodeOutcome,
        now: Instant,
    ) -> Result<(), RejectedNodeOutcome> {
        let statement = outcome.statement();
        let (yield_id, signer) = (statement.yield_id, statement.signer);
        if let Some(of_yield) = self.indexed.get_mut(&yield_id) {
            merge(of_yield.entry(signer), outcome);
            return Ok(());
        }
        let of_sender = self.unindexed.entry(signer).or_default();
        of_sender.retain(|_, unindexed| !unindexed.expired_at(now));
        if !of_sender.contains_key(&yield_id) && of_sender.len() >= MAX_UNINDEXED_YIELDS_PER_SENDER
        {
            return Err(RejectedNodeOutcome::TooManyUnindexedYields(signer));
        }
        match of_sender.get_mut(&yield_id) {
            Some(unindexed) => unindexed.held = unindexed.held.clone().with(outcome),
            None => {
                of_sender.insert(
                    yield_id,
                    Unindexed {
                        held: Held::One(outcome),
                        received_at: now,
                    },
                );
            }
        }
        Ok(())
    }

    fn index(&mut self, yield_id: YieldId, now: Instant) {
        let mut arrived_before: BTreeMap<ParticipantId, Held> = BTreeMap::new();
        for (sender, of_sender) in &mut self.unindexed {
            if let Some(unindexed) = of_sender.remove(&yield_id)
                && !unindexed.expired_at(now)
            {
                arrived_before.insert(*sender, unindexed.held);
            }
        }
        let of_yield = self.indexed.entry(yield_id).or_default();
        for (signer, held) in arrived_before {
            for outcome in held.into_outcomes() {
                merge(of_yield.entry(signer), outcome);
            }
        }
    }
}

fn merge(
    entry: std::collections::btree_map::Entry<'_, ParticipantId, Held>,
    outcome: VerifiedNodeOutcome,
) {
    use std::collections::btree_map::Entry;
    match entry {
        Entry::Vacant(vacant) => {
            vacant.insert(Held::One(outcome));
        }
        Entry::Occupied(mut occupied) => {
            let held = occupied.get().clone().with(outcome);
            occupied.insert(held);
        }
    }
}

impl Held {
    fn contains(&self, outcome: &SignedNodeOutcome) -> bool {
        match self {
            Self::One(held) => held.signed() == outcome,
            Self::Conflicting(first, second) => {
                first.signed() == outcome || second.signed() == outcome
            }
        }
    }

    /// Adds `outcome` from the same signer. A second, different statement makes the signer
    /// conflicting, and further ones are dropped.
    fn with(self, outcome: VerifiedNodeOutcome) -> Self {
        match self {
            Self::One(held) if held.statement() == outcome.statement() => Self::One(held),
            Self::One(held) => {
                tracing::warn!(
                    first = ?held.statement(),
                    second = ?outcome.statement(),
                    "conflicting statements: a node signed two different outcomes for one yield"
                );
                Self::Conflicting(held, outcome)
            }
            conflicting @ Self::Conflicting(..) => conflicting,
        }
    }

    fn into_outcomes(self) -> Vec<VerifiedNodeOutcome> {
        match self {
            Self::One(outcome) => vec![outcome],
            Self::Conflicting(first, second) => vec![first, second],
        }
    }
}

impl Unindexed {
    fn expired_at(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.received_at) >= UNINDEXED_OUTCOME_LIFETIME
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests;
