use std::collections::BTreeSet;

use futures::FutureExt as _;

use crate::network::AbortedByParticipant;
use crate::network::computation::ComputationTimeout;
use crate::primitives::ParticipantId;
use crate::providers::verify_foreign_tx::attempt_evidence::AttemptEvidence;
use crate::providers::verify_foreign_tx::attempt_outcomes::AttemptEnd;
use crate::providers::verify_foreign_tx::node_outcome::NoVerdictReason;
use crate::providers::verify_foreign_tx::node_outcome_statement::AttemptId;
use crate::providers::verify_foreign_tx::{
    MAX_ATTEMPTS_PER_LEADER, MAX_INCONCLUSIVE_ROUNDS_PER_LEADER,
};

/// Leads one V2 request: takes the asset of each attempt or inconclusive round and runs it.
pub(crate) trait LeadV2Request {
    type Asset;
    type Signed;
    type Evidence;

    /// Waits for the asset of the next attempt, before its Start. A free asset without any of
    /// `avoid` comes first.
    async fn take_attempt_asset(
        &self,
        avoid: &BTreeSet<ParticipantId>,
    ) -> anyhow::Result<Self::Asset>;

    /// Runs one attempt, from its Start to the signature.
    async fn run_attempt(&self, asset: Self::Asset) -> Result<Self::Signed, AttemptFailure>;

    /// Returns once the node outcomes of the attempts prove a cause for an inconclusive.
    async fn wait_for_inconclusive_evidence(&self) -> Self::Evidence;

    /// Waits for the asset of the next inconclusive round, before its Start. A free asset
    /// without any of `avoid` comes first.
    async fn take_round_asset(
        &self,
        avoid: &BTreeSet<ParticipantId>,
    ) -> anyhow::Result<Self::Asset>;

    /// Runs one inconclusive round that shows `evidence`, from its Start to the signature.
    async fn run_inconclusive_round(
        &self,
        asset: Self::Asset,
        evidence: &Self::Evidence,
    ) -> anyhow::Result<Self::Signed>;
}

/// The reason a leader stops leading a V2 request without a signature. The request then times out
/// unless another leader answers it.
#[derive(Debug, thiserror::Error)]
pub(crate) enum LeaderStop {
    #[error("no asset for the next V2 attempt: {0:#}")]
    NoAsset(anyhow::Error),
    #[error("the nodes disagree: {0}")]
    Disagreement(AttemptEnd),
    #[error("all {MAX_ATTEMPTS_PER_LEADER} V2 attempts failed, the last one with: {0}")]
    AttemptsExhausted(AttemptFailure),
    #[error(
        "all {MAX_INCONCLUSIVE_ROUNDS_PER_LEADER} inconclusive rounds failed, the last one with: \
         {0:#}"
    )]
    RoundsExhausted(anyhow::Error),
}

/// The reason a V2 attempt failed. It decides the leader's next step.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AttemptFailure {
    /// Two nodes found different verdicts, or the inspectors of one node disagree.
    #[error(transparent)]
    Disagreement(AttemptEnd),
    #[error("participant {participant} reached no verdict because of transient errors")]
    Transient { participant: ParticipantId },
    /// A follower refused the attempt, or failed after it joined.
    #[error(transparent)]
    Aborted(AbortedByParticipant),
    /// The attempt ran past its deadline. `silent` holds the followers without a node outcome.
    #[error("the attempt ran past its deadline, silent followers: {silent:?}")]
    DeadlineExceeded { silent: BTreeSet<ParticipantId> },
    /// Any other problem within the cluster, for example a share that does not combine.
    #[error(transparent)]
    Cluster(anyhow::Error),
}

impl AttemptFailure {
    /// Sorts the error that ended `attempt`. [`AttemptEvidence`] tells the silent followers apart.
    pub(crate) fn new(
        error: anyhow::Error,
        attempt: AttemptId,
        evidence: &AttemptEvidence,
    ) -> Self {
        let error = match error.downcast::<AttemptEnd>() {
            Ok(end) => return end.into(),
            Err(error) => error,
        };
        let error = match error.downcast::<AbortedByParticipant>() {
            Ok(aborted) => return Self::Aborted(aborted),
            Err(error) => error,
        };
        if error.is::<ComputationTimeout>() {
            return Self::DeadlineExceeded {
                silent: evidence.silent_followers(attempt),
            };
        }
        Self::Cluster(error)
    }
}

impl From<AttemptEnd> for AttemptFailure {
    fn from(end: AttemptEnd) -> Self {
        match end {
            AttemptEnd::NoVerdict {
                participant,
                reason: NoVerdictReason::Transient,
            } => Self::Transient { participant },
            AttemptEnd::NoVerdict {
                reason: NoVerdictReason::InspectorsDisagree,
                ..
            }
            | AttemptEnd::VerdictsDiffer { .. } => Self::Disagreement(end),
        }
    }
}

/// Leads one V2 request and returns the first signature. The leader runs attempts, see
/// [`lead_attempts`], until the node outcomes of its attempts prove a cause for an inconclusive.
/// It then runs inconclusive rounds instead, see [`lead_inconclusive_rounds`].
pub(crate) async fn lead_request<L: LeadV2Request>(leader: &L) -> Result<L::Signed, LeaderStop> {
    let attempts_stop = tokio::select! {
        biased;
        evidence = leader.wait_for_inconclusive_evidence() => {
            return lead_inconclusive_rounds(leader, &evidence).await;
        }
        led = lead_attempts(leader) => match led {
            Ok(signed) => return Ok(signed),
            Err(stop) => stop,
        },
    };
    match leader.wait_for_inconclusive_evidence().now_or_never() {
        Some(evidence) => lead_inconclusive_rounds(leader, &evidence).await,
        None => Err(attempts_stop),
    }
}

/// Leads up to [`MAX_ATTEMPTS_PER_LEADER`] attempts at one V2 request and returns the first
/// signature. After a failure other than a disagreement, the leader retries at once. The wait for
/// an asset does not use up an attempt.
async fn lead_attempts<L: LeadV2Request>(leader: &L) -> Result<L::Signed, LeaderStop> {
    let mut avoid = BTreeSet::new();
    let mut attempts_left = MAX_ATTEMPTS_PER_LEADER;
    loop {
        let asset = leader
            .take_attempt_asset(&avoid)
            .await
            .map_err(LeaderStop::NoAsset)?;
        attempts_left = attempts_left.saturating_sub(1);
        let failure = match leader.run_attempt(asset).await {
            Ok(signed) => return Ok(signed),
            Err(failure) => failure,
        };
        tracing::info!(%failure, attempts_left, "a V2 foreign tx attempt failed");
        let next_avoid = match &failure {
            AttemptFailure::Disagreement(end) => return Err(LeaderStop::Disagreement(*end)),
            AttemptFailure::Transient { participant } => BTreeSet::from([*participant]),
            AttemptFailure::Aborted(aborted) => BTreeSet::from([aborted.participant]),
            AttemptFailure::DeadlineExceeded { silent } => silent.clone(),
            AttemptFailure::Cluster(_) => BTreeSet::new(),
        };
        if attempts_left == 0 {
            return Err(LeaderStop::AttemptsExhausted(failure));
        }
        avoid = next_avoid;
    }
}

/// Leads up to [`MAX_INCONCLUSIVE_ROUNDS_PER_LEADER`] inconclusive rounds that show `evidence`,
/// and returns the first signature. After a failure the leader retries at once, with an asset
/// without a follower that refused. The wait for an asset does not use up a round.
async fn lead_inconclusive_rounds<L: LeadV2Request>(
    leader: &L,
    evidence: &L::Evidence,
) -> Result<L::Signed, LeaderStop> {
    let mut avoid = BTreeSet::new();
    let mut rounds_left = MAX_INCONCLUSIVE_ROUNDS_PER_LEADER;
    loop {
        let asset = leader
            .take_round_asset(&avoid)
            .await
            .map_err(LeaderStop::NoAsset)?;
        rounds_left = rounds_left.saturating_sub(1);
        let error = match leader.run_inconclusive_round(asset, evidence).await {
            Ok(signed) => return Ok(signed),
            Err(error) => error,
        };
        tracing::info!(error = %format!("{error:#}"), rounds_left, "an inconclusive round failed");
        if rounds_left == 0 {
            return Err(LeaderStop::RoundsExhausted(error));
        }
        avoid = error
            .downcast_ref::<AbortedByParticipant>()
            .map(|aborted| BTreeSet::from([aborted.participant]))
            .unwrap_or_default();
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests;
