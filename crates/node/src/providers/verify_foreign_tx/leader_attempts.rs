use std::collections::BTreeSet;

use crate::network::AbortedByParticipant;
use crate::network::computation::ComputationTimeout;
use crate::primitives::ParticipantId;
use crate::providers::verify_foreign_tx::attempt_evidence::AttemptEvidence;
use crate::providers::verify_foreign_tx::attempt_outcomes::AttemptEnd;
use crate::providers::verify_foreign_tx::node_outcome::NoVerdictReason;
use crate::providers::verify_foreign_tx::node_outcome_statement::AttemptId;

/// The number of attempts one leader makes at a V2 request.
const MAX_ATTEMPTS_PER_LEADER: usize = 3;

/// Leads the V2 attempts at one request: takes the asset of each attempt and runs it.
pub(crate) trait LeadV2Attempt {
    type Asset;
    type Signed;

    /// Waits for the asset of the next attempt, before its Start. A free asset without any of
    /// `avoid` comes first.
    async fn take_asset(&self, avoid: &BTreeSet<ParticipantId>) -> anyhow::Result<Self::Asset>;

    /// Runs one attempt, from its Start to the signature.
    async fn run_attempt(&self, asset: Self::Asset) -> Result<Self::Signed, AttemptFailure>;
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

/// Leads up to [`MAX_ATTEMPTS_PER_LEADER`] attempts at one V2 request and returns the first
/// signature. After a failure other than a disagreement, the leader retries at once. The wait for
/// an asset does not use up an attempt.
pub(crate) async fn lead_attempts<L: LeadV2Attempt>(leader: &L) -> Result<L::Signed, LeaderStop> {
    let mut avoid = BTreeSet::new();
    let mut attempts_left = MAX_ATTEMPTS_PER_LEADER;
    loop {
        let asset = leader
            .take_asset(&avoid)
            .await
            .map_err(LeaderStop::NoAsset)?;
        attempts_left = attempts_left.saturating_sub(1);
        let failure = match leader.run_attempt(asset).await {
            Ok(signed) => return Ok(signed),
            Err(failure) => failure,
        };
        tracing::info!(%failure, attempts_left, "a V2 foreign tx attempt failed");
        // TODO(#5126): start the inconclusive after a disagreement, and once the attempt evidence
        // holds transient errors from s − t + 1 nodes.
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

#[cfg(test)]
#[expect(non_snake_case)]
mod tests;
