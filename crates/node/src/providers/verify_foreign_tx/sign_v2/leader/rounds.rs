use std::collections::BTreeSet;

use super::StopLeading;
use crate::network::computation::ComputationTimeout;
use crate::network::{AbortedByParticipant, UnexpectedMessage};
use crate::primitives::ParticipantId;
use crate::providers::verify_foreign_tx::open_requests::MAX_ROUNDS_PER_LEADER;

/// Runs the signing rounds of this node, as the leader of one request.
pub(crate) trait LeadSigningRounds {
    type Asset;
    type Signed;

    /// Waits for a fresh asset for a retry. A free asset without any of `avoid` comes first.
    async fn take_retry_asset(
        &self,
        avoid: &BTreeSet<ParticipantId>,
    ) -> Result<Self::Asset, StopLeading>;

    /// Runs one round with `asset`, from its Start to the signature.
    async fn run_round(&self, asset: Self::Asset) -> Result<Self::Signed, RoundFailure>;
}

/// The reason a leader ends its signing rounds for a request without a signature. The request
/// then times out unless another leader answers it.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RoundsEnd {
    #[error(transparent)]
    Stopped(#[from] StopLeading),
    #[error("this node cannot run a V2 signing round: {0:#}")]
    Local(anyhow::Error),
    #[error("all {MAX_ROUNDS_PER_LEADER} V2 signing rounds failed, the last one with: {0}")]
    Exhausted(RoundFailure),
}

/// The reason a signing round failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RoundFailure {
    /// A signer refused the round, or failed after it joined.
    #[error(transparent)]
    Refused(AbortedByParticipant),
    /// A signer sent a message the round does not expect.
    #[error(transparent)]
    Unexpected(UnexpectedMessage),
    #[error("the round ran past its deadline, silent signers: {silent:?}")]
    DeadlineExceeded { silent: BTreeSet<ParticipantId> },
    /// A failure that names no signer, for example shares that do not combine to a signature.
    #[error(transparent)]
    Unattributed(anyhow::Error),
    /// A failure of this node. Another round would fail the same way.
    #[error("this node cannot run the round: {0:#}")]
    Local(anyhow::Error),
    /// This node stopped leading before the round started.
    #[error(transparent)]
    Stopped(StopLeading),
}

impl RoundFailure {
    /// Sorts the error that ended a round. `silent` holds the signers that sent this node nothing
    /// in the round.
    pub(crate) fn new(error: anyhow::Error, silent: BTreeSet<ParticipantId>) -> Self {
        let error = match error.downcast::<AbortedByParticipant>() {
            Ok(aborted) => return Self::Refused(aborted),
            Err(error) => error,
        };
        match error.downcast::<UnexpectedMessage>() {
            Ok(unexpected) => Self::Unexpected(unexpected),
            Err(error) if error.is::<ComputationTimeout>() => Self::DeadlineExceeded { silent },
            Err(error) => Self::Unattributed(error),
        }
    }

    /// The signers that failed the round. A retry avoids them when it can.
    fn failed_signers(&self) -> BTreeSet<ParticipantId> {
        match self {
            Self::Refused(aborted) => BTreeSet::from([aborted.participant]),
            Self::Unexpected(unexpected) => BTreeSet::from([unexpected.participant]),
            Self::DeadlineExceeded { silent } => silent.clone(),
            Self::Unattributed(_) | Self::Local(_) | Self::Stopped(_) => BTreeSet::new(),
        }
    }
}

/// Runs up to [`MAX_ROUNDS_PER_LEADER`] signing rounds, the first one with `first_asset`, and
/// returns the first signature. Each retry takes a fresh asset, without the signers that failed
/// an earlier round when one is free. The wait for an asset uses up no round.
pub(crate) async fn lead_rounds<L: LeadSigningRounds>(
    leader: &L,
    first_asset: L::Asset,
) -> Result<L::Signed, RoundsEnd> {
    let mut asset = first_asset;
    let mut avoid = BTreeSet::new();
    let mut rounds_left = MAX_ROUNDS_PER_LEADER;
    loop {
        rounds_left = rounds_left.saturating_sub(1);
        let failure = match leader.run_round(asset).await {
            Ok(signed) => return Ok(signed),
            Err(RoundFailure::Local(error)) => return Err(RoundsEnd::Local(error)),
            Err(RoundFailure::Stopped(stop)) => return Err(RoundsEnd::Stopped(stop)),
            Err(failure) => failure,
        };
        tracing::info!(%failure, rounds_left, "a V2 signing round failed");
        if rounds_left == 0 {
            return Err(RoundsEnd::Exhausted(failure));
        }
        avoid.extend(failure.failed_signers());
        asset = leader.take_retry_asset(&avoid).await?;
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests;
