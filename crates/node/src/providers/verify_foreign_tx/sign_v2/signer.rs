use std::collections::BTreeSet;

use anyhow::Context;
use near_mpc_bounded_collections::BoundedVec;
use near_mpc_contract_interface::types::{
    self as dtos, ECDSA_PAYLOAD_SIZE_BYTES, Payload, Tweak, YieldId,
};
use tokio::time::{Duration, Instant, timeout_at};

use super::ROUND_DEADLINE;
use crate::network::NetworkTaskChannel;
use crate::primitives::{ParticipantId, UniqueId};
use crate::providers::verify_foreign_tx::VerifyForeignTxProvider;
use crate::providers::verify_foreign_tx::acting_leader::{ActingLeader, LeaderRefusal};
use crate::providers::verify_foreign_tx::counting_rule::{Decision, Tally};
use crate::providers::verify_foreign_tx::node_outcome::{NodeVerdict, RoundOutcome};
use crate::providers::verify_foreign_tx::node_outcome_statement::{
    NodeOutcomeVerificationError, OutcomePublicKeys, SignedNodeOutcome, VerifiedNodeOutcome,
};
use crate::providers::verify_foreign_tx::open_requests::JoinRoundRefusal;
use crate::types::{SignatureRequest, VerifyForeignTxRequestV2};

/// The time a signer waits for its own indexer to report the request of a Start, and for the
/// leader's evidence.
const ROUND_SETUP_WAIT: Duration = Duration::from_secs(3);

/// The reasons a signer refuses a V2 signing round.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RoundRefusal {
    #[error(transparent)]
    Leader(LeaderRefusal),
    #[error("the evidence holds {statements} statements, more than the {max} a round needs")]
    TooManyStatements { statements: usize, max: usize },
    #[error("the evidence holds a statement for another yield")]
    OtherYield,
    #[error("the evidence holds a statement that does not verify")]
    Unverified(#[from] NodeOutcomeVerificationError),
    #[error("the evidence holds no statement of this node")]
    WithoutOwnStatement,
    #[error("this node did not sign {0:?}, the verdict of the round")]
    NotABacker(NodeVerdict),
    #[error("{backers} supporters signed {verdict:?}, below the signing threshold {threshold}")]
    BelowThreshold {
        verdict: NodeVerdict,
        backers: usize,
        threshold: usize,
    },
    #[error(
        "a verdict can still reach the signing threshold, so the evidence proves no inconclusive"
    )]
    VerdictCanReachThreshold,
    #[error("the evidence holds no single outcome of round participant {0}")]
    ParticipantNotHeard(ParticipantId),
    #[error(transparent)]
    Join(JoinRoundRefusal),
}

/// The values a signer checks the evidence of a round against.
struct EvidenceCheck<'a> {
    me: ParticipantId,
    yield_id: YieldId,
    outcome: RoundOutcome,
    /// The participants of the round, this node and the leader included.
    participants: &'a [ParticipantId],
    outcome_keys: &'a OutcomePublicKeys,
    supporters: &'a BTreeSet<ParticipantId>,
    threshold: usize,
}

impl VerifyForeignTxProvider {
    /// Joins a V2 signing round when the request is open, the sender is an acting leader of it
    /// in the view of this node, the evidence meets the counting rule, and this node joined
    /// fewer than [`MAX_ROUNDS_PER_LEADER`] rounds of that leader for the request. Otherwise it
    /// refuses with the network abort.
    ///
    /// [`MAX_ROUNDS_PER_LEADER`]: crate::providers::verify_foreign_tx::open_requests::MAX_ROUNDS_PER_LEADER
    pub(crate) async fn make_sign_outcome_follower(
        &self,
        mut channel: NetworkTaskChannel,
        yield_id: YieldId,
        outcome: RoundOutcome,
        paired_triple_id: UniqueId,
    ) -> anyhow::Result<()> {
        let sender = channel.sender();
        let request = match self.check_round(&mut channel, yield_id, outcome).await {
            Ok(checked) => checked,
            Err(refusal) => {
                sender.communicate_failure(&refusal);
                return Err(refusal.context("refused a V2 signing round"));
            }
        };
        let payload_hash = request.sign_payload(outcome.into()).compute_msg_hash()?;
        self.ecdsa_signature_provider
            .make_online_presign_signature_follower_given_request(
                channel,
                paired_triple_id,
                sign_request(&request, payload_hash),
                ROUND_DEADLINE,
            )
            .await
    }

    async fn check_round(
        &self,
        channel: &mut NetworkTaskChannel,
        yield_id: YieldId,
        outcome: RoundOutcome,
    ) -> anyhow::Result<VerifyForeignTxRequestV2> {
        let setup_deadline = Instant::now() + ROUND_SETUP_WAIT;
        let request = timeout_at(
            setup_deadline,
            self.v2.open_requests.wait_for_yield(yield_id),
        )
        .await
        .with_context(|| format!("no open V2 request within {ROUND_SETUP_WAIT:?} of Start"))?;
        let leader = self
            .ensure_acting_leader(&request, channel.leader())
            .map_err(RoundRefusal::Leader)?;
        let evidence = timeout_at(setup_deadline, channel.receive_evidence())
            .await
            .with_context(|| format!("no evidence within {ROUND_SETUP_WAIT:?} of Start"))??;
        let keyshare = self.ecdsa_signature_provider.keyshare(request.domain_id)?;
        let threshold = usize::try_from(keyshare.reconstruction_threshold.value())?;
        self.join_round_with_evidence(
            &request,
            leader,
            channel.participants(),
            outcome,
            evidence,
            threshold,
        )?;
        Ok(request)
    }

    /// Joins the round of `leader` for `request` when `evidence` proves `outcome` under the
    /// counting rule, with this node's own statements counted too. A refused round does not
    /// count against `leader`.
    fn join_round_with_evidence(
        &self,
        request: &VerifyForeignTxRequestV2,
        leader: ActingLeader,
        participants: &[ParticipantId],
        outcome: RoundOutcome,
        evidence: Vec<SignedNodeOutcome>,
        threshold: usize,
    ) -> Result<(), RoundRefusal> {
        let me = self.ecdsa_signature_provider.my_participant_id();
        let node_outcomes = self.v2.network.node_outcomes();
        let own: Vec<VerifiedNodeOutcome> = node_outcomes
            .outcomes_of(request.yield_id)
            .into_iter()
            .filter(|outcome| outcome.statement().signer == me)
            .collect();
        EvidenceCheck {
            me,
            yield_id: request.yield_id,
            outcome,
            participants,
            outcome_keys: &node_outcomes.outcome_keys(),
            supporters: &self.v2_chain_supporters(request.request.chain()),
            threshold,
        }
        .check(evidence, &own)?;
        self.v2
            .open_requests
            .join_round(leader)
            .map_err(RoundRefusal::Join)
    }
}

impl EvidenceCheck<'_> {
    /// Checks that `evidence` holds a verified statement of this node and meets the counting
    /// rule for the outcome. This node's `own` statements count too, so a node that signed
    /// another outcome before a restart takes part in no round. Evidence longer than
    /// [`Self::max_statements`] is refused before any signature check.
    fn check(
        &self,
        evidence: Vec<SignedNodeOutcome>,
        own: &[VerifiedNodeOutcome],
    ) -> Result<(), RoundRefusal> {
        let max = self.max_statements();
        if evidence.len() > max {
            return Err(RoundRefusal::TooManyStatements {
                statements: evidence.len(),
                max,
            });
        }
        let verified = evidence
            .into_iter()
            .map(|signed| {
                if signed.unverified_statement().yield_id != self.yield_id {
                    return Err(RoundRefusal::OtherYield);
                }
                Ok(signed.verify(self.outcome_keys)?)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if !verified
            .iter()
            .any(|outcome| outcome.statement().signer == self.me)
        {
            return Err(RoundRefusal::WithoutOwnStatement);
        }
        let tally = verified
            .iter()
            .chain(own)
            .map(VerifiedNodeOutcome::statement)
            .collect::<Tally>();
        match self.outcome {
            RoundOutcome::Verdict(verdict) => self.check_verdict(&tally, verdict),
            RoundOutcome::Inconclusive => self.check_inconclusive(&tally),
        }
    }

    /// The most statements a leader needs to prove the outcome: one per supporter for a
    /// verdict, and for an inconclusive two per supporter, since two different statements show
    /// a supporter that counts for no verdict.
    fn max_statements(&self) -> usize {
        match self.outcome {
            RoundOutcome::Verdict(_) => self.supporters.len(),
            RoundOutcome::Inconclusive => self.supporters.len().saturating_mul(2),
        }
    }

    fn check_verdict(&self, tally: &Tally, verdict: NodeVerdict) -> Result<(), RoundRefusal> {
        let backers = tally.backers_of(verdict, self.supporters);
        if !backers.contains(&self.me) {
            return Err(RoundRefusal::NotABacker(verdict));
        }
        if backers.len() < self.threshold {
            return Err(RoundRefusal::BelowThreshold {
                verdict,
                backers: backers.len(),
                threshold: self.threshold,
            });
        }
        Ok(())
    }

    /// Checks that no verdict can reach t, even counting every supporter the evidence does not
    /// name, and that every round participant signed exactly one outcome.
    fn check_inconclusive(&self, tally: &Tally) -> Result<(), RoundRefusal> {
        let Decision::Inconclusive { heard, .. } = tally.decide(self.supporters, self.threshold)
        else {
            return Err(RoundRefusal::VerdictCanReachThreshold);
        };
        match self
            .participants
            .iter()
            .find(|participant| !heard.contains(participant))
        {
            Some(participant) => Err(RoundRefusal::ParticipantNotHeard(*participant)),
            None => Ok(()),
        }
    }
}

/// The signature request a signer runs the shared signing protocol with. Only its payload and
/// tweak reach the protocol.
fn sign_request(
    request: &VerifyForeignTxRequestV2,
    payload_hash: dtos::Hash256,
) -> SignatureRequest {
    let payload_hash: [u8; ECDSA_PAYLOAD_SIZE_BYTES] = payload_hash.into();
    let payload: BoundedVec<u8, ECDSA_PAYLOAD_SIZE_BYTES, ECDSA_PAYLOAD_SIZE_BYTES> =
        payload_hash.into();
    SignatureRequest {
        id: request.id,
        receipt_id: request.receipt_id,
        payload: Payload::Ecdsa(payload),
        tweak: Tweak::new([0; 32]),
        entropy: request.entropy,
        timestamp_nanosec: request.timestamp_nanosec,
        domain: request.domain_id,
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests;
