use std::collections::BTreeSet;

use anyhow::Context;
use near_mpc_bounded_collections::BoundedVec;
use near_mpc_contract_interface::types::{
    self as dtos, ECDSA_PAYLOAD_SIZE_BYTES, Payload, Tweak, YieldId,
};
use tokio::time::{Duration, timeout};

use crate::network::NetworkTaskChannel;
use crate::primitives::{ParticipantId, UniqueId};
use crate::providers::verify_foreign_tx::VerifyForeignTxProvider;
use crate::providers::verify_foreign_tx::counting_rule::Tally;
use crate::providers::verify_foreign_tx::node_outcome::{NodeVerdict, RoundOutcome};
use crate::providers::verify_foreign_tx::node_outcome_statement::{
    NodeOutcomeVerificationError, OutcomePublicKeys, SignedNodeOutcome, VerifiedNodeOutcome,
};
use crate::types::{SignatureRequest, VerifyForeignTxRequestV2};

/// The time a signer waits for its own indexer to report the request of a Start, and for the
/// leader's evidence.
const ROUND_SETUP_WAIT: Duration = Duration::from_secs(3);

/// The reasons a signer refuses a V2 signing round.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RoundRefusal {
    // TODO(#5126): join inconclusive rounds.
    #[error("inconclusive signing rounds are not supported yet")]
    Inconclusive,
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
    #[error("the V2 request closed before this node joined the round")]
    RequestClosed,
}

/// What a signer checks the evidence of a round for a verdict against.
struct VerdictCheck<'a> {
    me: ParticipantId,
    yield_id: YieldId,
    verdict: NodeVerdict,
    outcome_keys: &'a OutcomePublicKeys,
    supporters: &'a BTreeSet<ParticipantId>,
    threshold: usize,
}

impl VerifyForeignTxProvider {
    /// Joins a V2 signing round when the request is open and the evidence meets the counting
    /// rule. Otherwise it refuses with the network abort.
    pub(crate) async fn make_sign_outcome_follower(
        &self,
        mut channel: NetworkTaskChannel,
        yield_id: YieldId,
        outcome: RoundOutcome,
        paired_triple_id: UniqueId,
    ) -> anyhow::Result<()> {
        let sender = channel.sender();
        let (request, verdict) = match self.check_round(&mut channel, yield_id, outcome).await {
            Ok(checked) => checked,
            Err(refusal) => {
                sender.communicate_failure(&refusal);
                return Err(refusal.context("refused a V2 signing round"));
            }
        };
        let payload_hash = request.sign_payload(verdict.into()).compute_msg_hash()?;
        self.ecdsa_signature_provider
            .make_online_presign_signature_follower_given_request(
                channel,
                paired_triple_id,
                sign_request(&request, payload_hash),
            )
            .await
    }

    async fn check_round(
        &self,
        channel: &mut NetworkTaskChannel,
        yield_id: YieldId,
        outcome: RoundOutcome,
    ) -> anyhow::Result<(VerifyForeignTxRequestV2, NodeVerdict)> {
        let RoundOutcome::Verdict(verdict) = outcome else {
            return Err(RoundRefusal::Inconclusive.into());
        };
        // TODO(#5124): refuse a leader that is not an acting leader of the request, or that
        // already ran three rounds with this node.
        let (request, evidence) = timeout(ROUND_SETUP_WAIT, async {
            let request = self.v2.open_requests.wait_for_yield(yield_id).await;
            let evidence = channel.receive_evidence().await?;
            anyhow::Ok((request, evidence))
        })
        .await
        .with_context(|| {
            format!("no open V2 request or no evidence within {ROUND_SETUP_WAIT:?} of Start")
        })??;
        let me = self.ecdsa_signature_provider.my_participant_id();
        let keyshare = self.ecdsa_signature_provider.keyshare(request.domain_id)?;
        let node_outcomes = self.v2.network.node_outcomes();
        let own: Vec<VerifiedNodeOutcome> = node_outcomes
            .outcomes_of(yield_id)
            .into_iter()
            .filter(|outcome| outcome.statement().signer == me)
            .collect();
        VerdictCheck {
            me,
            yield_id,
            verdict,
            outcome_keys: &node_outcomes.outcome_keys(),
            supporters: &self.v2_chain_supporters(request.request.chain()),
            threshold: usize::try_from(keyshare.reconstruction_threshold.value())?,
        }
        .check(evidence, &own)?;
        if self.v2.open_requests.get(request.id).is_none() {
            return Err(RoundRefusal::RequestClosed.into());
        }
        Ok((request, verdict))
    }
}

impl VerdictCheck<'_> {
    /// Checks that `evidence` holds a verified statement of this node and that t supporters
    /// signed the verdict. This node's `own` statements count too, so a node that signed
    /// another outcome before a restart backs no verdict.
    fn check(
        &self,
        evidence: Vec<SignedNodeOutcome>,
        own: &[VerifiedNodeOutcome],
    ) -> Result<(), RoundRefusal> {
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
        let backers = verified
            .iter()
            .chain(own)
            .map(VerifiedNodeOutcome::statement)
            .collect::<Tally>()
            .backers_of(self.verdict, self.supporters);
        if !backers.contains(&self.me) {
            return Err(RoundRefusal::NotABacker(self.verdict));
        }
        if backers.len() < self.threshold {
            return Err(RoundRefusal::BelowThreshold {
                verdict: self.verdict,
                backers: backers.len(),
                threshold: self.threshold,
            });
        }
        Ok(())
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
