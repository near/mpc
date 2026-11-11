use std::collections::HashSet;

use anyhow::Context;
use near_mpc_contract_interface::types::{self as dtos, YieldId};
use tokio::time::{Duration, timeout};

use crate::metrics;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::{NetworkTaskChannel, PeerNodeOutcomes};
use crate::primitives::{ParticipantId, UniqueId};
use crate::providers::verify_foreign_tx::VerifyForeignTxProvider;
use crate::providers::verify_foreign_tx::inconclusive_evidence::{
    EvidenceRequirements, InconclusiveCause, InconclusiveEvidence, TransientQuorum,
};
use crate::providers::verify_foreign_tx::node_outcome_statement::SignedNodeOutcome;
use crate::providers::verify_foreign_tx::outcome_signing::{
    OutcomeSigning, SignedOutcome, sign_request,
};
use crate::providers::verify_foreign_tx::sign_v2::FOLLOWER_INDEX_WAIT;
use crate::types::VerifyForeignTxRequestV2;

/// The deadline of an inconclusive round, from its Start.
const INCONCLUSIVE_ROUND_DEADLINE: Duration = Duration::from_secs(5);

const VERDICTS_DIFFER_CAUSE_LABEL: &str = "verdicts_differ";
const INSPECTORS_DISAGREE_CAUSE_LABEL: &str = "inspectors_disagree";
const TRANSIENT_CAUSE_LABEL: &str = "transient";

impl VerifyForeignTxProvider {
    /// Returns once the node outcomes of this node's attempts at `request` prove a cause for an
    /// inconclusive.
    pub(crate) async fn wait_for_inconclusive_evidence(
        &self,
        request: &VerifyForeignTxRequestV2,
        signing_threshold: usize,
    ) -> InconclusiveEvidence {
        let transient_quorum = self.transient_quorum(request, signing_threshold);
        let evidence = self
            .v2
            .network
            .attempt_evidence()
            .wait_for(request.yield_id, |outcomes| {
                InconclusiveEvidence::find(outcomes, transient_quorum)
            })
            .await;
        tracing::info!(
            yield_id = ?request.yield_id,
            cause = ?evidence.cause,
            outcomes = ?evidence.outcomes,
            "the V2 foreign tx attempts prove an inconclusive"
        );
        evidence
    }

    /// Takes part in an inconclusive round for the V2 request waiting on `yield_id`. A signer
    /// refuses with the network abort unless the request is open, the leader is an acting leader
    /// in its view, it joined fewer than
    /// [`MAX_INCONCLUSIVE_ROUNDS_PER_LEADER`](super::MAX_INCONCLUSIVE_ROUNDS_PER_LEADER) rounds of
    /// the leader, and the leader's evidence proves a cause.
    pub(crate) async fn make_verify_foreign_tx_inconclusive_follower(
        &self,
        mut channel: NetworkTaskChannel,
        yield_id: YieldId,
        paired_triple_id: UniqueId,
    ) -> anyhow::Result<()> {
        let sender = channel.sender();
        let request = match self
            .join_inconclusive_round(&mut channel, yield_id, paired_triple_id)
            .await
        {
            Ok(request) => request,
            Err(refusal) => {
                sender.abort(&refusal);
                return Err(refusal.context("refused an inconclusive round"));
            }
        };
        let payload_hash = request
            .sign_payload(dtos::ForeignTxVerificationOutcome::Inconclusive {})?
            .compute_msg_hash()?;
        self.ecdsa_signature_provider
            .make_online_presign_signature_follower_given_request(
                channel,
                paired_triple_id,
                sign_request(&request, payload_hash),
            )
            .await
    }

    async fn join_inconclusive_round(
        &self,
        channel: &mut NetworkTaskChannel,
        yield_id: YieldId,
        paired_triple_id: UniqueId,
    ) -> anyhow::Result<VerifyForeignTxRequestV2> {
        let leader = channel.leader();
        paired_triple_id.validate_owned_by(leader)?;
        let request = timeout(
            FOLLOWER_INDEX_WAIT,
            self.v2.open_requests.wait_for_yield(yield_id),
        )
        .await
        .with_context(|| {
            format!("the V2 request is not open within {FOLLOWER_INDEX_WAIT:?} of Start")
        })?;
        self.ensure_acting_leader(&request, leader)?;
        self.v2
            .open_requests
            .join_inconclusive_round(request.id, leader)?;
        let outcomes = timeout(INCONCLUSIVE_ROUND_DEADLINE, receive_evidence(channel))
            .await
            .context("the leader sent no evidence within the round deadline")??;
        let signing_threshold = self
            .ecdsa_signature_provider
            .keyshare(request.request.domain_id)?
            .reconstruction_threshold
            .value();
        let requirements = EvidenceRequirements {
            leader,
            yield_id,
            participants: &self.v2.participants,
            transient_quorum: self.transient_quorum(&request, usize::try_from(signing_threshold)?),
        };
        let evidence = InconclusiveEvidence::check(outcomes, &requirements)?;
        tracing::info!(%leader, cause = ?evidence.cause, "joined an inconclusive round");
        Ok(request)
    }

    fn transient_quorum(
        &self,
        request: &VerifyForeignTxRequestV2,
        signing_threshold: usize,
    ) -> TransientQuorum {
        let chain_supporters = self
            .supporters_by_foreign_chain
            .borrow()
            .get(&request.request.request.chain())
            .map_or(0, HashSet::len);
        TransientQuorum::new(chain_supporters, signing_threshold)
    }
}

/// Receives the evidence that the leader sends right after the Start. Node outcomes from other
/// participants are dropped, so they cannot fail the round.
async fn receive_evidence(
    channel: &mut NetworkTaskChannel,
) -> anyhow::Result<Vec<SignedNodeOutcome>> {
    let leader = channel.leader();
    loop {
        let PeerNodeOutcomes { from, outcomes } = channel.receive_node_outcomes().await?;
        if from == leader {
            return Ok(outcomes);
        }
        tracing::debug!(%from, "dropping node outcomes from a signer of an inconclusive round");
    }
}

/// The leader's side of an inconclusive round: it shows the evidence right after the Start, and
/// then signs the inconclusive payload.
pub(crate) struct InconclusiveRoundComputation {
    pub(crate) evidence: InconclusiveEvidence,
    pub(crate) signing: OutcomeSigning,
}

impl InconclusiveRoundComputation {
    /// Runs the round for at most [`INCONCLUSIVE_ROUND_DEADLINE`] after the Start that `channel`
    /// sent. A signed inconclusive raises
    /// [`MPC_NUM_VERIFY_FOREIGN_TX_INCONCLUSIVES`](metrics::MPC_NUM_VERIFY_FOREIGN_TX_INCONCLUSIVES).
    pub(crate) async fn run(self, channel: NetworkTaskChannel) -> anyhow::Result<SignedOutcome> {
        let chain = self.signing.request.request.request.chain();
        let yield_id = self.signing.request.yield_id;
        let evidence = self.evidence.clone();
        let signed = self
            .perform_leader_centric_computation(channel, INCONCLUSIVE_ROUND_DEADLINE)
            .await?;
        let labels = InconclusiveLabels::new(evidence.cause);
        metrics::MPC_NUM_VERIFY_FOREIGN_TX_INCONCLUSIVES
            .with_label_values(&[
                labels.cause,
                chain.label(),
                &labels.first_node,
                &labels.second_node,
            ])
            .inc();
        tracing::info!(
            ?yield_id,
            cause = ?evidence.cause,
            outcomes = ?evidence.outcomes,
            "signed an inconclusive"
        );
        Ok(signed)
    }
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<SignedOutcome> for InconclusiveRoundComputation {
    async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<SignedOutcome> {
        channel
            .sender()
            .send_evidence(self.evidence.signed_outcomes())?;
        self.signing
            .sign(channel, dtos::ForeignTxVerificationOutcome::Inconclusive {})
            .await
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}

/// The metric labels of an inconclusive. A disagreement names its nodes in ascending order, so
/// the series stay bounded by the pairs of participants.
struct InconclusiveLabels {
    cause: &'static str,
    first_node: String,
    second_node: String,
}

impl InconclusiveLabels {
    fn new(cause: InconclusiveCause) -> Self {
        let node = |participant: ParticipantId| participant.raw().to_string();
        match cause {
            InconclusiveCause::VerdictsDiffer { first, second } => Self {
                cause: VERDICTS_DIFFER_CAUSE_LABEL,
                first_node: node(first.min(second)),
                second_node: node(first.max(second)),
            },
            InconclusiveCause::InspectorsDisagree { participant } => Self {
                cause: INSPECTORS_DISAGREE_CAUSE_LABEL,
                first_node: node(participant),
                second_node: String::new(),
            },
            InconclusiveCause::Transient => Self {
                cause: TRANSIENT_CAUSE_LABEL,
                first_node: String::new(),
                second_node: String::new(),
            },
        }
    }
}
