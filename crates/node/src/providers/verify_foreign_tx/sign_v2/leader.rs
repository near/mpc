use std::collections::{BTreeSet, HashSet};

use anyhow::Context;
use near_mpc_contract_interface::types::Tweak;
use threshold_signatures::ReconstructionThreshold;
use threshold_signatures::ecdsa::KeygenOutput;
use tokio::time::Duration;

use super::{ROUND_DEADLINE, SignedVerdict};
use crate::metrics;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::wire_format::VerifyForeignTxTaskId;
use crate::primitives::{ParticipantId, UniqueId};
use crate::protocol_version::V2_FOREIGN_TX_MIN_PROTOCOL_VERSION;
use crate::providers::ecdsa::OnlinePresignSignComputation;
use crate::providers::ecdsa::triple::{PairedTriple, participants_from_triples};
use crate::providers::verify_foreign_tx::VerifyForeignTxProvider;
use crate::providers::verify_foreign_tx::counting_rule::{Decision, Tally};
use crate::providers::verify_foreign_tx::node_outcome::{NodeVerdict, RoundOutcome};
use crate::providers::verify_foreign_tx::node_outcome_statement::{
    SignedNodeOutcome, VerifiedNodeOutcome,
};
use crate::providers::verify_foreign_tx::sign::{TRIPLE_TAKE_GRACE_PERIOD, await_with_slow_hook};
use crate::types::{VerifyForeignTxId, VerifyForeignTxRequestV2};

/// The interval at which a leader that waits for node outcomes checks that the request is still
/// open.
const OPEN_RECHECK_INTERVAL: Duration = Duration::from_secs(1);

/// A signing round for a verdict, ready to start: the asset is taken, and every participant of
/// the asset signed the verdict.
pub(crate) struct VerdictRound {
    request: VerifyForeignTxRequestV2,
    evidence: VerdictEvidence,
    paired_triple_id: UniqueId,
    triples: PairedTriple,
    keygen_out: KeygenOutput,
    reconstruction_threshold: ReconstructionThreshold,
}

/// A verdict that t supporters signed, with their statements.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VerdictEvidence {
    verdict: NodeVerdict,
    backers: BTreeSet<ParticipantId>,
    statements: Vec<SignedNodeOutcome>,
}

/// The reasons a leader stops leading a request without a signing round.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum StopLeading {
    #[error("this node did not sign {0:?}, the verdict t nodes signed, so it cannot own its asset")]
    NotABacker(NodeVerdict),
    // TODO(#5126): sign an inconclusive instead.
    #[error("no verdict can reach the signing threshold")]
    NoVerdictCanReachThreshold,
    #[error("the V2 request closed before t nodes signed the same verdict")]
    RequestClosed,
}

impl VerifyForeignTxProvider {
    /// Waits until t supporters signed the same verdict for the open request `id`, then takes an
    /// asset whose participants all signed it. Fails with [`StopLeading`] when this node cannot
    /// lead a round for the request.
    pub(crate) async fn prepare_verdict_round(
        &self,
        id: VerifyForeignTxId,
    ) -> anyhow::Result<VerdictRound> {
        let request = self
            .v2
            .open_requests
            .get(id)
            .ok_or(StopLeading::RequestClosed)?;
        let requested_chain = request.request.chain();
        self.leader_chain_supporters(requested_chain)?;
        let keyshare = self.ecdsa_signature_provider.keyshare(request.domain_id)?;
        let threshold = usize::try_from(keyshare.reconstruction_threshold.value())?;
        let evidence = self.wait_for_verdict(&request, threshold).await?;

        let v2_capable: HashSet<ParticipantId> = self
            .v2
            .network
            .participants_supporting(V2_FOREIGN_TX_MIN_PROTOCOL_VERSION)
            .into_iter()
            .collect();
        let candidates = round_candidates(&evidence.backers, &v2_capable);
        // TODO(#5125): take only a triple pair without the nodes that failed an earlier round.
        let (paired_triple_id, triples) = await_with_slow_hook(
            TRIPLE_TAKE_GRACE_PERIOD,
            self.ecdsa_signature_provider
                .triple_store_for_t(keyshare.reconstruction_threshold)?
                .take_owned_matching(candidates),
            || {
                metrics::MPC_NUM_VERIFY_FOREIGN_TX_TRIPLE_WAITS.inc();
                tracing::warn!(
                    ?requested_chain,
                    "no triple pair among the backers of the verdict available, waiting"
                )
            },
        )
        .await;
        Ok(VerdictRound {
            request,
            evidence,
            paired_triple_id,
            triples,
            keygen_out: keyshare.keygen_output,
            reconstruction_threshold: ReconstructionThreshold::from(threshold),
        })
    }

    /// Runs one signing round for the verdict. It ends at most [`ROUND_DEADLINE`] after Start.
    pub(crate) async fn run_verdict_round(
        &self,
        round: VerdictRound,
    ) -> anyhow::Result<SignedVerdict> {
        let VerdictRound {
            request,
            evidence,
            paired_triple_id,
            triples,
            keygen_out,
            reconstruction_threshold,
        } = round;
        anyhow::ensure!(
            self.v2.open_requests.get(request.id).is_some(),
            "the V2 request closed before its signing round started"
        );
        let task_id = VerifyForeignTxTaskId::SignOutcome {
            yield_id: request.yield_id,
            outcome: RoundOutcome::Verdict(evidence.verdict),
            paired_triple_id,
        };
        let channel = self.v2.network.new_channel_for_task_with_evidence(
            task_id,
            participants_from_triples(&triples.0, &triples.1),
            evidence.statements,
        )?;
        let payload_hash = request
            .sign_payload(evidence.verdict.into())
            .compute_msg_hash()?;
        let (signature, public_key) = OnlinePresignSignComputation {
            keygen_out,
            reconstruction_threshold,
            triples,
            msg_hash: payload_hash.clone().into(),
            tweak: Tweak::new([0; 32]),
        }
        .perform_leader_centric_computation(channel, ROUND_DEADLINE)
        .await?;
        Ok(SignedVerdict {
            verdict: evidence.verdict,
            payload_hash,
            signature: signature.context("the leader should obtain a signature")?,
            public_key,
        })
    }

    async fn wait_for_verdict(
        &self,
        request: &VerifyForeignTxRequestV2,
        threshold: usize,
    ) -> anyhow::Result<VerdictEvidence> {
        let me = self.ecdsa_signature_provider.my_participant_id();
        let node_outcomes = self.v2.network.node_outcomes();
        loop {
            let changed = node_outcomes.changed();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.v2.open_requests.get(request.id).is_none() {
                return Err(StopLeading::RequestClosed.into());
            }
            let supporters = self.v2_chain_supporters(request.request.chain());
            let outcomes = node_outcomes.outcomes_of(request.yield_id);
            if let Some(evidence) = verdict_to_sign(&outcomes, me, &supporters, threshold)? {
                return Ok(evidence);
            }
            let _ = tokio::time::timeout(OPEN_RECHECK_INTERVAL, changed).await;
        }
    }
}

/// Applies the counting rule to the kept `outcomes`. Returns `None` while the leader waits for
/// more of them.
fn verdict_to_sign(
    outcomes: &[VerifiedNodeOutcome],
    me: ParticipantId,
    supporters: &BTreeSet<ParticipantId>,
    threshold: usize,
) -> Result<Option<VerdictEvidence>, StopLeading> {
    let decision = outcomes
        .iter()
        .map(VerifiedNodeOutcome::statement)
        .collect::<Tally>()
        .decide(supporters, threshold);
    match decision {
        Decision::Wait => Ok(None),
        Decision::Inconclusive { .. } => Err(StopLeading::NoVerdictCanReachThreshold),
        Decision::Verdict { verdict, backers } if !backers.contains(&me) => {
            Err(StopLeading::NotABacker(verdict))
        }
        Decision::Verdict { verdict, backers } => {
            let statements = outcomes
                .iter()
                .filter(|outcome| backers.contains(&outcome.statement().signer))
                .map(|outcome| outcome.signed().clone())
                .collect();
            Ok(Some(VerdictEvidence {
                verdict,
                backers,
                statements,
            }))
        }
    }
}

/// The participants a signing round for a verdict may include: its backers that speak the V2
/// messages, in ascending order.
fn round_candidates(
    backers: &BTreeSet<ParticipantId>,
    v2_capable: &HashSet<ParticipantId>,
) -> Vec<ParticipantId> {
    backers
        .iter()
        .filter(|backer| v2_capable.contains(backer))
        .copied()
        .collect()
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests;
