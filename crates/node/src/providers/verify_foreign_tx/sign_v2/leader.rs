use std::collections::{BTreeSet, HashSet};
use std::future::Future;

use anyhow::Context;
use near_mpc_contract_interface::types::Tweak;
use threshold_signatures::ReconstructionThreshold;
use threshold_signatures::ecdsa::KeygenOutput;
use tokio::time::Instant;

use super::{ROUND_DEADLINE, SignedVerdict};
use crate::metrics;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::wire_format::VerifyForeignTxTaskId;
use crate::primitives::{ParticipantId, UniqueId};
use crate::protocol_version::V2_FOREIGN_TX_MIN_PROTOCOL_VERSION;
use crate::providers::ecdsa::OnlinePresignSignComputation;
use crate::providers::ecdsa::triple::{PairedTriple, TripleStorage, participants_from_triples};
use crate::providers::verify_foreign_tx::VerifyForeignTxProvider;
use crate::providers::verify_foreign_tx::counting_rule::{Decision, Tally};
use crate::providers::verify_foreign_tx::node_outcome::{NodeVerdict, RoundOutcome};
use crate::providers::verify_foreign_tx::node_outcome_statement::{
    SignedNodeOutcome, VerifiedNodeOutcome,
};
use crate::providers::verify_foreign_tx::node_outcomes::NodeOutcomes;
use crate::providers::verify_foreign_tx::open_requests::OpenVerifyForeignTxRequestsV2;
use crate::providers::verify_foreign_tx::sign::TRIPLE_TAKE_GRACE_PERIOD;
use crate::types::{VerifyForeignTxId, VerifyForeignTxRequestV2};

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
    #[error("the V2 request closed before its signing round could start")]
    RequestClosed,
}

/// The owned assets of a leader, each shared with a set of participants.
trait TakeOwnedMatching {
    type Asset;

    /// Takes an owned asset whose participants all belong to `eligible`, once one is free.
    /// Dropping the future before it completes takes nothing.
    fn take_owned_matching(
        &self,
        eligible: Vec<ParticipantId>,
    ) -> impl Future<Output = (UniqueId, Self::Asset)> + Send;
}

/// The state a leader waits on before a signing round for a verdict.
struct RoundWait<'a, Assets> {
    node_outcomes: &'a NodeOutcomes,
    open_requests: &'a OpenVerifyForeignTxRequestsV2,
    assets: &'a Assets,
    request: &'a VerifyForeignTxRequestV2,
    me: ParticipantId,
    threshold: usize,
}

impl VerifyForeignTxProvider {
    /// Waits until t supporters signed the same verdict for the open request `id`, and takes an
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
        let triple_store = self
            .ecdsa_signature_provider
            .triple_store_for_t(keyshare.reconstruction_threshold)?;
        // TODO(#5125): take only a triple pair without the nodes that failed an earlier round.
        let (evidence, paired_triple_id, triples) = RoundWait {
            node_outcomes: self.v2.network.node_outcomes(),
            open_requests: &self.v2.open_requests,
            assets: triple_store.as_ref(),
            request: &request,
            me: self.ecdsa_signature_provider.my_participant_id(),
            threshold,
        }
        .verdict_and_asset(
            || self.v2_chain_supporters(requested_chain),
            || {
                self.v2
                    .network
                    .participants_supporting(V2_FOREIGN_TX_MIN_PROTOCOL_VERSION)
                    .into_iter()
                    .collect()
            },
        )
        .await?;
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
}

impl<Assets: TakeOwnedMatching> RoundWait<'_, Assets> {
    /// Waits until t supporters signed the same verdict and an asset among its current backers
    /// is free. The backers, the evidence and the candidates follow every new outcome and every
    /// indexed block, so a backer without a matching asset blocks nothing once other backers
    /// sign. Fails with [`StopLeading::RequestClosed`] once the request closes, and then takes
    /// no asset.
    async fn verdict_and_asset(
        &self,
        supporters: impl Fn() -> BTreeSet<ParticipantId>,
        v2_capable: impl Fn() -> HashSet<ParticipantId>,
    ) -> Result<(VerdictEvidence, UniqueId, Assets::Asset), StopLeading> {
        let mut asset_wait_started: Option<Instant> = None;
        let mut slow_asset_wait_reported = false;
        loop {
            let outcome_kept = self.node_outcomes.changed();
            tokio::pin!(outcome_kept);
            outcome_kept.as_mut().enable();
            let block_indexed = self.open_requests.changed();
            tokio::pin!(block_indexed);
            block_indexed.as_mut().enable();
            if self.open_requests.get(self.request.id).is_none() {
                return Err(StopLeading::RequestClosed);
            }
            let outcomes = self.node_outcomes.outcomes_of(self.request.yield_id);
            let Some(evidence) =
                verdict_to_sign(&outcomes, self.me, &supporters(), self.threshold)?
            else {
                tokio::select! {
                    _ = &mut outcome_kept => {}
                    _ = &mut block_indexed => {}
                }
                continue;
            };
            let candidates = round_candidates(&evidence.backers, &v2_capable());
            let slow_at =
                *asset_wait_started.get_or_insert_with(Instant::now) + TRIPLE_TAKE_GRACE_PERIOD;
            tokio::select! {
                biased;
                _ = &mut block_indexed => {}
                _ = &mut outcome_kept => {}
                () = tokio::time::sleep_until(slow_at), if !slow_asset_wait_reported => {
                    slow_asset_wait_reported = true;
                    metrics::MPC_NUM_VERIFY_FOREIGN_TX_TRIPLE_WAITS.inc();
                    tracing::warn!(
                        chain = ?self.request.request.chain(),
                        "no triple pair among the backers of the verdict available, waiting"
                    );
                }
                (id, asset) = self.assets.take_owned_matching(candidates) => {
                    return Ok((evidence, id, asset));
                }
            }
        }
    }
}

impl TakeOwnedMatching for TripleStorage {
    type Asset = PairedTriple;

    fn take_owned_matching(
        &self,
        eligible: Vec<ParticipantId>,
    ) -> impl Future<Output = (UniqueId, PairedTriple)> + Send {
        (**self).take_owned_matching(eligible)
    }
}

/// Applies the counting rule to the kept `outcomes`. Returns `None` while the leader waits for
/// more of them. When two verdicts reach t, it picks the one `me` signed.
fn verdict_to_sign(
    outcomes: &[VerifiedNodeOutcome],
    me: ParticipantId,
    supporters: &BTreeSet<ParticipantId>,
    threshold: usize,
) -> Result<Option<VerdictEvidence>, StopLeading> {
    let tally = outcomes
        .iter()
        .map(VerifiedNodeOutcome::statement)
        .collect::<Tally>();
    match tally.decide(supporters, threshold) {
        Decision::Wait => Ok(None),
        Decision::Inconclusive { .. } => Err(StopLeading::NoVerdictCanReachThreshold),
        Decision::Verdict { verdict, backers } => {
            let (verdict, backers) = if backers.contains(&me) {
                (verdict, backers)
            } else {
                // Two verdicts can reach t, and signers accept either, so the leader signs the
                // one it backs.
                let own = tally
                    .verdict_of(me)
                    .map(|own| (own, tally.backers_of(own, supporters)))
                    .filter(|(_, own_backers)| {
                        own_backers.contains(&me) && own_backers.len() >= threshold
                    });
                own.ok_or(StopLeading::NotABacker(verdict))?
            };
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
