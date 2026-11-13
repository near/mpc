mod rounds;

use std::collections::{BTreeSet, HashSet};
use std::future::Future;
use std::sync::Arc;

use anyhow::Context;
use futures::FutureExt;
use near_mpc_contract_interface::types::{self as dtos, Tweak};
use threshold_signatures::ReconstructionThreshold;
use threshold_signatures::ecdsa::KeygenOutput;
use tokio::time::Instant;

use super::{ROUND_DEADLINE, SignedOutcome};
use crate::metrics;
use crate::network::NetworkTaskChannel;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::wire_format::VerifyForeignTxTaskId;
use crate::primitives::{ParticipantId, UniqueId};
use crate::protocol_version::V2_FOREIGN_TX_MIN_PROTOCOL_VERSION;
use crate::providers::ecdsa::OnlinePresignSignComputation;
use crate::providers::ecdsa::triple::{PairedTriple, TripleStorage, participants_from_triples};
use crate::providers::verify_foreign_tx::VerifyForeignTxProvider;
use crate::providers::verify_foreign_tx::counting_rule::{Decision, InconclusiveCause, Tally};
use crate::providers::verify_foreign_tx::node_outcome::{NodeVerdict, RoundOutcome};
use crate::providers::verify_foreign_tx::node_outcome_statement::{
    SignedNodeOutcome, VerifiedNodeOutcome,
};
use crate::providers::verify_foreign_tx::node_outcomes::NodeOutcomes;
use crate::providers::verify_foreign_tx::open_requests::OpenVerifyForeignTxRequestsV2;
use crate::providers::verify_foreign_tx::sign::TRIPLE_TAKE_GRACE_PERIOD;
use crate::types::{VerifyForeignTxId, VerifyForeignTxRequestV2};
pub(crate) use rounds::RoundsEnd;
use rounds::{LeadSigningRounds, RoundFailure, lead_rounds};

/// The first signing round for an outcome, ready to start: the asset is taken, and every
/// participant of the asset may sign the outcome.
pub(crate) struct OutcomeRound {
    request: VerifyForeignTxRequestV2,
    evidence: RoundEvidence,
    asset: OwnedAsset<PairedTriple>,
    triple_store: Arc<TripleStorage>,
    keygen_out: KeygenOutput,
    reconstruction_threshold: ReconstructionThreshold,
}

/// The signing rounds this node leads for an outcome. Every round reuses the evidence.
struct OutcomeRounds<'a> {
    provider: &'a VerifyForeignTxProvider,
    request: VerifyForeignTxRequestV2,
    evidence: RoundEvidence,
    payload_hash: dtos::Hash256,
    triple_store: Arc<TripleStorage>,
    keygen_out: KeygenOutput,
    reconstruction_threshold: ReconstructionThreshold,
}

/// A round's evidence and the asset this node took for it.
#[derive(Debug)]
struct EvidenceAndAsset<A> {
    evidence: RoundEvidence,
    asset: OwnedAsset<A>,
}

/// An outcome the counting rule lets this node sign, with the statements that prove it. Only
/// [`evidence_to_sign`] builds it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RoundEvidence {
    proven: ProvenOutcome,
    /// The supporters a round's asset may include: the backers of a verdict, or for an
    /// inconclusive the supporters that signed exactly one outcome.
    eligible: BTreeSet<ParticipantId>,
    statements: Vec<SignedNodeOutcome>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProvenOutcome {
    Verdict(NodeVerdict),
    Inconclusive(InconclusiveCause),
}

/// The reasons a leader stops leading a request without a signing round.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum StopLeading {
    #[error("this node did not sign {0:?}, the verdict t nodes signed, so it cannot own its asset")]
    NotABacker(NodeVerdict),
    #[error(
        "this node signed two different outcomes for the request, so it takes part in no round"
    )]
    ConflictingOwnOutcome,
    #[error("this node no longer supports the chain of the request in its own view")]
    NotASupporter,
    #[error("the V2 request closed before its signing round could start")]
    RequestClosed,
}

/// An owned asset this node took for a signing round it leads.
#[derive(Debug)]
struct OwnedAsset<T> {
    id: UniqueId,
    asset: T,
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

/// The state a leader waits on before the first signing round.
struct RoundWait<'a, Assets> {
    node_outcomes: &'a NodeOutcomes,
    open_requests: &'a OpenVerifyForeignTxRequestsV2,
    assets: &'a Assets,
    request: &'a VerifyForeignTxRequestV2,
    me: ParticipantId,
    threshold: usize,
}

/// The state a leader waits on for the asset of a retry.
struct RetryAssetWait<'a, Assets> {
    open_requests: &'a OpenVerifyForeignTxRequestsV2,
    assets: &'a Assets,
    request_id: VerifyForeignTxId,
}

impl VerifyForeignTxProvider {
    /// Waits until the counting rule lets this node sign an outcome for the open request `id`,
    /// and takes an asset whose participants may all sign it. Fails with [`StopLeading`] when
    /// this node cannot lead a round for the request.
    pub(crate) async fn prepare_outcome_round(
        &self,
        id: VerifyForeignTxId,
    ) -> anyhow::Result<OutcomeRound> {
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
        let EvidenceAndAsset { evidence, asset } = RoundWait {
            node_outcomes: self.v2.network.node_outcomes(),
            open_requests: &self.v2.open_requests,
            assets: triple_store.as_ref(),
            request: &request,
            me: self.ecdsa_signature_provider.my_participant_id(),
            threshold,
        }
        .evidence_and_asset(
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
        Ok(OutcomeRound {
            request,
            evidence,
            asset,
            triple_store,
            keygen_out: keyshare.keygen_output,
            reconstruction_threshold: ReconstructionThreshold::from(threshold),
        })
    }

    /// Runs the signing rounds for the outcome of `round`, see [`lead_rounds`], and returns the
    /// first signature. A signed inconclusive raises
    /// [`metrics::MPC_NUM_VERIFY_FOREIGN_TX_INCONCLUSIVES`] and logs its evidence.
    pub(crate) async fn lead_outcome_rounds(
        &self,
        round: OutcomeRound,
    ) -> Result<SignedOutcome, RoundsEnd> {
        let OutcomeRound {
            request,
            evidence,
            asset,
            triple_store,
            keygen_out,
            reconstruction_threshold,
        } = round;
        let payload_hash = request
            .sign_payload(evidence.outcome().into())
            .compute_msg_hash()
            .map_err(|error| RoundsEnd::Local(error.into()))?;
        let rounds = OutcomeRounds {
            provider: self,
            request,
            evidence,
            payload_hash,
            triple_store,
            keygen_out,
            reconstruction_threshold,
        };
        let signed = lead_rounds(&rounds, asset).await?;
        if let ProvenOutcome::Inconclusive(cause) = rounds.evidence.proven {
            report_inconclusive(&rounds.request, cause, &rounds.evidence.statements);
        }
        Ok(signed)
    }
}

impl LeadSigningRounds for OutcomeRounds<'_> {
    type Asset = OwnedAsset<PairedTriple>;
    type Signed = SignedOutcome;

    async fn take_retry_asset(
        &self,
        avoid: &BTreeSet<ParticipantId>,
    ) -> Result<OwnedAsset<PairedTriple>, StopLeading> {
        let network = &self.provider.v2.network;
        RetryAssetWait {
            open_requests: &self.provider.v2.open_requests,
            assets: self.triple_store.as_ref(),
            request_id: self.request.id,
        }
        .take(
            || {
                let v2_capable = network
                    .participants_supporting(V2_FOREIGN_TX_MIN_PROTOCOL_VERSION)
                    .into_iter()
                    .collect();
                round_candidates(&self.evidence.eligible, &v2_capable)
            },
            avoid,
        )
        .await
    }

    /// Runs one signing round. It ends at most [`ROUND_DEADLINE`] after Start.
    async fn run_round(
        &self,
        triples: OwnedAsset<PairedTriple>,
    ) -> Result<SignedOutcome, RoundFailure> {
        if self
            .provider
            .v2
            .open_requests
            .get(self.request.id)
            .is_none()
        {
            return Err(RoundFailure::Stopped(StopLeading::RequestClosed));
        }
        let task_id = VerifyForeignTxTaskId::SignOutcome {
            yield_id: self.request.yield_id,
            outcome: self.evidence.outcome(),
            paired_triple_id: triples.id,
        };
        let channel = self.provider.v2.network.new_channel_for_task_with_evidence(
            task_id,
            participants_from_triples(&triples.asset.0, &triples.asset.1),
            self.evidence.statements.clone(),
        );
        let (signature, public_key) = run_led_round(
            channel,
            OnlinePresignSignComputation {
                keygen_out: self.keygen_out.clone(),
                reconstruction_threshold: self.reconstruction_threshold,
                triples: triples.asset,
                msg_hash: self.payload_hash.clone().into(),
                tweak: Tweak::new([0; 32]),
            },
        )
        .await?;
        Ok(SignedOutcome {
            outcome: self.evidence.outcome(),
            payload_hash: self.payload_hash.clone(),
            signature: signature
                .context("the leader should obtain a signature")
                .map_err(RoundFailure::Local)?,
            public_key,
        })
    }
}

/// Counts and logs an inconclusive this node got the network to sign. The statements point to
/// the nodes to look at, and prove no fault.
fn report_inconclusive(
    request: &VerifyForeignTxRequestV2,
    cause: InconclusiveCause,
    statements: &[SignedNodeOutcome],
) {
    let chain = request.request.chain();
    metrics::MPC_NUM_VERIFY_FOREIGN_TX_INCONCLUSIVES
        .with_label_values(&[cause.label(), chain.label()])
        .inc();
    let outcomes: Vec<_> = statements
        .iter()
        .map(|signed| {
            let statement = signed.unverified_statement();
            (statement.signer, statement.outcome)
        })
        .collect();
    tracing::info!(
        ?chain,
        cause = cause.label(),
        ?outcomes,
        "signed an inconclusive for a V2 request"
    );
}

/// Runs `computation` as a signing round this node leads on `channel`, for at most
/// [`ROUND_DEADLINE`] after Start, and counts the round. A channel that failed to open counts as
/// a failed round.
async fn run_led_round<T>(
    channel: anyhow::Result<NetworkTaskChannel>,
    computation: impl MpcLeaderCentricComputation<T>,
) -> Result<T, RoundFailure> {
    let result = match channel {
        Ok(channel) => {
            let channel_sender = channel.sender();
            computation
                .perform_leader_centric_computation(channel, ROUND_DEADLINE)
                .await
                .map_err(|error| RoundFailure::new(error, channel_sender.silent_participants()))
        }
        Err(error) => Err(RoundFailure::Unattributed(error)),
    };
    count_led_round(&result);
    result
}

/// Counts a signing round this node led, with the label of its result.
fn count_led_round<T>(result: &Result<T, RoundFailure>) {
    let outcome_label = match result {
        Ok(_) => metrics::SUCCEEDED_OUTCOME_LABEL,
        Err(RoundFailure::DeadlineExceeded { .. }) => metrics::DEADLINE_EXCEEDED_OUTCOME_LABEL,
        Err(_) => metrics::FAILED_OUTCOME_LABEL,
    };
    for label in [metrics::TOTAL_RESULT_LABEL, outcome_label] {
        metrics::MPC_NUM_VERIFY_FOREIGN_TX_COMPUTATIONS_LED
            .with_label_values(&[label])
            .inc();
    }
}

impl<Assets: TakeOwnedMatching> RoundWait<'_, Assets> {
    /// Waits until the counting rule lets this node sign an outcome and an asset among the
    /// participants eligible for it is free. The evidence and the candidates follow every new
    /// outcome and every indexed block, so an eligible participant without a matching asset
    /// blocks nothing once others sign. Fails with [`StopLeading::RequestClosed`] once the
    /// request closes, and then takes no asset.
    async fn evidence_and_asset(
        &self,
        supporters: impl Fn() -> BTreeSet<ParticipantId>,
        v2_capable: impl Fn() -> HashSet<ParticipantId>,
    ) -> Result<EvidenceAndAsset<Assets::Asset>, StopLeading> {
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
                evidence_to_sign(&outcomes, self.me, &supporters(), self.threshold)?
            else {
                tokio::select! {
                    _ = &mut outcome_kept => {}
                    _ = &mut block_indexed => {}
                }
                continue;
            };
            let candidates = round_candidates(&evidence.eligible, &v2_capable());
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
                        "no triple pair among the participants eligible for the round available, waiting"
                    );
                }
                (id, asset) = self.assets.take_owned_matching(candidates) => {
                    return Ok(EvidenceAndAsset {
                        evidence,
                        asset: OwnedAsset { id, asset },
                    });
                }
            }
        }
    }
}

impl<Assets: TakeOwnedMatching> RetryAssetWait<'_, Assets> {
    /// Waits for a free asset whose participants all belong to `candidates`, and takes one
    /// without any of `avoid` first. The candidates follow every indexed block. Fails with
    /// [`StopLeading::RequestClosed`] once the request closes, and then takes no asset.
    async fn take(
        &self,
        candidates: impl Fn() -> Vec<ParticipantId>,
        avoid: &BTreeSet<ParticipantId>,
    ) -> Result<OwnedAsset<Assets::Asset>, StopLeading> {
        loop {
            let block_indexed = self.open_requests.changed();
            tokio::pin!(block_indexed);
            block_indexed.as_mut().enable();
            if self.open_requests.get(self.request_id).is_none() {
                return Err(StopLeading::RequestClosed);
            }
            let candidates = candidates();
            let preferred = candidates
                .iter()
                .filter(|participant| !avoid.contains(participant))
                .copied()
                .collect();
            let (id, asset) = match self.assets.take_owned_matching(preferred).now_or_never() {
                Some(taken) => taken,
                None => tokio::select! {
                    biased;
                    _ = &mut block_indexed => continue,
                    taken = self.assets.take_owned_matching(candidates) => taken,
                },
            };
            return Ok(OwnedAsset { id, asset });
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
/// more of them. A leader outside `supporters` stops. When two verdicts reach t, it picks the one `me` signed. For an inconclusive it
/// waits for the outcome of `me`, and the evidence holds every statement of a supporter, since
/// leaving one out only makes the rule harder to meet.
fn evidence_to_sign(
    outcomes: &[VerifiedNodeOutcome],
    me: ParticipantId,
    supporters: &BTreeSet<ParticipantId>,
    threshold: usize,
) -> Result<Option<RoundEvidence>, StopLeading> {
    if !supporters.contains(&me) {
        return Err(StopLeading::NotASupporter);
    }
    let tally = outcomes
        .iter()
        .map(VerifiedNodeOutcome::statement)
        .collect::<Tally>();
    match tally.decide(supporters, threshold) {
        Decision::Wait => Ok(None),
        Decision::Inconclusive { heard, cause } => {
            if !heard.contains(&me) {
                let signed_any = outcomes
                    .iter()
                    .any(|outcome| outcome.statement().signer == me);
                return if signed_any {
                    Err(StopLeading::ConflictingOwnOutcome)
                } else {
                    Ok(None)
                };
            }
            let statements = outcomes
                .iter()
                .filter(|outcome| supporters.contains(&outcome.statement().signer))
                .map(|outcome| outcome.signed().clone())
                .collect();
            Ok(Some(RoundEvidence {
                proven: ProvenOutcome::Inconclusive(cause),
                eligible: heard,
                statements,
            }))
        }
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
            Ok(Some(RoundEvidence {
                proven: ProvenOutcome::Verdict(verdict),
                eligible: backers,
                statements,
            }))
        }
    }
}

/// The participants a signing round may include: the `eligible` ones that speak the V2
/// messages, in ascending order.
fn round_candidates(
    eligible: &BTreeSet<ParticipantId>,
    v2_capable: &HashSet<ParticipantId>,
) -> Vec<ParticipantId> {
    eligible
        .iter()
        .filter(|participant| v2_capable.contains(participant))
        .copied()
        .collect()
}

impl RoundEvidence {
    fn outcome(&self) -> RoundOutcome {
        match self.proven {
            ProvenOutcome::Verdict(verdict) => RoundOutcome::Verdict(verdict),
            ProvenOutcome::Inconclusive(_) => RoundOutcome::Inconclusive,
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests;
