use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::Context;
use near_contract_transport::BlockHeight;
use near_mpc_bounded_collections::BoundedVec;
use near_mpc_contract_interface::types::{self as dtos, ECDSA_PAYLOAD_SIZE_BYTES, Payload, Tweak};
use threshold_signatures::ReconstructionThreshold;
use threshold_signatures::ecdsa::{KeygenOutput, Signature};
use threshold_signatures::frost_secp256k1::VerifyingKey;
use tokio::sync::oneshot;
use tokio::time::{Duration, timeout};

use crate::assets::DistributedAssetStorage;
use crate::config::ParticipantsConfig;
use crate::metrics;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::wire_format::VerifyForeignTxTaskId;
use crate::network::{MeshNetworkClient, NetworkTaskChannel, PeerNodeOutcomes};
use crate::primitives::{ParticipantId, UniqueId};
use crate::providers::ecdsa::OnlinePresignSignComputation;
use crate::providers::ecdsa::triple::{PairedTriple, TripleStorage, participants_from_triples};
use crate::providers::verify_foreign_tx::attempt_assets::{
    OwnedAsset, is_within_indexer_margin, take_owned_avoiding,
};
use crate::providers::verify_foreign_tx::attempt_evidence::{AttemptEvidence, LedAttempt};
use crate::providers::verify_foreign_tx::attempt_outcomes::{AttemptOutcomes, AttemptStatus};
use crate::providers::verify_foreign_tx::leader_attempts::{
    AttemptFailure, LeadV2Attempt, lead_attempts,
};
use crate::providers::verify_foreign_tx::node_outcome::{NodeOutcome, NodeVerdict};
use crate::providers::verify_foreign_tx::node_outcome_statement::{
    AttemptId, NodeOutcomeSigningKey, NodeOutcomeStatement, SignedNodeOutcome,
};
use crate::providers::verify_foreign_tx::open_requests::OpenVerifyForeignTxRequestsV2;
use crate::providers::verify_foreign_tx::{
    FOREIGN_CHAIN_INSPECTION_TIMEOUT, V2_FOREIGN_TX_MIN_PROTOCOL_VERSION, VerifyForeignTxProvider,
};
use crate::types::{SignatureRequest, VerifyForeignTxId, VerifyForeignTxRequestV2};

/// The time a follower waits for its own indexer to report the request of a Start.
const FOLLOWER_INDEX_WAIT: Duration = Duration::from_secs(3);

/// The time the messages of a V2 attempt take within the cluster.
const CLUSTER_MESSAGES_TIME: Duration = Duration::from_secs(5);

/// The deadline of a V2 attempt, from its Start: a follower's index wait, its inspection and the
/// messages within the cluster.
const ATTEMPT_DEADLINE: Duration = FOLLOWER_INDEX_WAIT
    .saturating_add(FOREIGN_CHAIN_INSPECTION_TIMEOUT)
    .saturating_add(CLUSTER_MESSAGES_TIME);

/// The time a V2 leader waits for a triple pair before it checks the request and the candidates
/// again.
const ASSET_RECHECK_INTERVAL: Duration = Duration::from_secs(1);

#[cfg(test)]
#[expect(non_snake_case)]
mod tests;

/// What a node needs, beyond the V1 flow, to take part in V2 attempts.
pub(crate) struct VerifyForeignTxV2Context {
    pub(crate) open_requests: Arc<OpenVerifyForeignTxRequestsV2>,
    pub(crate) signing_key: NodeOutcomeSigningKey,
    /// The participant set that holds the TLS key each node outcome is verified against.
    pub(crate) participants: Arc<ParticipantsConfig>,
    pub(crate) network: Arc<MeshNetworkClient>,
}

/// The signature of a V2 attempt where every participant found [`Self::verdict`].
pub(crate) struct SignedVerdict {
    pub(crate) verdict: NodeVerdict,
    pub(crate) payload_hash: dtos::Hash256,
    pub(crate) signature: Signature,
    pub(crate) public_key: VerifyingKey,
}

impl VerifyForeignTxProvider {
    /// Leads the attempts at the open V2 request `id`, see [`lead_attempts`], and returns the
    /// first signature.
    pub(crate) async fn make_verify_foreign_tx_v2_leader(
        self: &Arc<Self>,
        id: VerifyForeignTxId,
    ) -> anyhow::Result<SignedVerdict> {
        let request = self
            .v2
            .open_requests
            .get(id)
            .context("the V2 request is not open")?;
        let keyshare = self
            .ecdsa_signature_provider
            .keyshare(request.request.domain_id)?;
        let leader = V2Leader {
            provider: self.clone(),
            request,
            triples: self
                .ecdsa_signature_provider
                .triple_store_for_t(keyshare.reconstruction_threshold)?,
            reconstruction_threshold: ReconstructionThreshold::from(usize::try_from(
                keyshare.reconstruction_threshold.value(),
            )?),
            keygen_out: keyshare.keygen_output,
        };
        Ok(lead_attempts(&leader).await?)
    }

    /// The participants a V2 attempt on `requested_chain` may include: chain supporters that
    /// speak the V2 messages, with an indexer within the margin of this node's.
    fn v2_attempt_candidates(
        &self,
        requested_chain: dtos::ForeignChain,
    ) -> anyhow::Result<Vec<ParticipantId>> {
        let chain_supporters = self.leader_chain_supporters(requested_chain)?;
        let network = &self.v2.network;
        let indexer_heights = network.get_indexer_heights();
        let height_of =
            |participant| BlockHeight::new(indexer_heights.get(&participant).copied().unwrap_or(0));
        let my_height = height_of(network.my_participant_id());
        let mut candidates: Vec<ParticipantId> = network
            .participants_supporting(V2_FOREIGN_TX_MIN_PROTOCOL_VERSION)
            .into_iter()
            .filter(|participant| {
                chain_supporters.contains(participant)
                    && is_within_indexer_margin(my_height, height_of(*participant))
            })
            .collect();
        candidates.sort();
        Ok(candidates)
    }

    /// Inspects `request` as the leader of `attempt`, and keeps the signed node outcome as
    /// evidence. The inspection outlives the attempt, so its outcome joins the evidence after the
    /// attempt ended.
    fn spawn_own_inspection(
        self: &Arc<Self>,
        request: &VerifyForeignTxRequestV2,
        attempt: &LedAttempt,
    ) -> oneshot::Receiver<anyhow::Result<NodeOutcome>> {
        let (own_outcome_sender, own_outcome) = oneshot::channel();
        self.own_inspections.lock().unwrap().spawn_checked(
            &format!("own inspection of V2 attempt {:?}", attempt.id),
            {
                let this = self.clone();
                let request = request.clone();
                let attempt = attempt.clone();
                async move {
                    let outcome = this
                        .signed_node_outcome(&request, attempt.leader, attempt.id)
                        .await
                        .and_then(|signed| {
                            record_own_outcome(signed, &attempt, this.v2.network.attempt_evidence())
                        });
                    let _ = own_outcome_sender.send(outcome);
                    anyhow::Ok(())
                }
            },
        );
        own_outcome
    }

    /// Takes part in a V2 attempt. A follower that cannot inspect refuses with the network abort.
    /// Otherwise it sends its signed node outcome, even when the attempt already ended, and its
    /// share only for a verdict.
    pub(crate) async fn make_verify_foreign_tx_v2_follower(
        &self,
        channel: NetworkTaskChannel,
        id: VerifyForeignTxId,
        paired_triple_id: UniqueId,
    ) -> anyhow::Result<()> {
        let sender = channel.sender();
        let (request, signed) = match self.follower_node_outcome(&channel, id).await {
            Ok(reported) => reported,
            Err(refusal) => {
                sender.abort(&refusal);
                return Err(refusal.context("refused a V2 foreign tx attempt"));
            }
        };
        let outcome = signed.unverified_statement().outcome;
        sender.send_node_outcome(signed)?;
        let NodeOutcome::Verdict(verdict) = outcome else {
            tracing::info!(?outcome, "reported no verdict for a V2 foreign tx attempt");
            return Ok(());
        };
        let payload_hash = request.sign_payload(verdict.into())?.compute_msg_hash()?;
        self.ecdsa_signature_provider
            .make_online_presign_signature_follower_given_request(
                channel,
                paired_triple_id,
                sign_request(&request, payload_hash),
            )
            .await
    }

    async fn follower_node_outcome(
        &self,
        channel: &NetworkTaskChannel,
        id: VerifyForeignTxId,
    ) -> anyhow::Result<(VerifyForeignTxRequestV2, SignedNodeOutcome)> {
        let request = timeout(FOLLOWER_INDEX_WAIT, self.v2.open_requests.wait_for(id))
            .await
            .with_context(|| {
                format!("the V2 request is not open within {FOLLOWER_INDEX_WAIT:?} of Start")
            })?;
        // TODO(#5124): refuse a leader that is not an acting leader of the request, or that
        // already ran three attempts with this node.
        let signed = self
            .signed_node_outcome(&request, channel.leader(), AttemptId(channel.channel_id()))
            .await?;
        Ok((request, signed))
    }

    /// Inspects the request and signs the node outcome, while the request is open.
    async fn signed_node_outcome(
        &self,
        request: &VerifyForeignTxRequestV2,
        leader: ParticipantId,
        attempt: AttemptId,
    ) -> anyhow::Result<SignedNodeOutcome> {
        let outcome = self.reach_node_outcome(&request.request).await?;
        anyhow::ensure!(
            self.v2.open_requests.get(request.id).is_some(),
            "the V2 request closed during the inspection"
        );
        let statement = NodeOutcomeStatement {
            yield_id: request.yield_id,
            leader,
            attempt,
            signer: self.ecdsa_signature_provider.my_participant_id(),
            outcome,
        };
        Ok(self.v2.signing_key.sign(statement)?)
    }
}

/// Opens the channel of a V2 attempt this node leads. [`AttemptEvidence`] keeps the attempt's
/// node outcomes from before its Start leaves.
fn open_led_attempt(
    network: &MeshNetworkClient,
    task_id: VerifyForeignTxTaskId,
    participants: Vec<ParticipantId>,
    yield_id: dtos::YieldId,
    keys: Arc<ParticipantsConfig>,
) -> anyhow::Result<(NetworkTaskChannel, LedAttempt)> {
    let led_attempt = |channel_id| LedAttempt {
        id: AttemptId(channel_id),
        yield_id,
        leader: network.my_participant_id(),
        participants: participants.clone(),
        keys: keys.clone(),
    };
    let channel =
        network.new_channel_for_task_with(task_id, participants.clone(), |channel_id| {
            network.attempt_evidence().open(led_attempt(channel_id));
        })?;
    let attempt = led_attempt(channel.channel_id());
    Ok((channel, attempt))
}

/// Keeps the leader's own signed node outcome as evidence of `attempt`.
fn record_own_outcome(
    signed: SignedNodeOutcome,
    attempt: &LedAttempt,
    evidence: &AttemptEvidence,
) -> anyhow::Result<NodeOutcome> {
    let verified = signed.verify(&attempt.keys)?;
    let outcome = verified.statement().outcome;
    evidence.record(verified);
    Ok(outcome)
}

/// The leader's side of the V2 attempts at one request.
struct V2Leader {
    provider: Arc<VerifyForeignTxProvider>,
    request: VerifyForeignTxRequestV2,
    triples: Arc<TripleStorage>,
    keygen_out: KeygenOutput,
    reconstruction_threshold: ReconstructionThreshold,
}

impl LeadV2Attempt for V2Leader {
    type Asset = OwnedAsset<PairedTriple>;
    type Signed = SignedVerdict;

    /// Waits for a triple pair while the request is open. The candidates follow the current
    /// indexer heights.
    async fn take_asset(
        &self,
        avoid: &BTreeSet<ParticipantId>,
    ) -> anyhow::Result<OwnedAsset<PairedTriple>> {
        let requested_chain = self.request.request.request.chain();
        let mut reported_wait = false;
        loop {
            anyhow::ensure!(
                self.provider
                    .v2
                    .open_requests
                    .get(self.request.id)
                    .is_some(),
                "the V2 request closed before a triple pair was free"
            );
            let candidates = self.provider.v2_attempt_candidates(requested_chain)?;
            let store: &DistributedAssetStorage<PairedTriple> = &self.triples;
            if let Some(triples) =
                take_owned_avoiding(store, candidates, avoid, ASSET_RECHECK_INTERVAL).await
            {
                return Ok(triples);
            }
            if !reported_wait {
                reported_wait = true;
                metrics::MPC_NUM_VERIFY_FOREIGN_TX_TRIPLE_WAITS.inc();
                tracing::warn!(
                    ?requested_chain,
                    "no triple pair of V2 capable chain supporters available, waiting"
                );
            }
        }
    }

    async fn run_attempt(
        &self,
        triples: OwnedAsset<PairedTriple>,
    ) -> Result<SignedVerdict, AttemptFailure> {
        let network = &self.provider.v2.network;
        let (channel, attempt) = open_led_attempt(
            network,
            VerifyForeignTxTaskId::VerifyForeignTxV2 {
                id: self.request.id,
                paired_triple_id: triples.id,
            },
            participants_from_triples(&triples.asset.0, &triples.asset.1),
            self.request.yield_id,
            self.provider.v2.participants.clone(),
        )
        .map_err(AttemptFailure::Cluster)?;
        let result = V2LeaderComputation {
            own_outcome: self.provider.spawn_own_inspection(&self.request, &attempt),
            attempt,
            request: self.request.clone(),
            keygen_out: self.keygen_out.clone(),
            reconstruction_threshold: self.reconstruction_threshold,
            triples: triples.asset,
        }
        .run(channel, network.attempt_evidence())
        .await;
        let outcome_label = match &result {
            Ok(_) => metrics::SUCCEEDED_OUTCOME_LABEL,
            Err(AttemptFailure::DeadlineExceeded { .. }) => {
                metrics::DEADLINE_EXCEEDED_OUTCOME_LABEL
            }
            Err(_) => metrics::FAILED_OUTCOME_LABEL,
        };
        for label in [metrics::TOTAL_RESULT_LABEL, outcome_label] {
            metrics::MPC_NUM_VERIFY_FOREIGN_TX_COMPUTATIONS_LED
                .with_label_values(&[label])
                .inc();
        }
        result
    }
}

/// The leader's side of a V2 attempt: it collects every node outcome, its own included, and
/// signs only when they all agree. [`AttemptEvidence`] keeps the outcomes as they arrive.
struct V2LeaderComputation {
    attempt: LedAttempt,
    own_outcome: oneshot::Receiver<anyhow::Result<NodeOutcome>>,
    request: VerifyForeignTxRequestV2,
    keygen_out: KeygenOutput,
    reconstruction_threshold: ReconstructionThreshold,
    triples: PairedTriple,
}

impl V2LeaderComputation {
    /// Runs the attempt for at most [`ATTEMPT_DEADLINE`] after the Start that `channel` sent.
    async fn run(
        self,
        channel: NetworkTaskChannel,
        evidence: &AttemptEvidence,
    ) -> Result<SignedVerdict, AttemptFailure> {
        let attempt = self.attempt.id;
        self.perform_leader_centric_computation(channel, ATTEMPT_DEADLINE)
            .await
            .map_err(|error| AttemptFailure::new(error, attempt, evidence))
    }
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<SignedVerdict> for V2LeaderComputation {
    async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<SignedVerdict> {
        let mut outcomes = AttemptOutcomes::new(self.attempt.participants.iter().copied());
        let mut own_outcome = self.own_outcome;
        let mut own_outcome_reported = false;
        let verdict = loop {
            let status = tokio::select! {
                own = &mut own_outcome, if !own_outcome_reported => {
                    own_outcome_reported = true;
                    let outcome = own.context("the leader's inspection stopped")??;
                    outcomes.record(self.attempt.leader, outcome)?
                }
                received = channel.receive_node_outcomes() => {
                    let PeerNodeOutcomes { from, outcomes: signed } = received?;
                    let verified = self.attempt.accept(from, signed)?;
                    outcomes.record(from, verified.statement().outcome)?
                }
            };
            match status {
                AttemptStatus::Pending => {}
                AttemptStatus::Agreed(verdict) => break verdict,
                AttemptStatus::Ended(end) => return Err(end.into()),
            }
        };

        let payload_hash = self
            .request
            .sign_payload(verdict.into())?
            .compute_msg_hash()?;
        let (signature, public_key) = OnlinePresignSignComputation {
            keygen_out: self.keygen_out,
            reconstruction_threshold: self.reconstruction_threshold,
            triples: self.triples,
            msg_hash: payload_hash.clone().into(),
            tweak: Tweak::new([0; 32]),
        }
        .compute(channel)
        .await?;
        Ok(SignedVerdict {
            verdict,
            payload_hash,
            signature: signature.context("the leader should obtain a signature")?,
            public_key,
        })
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}

/// The signature request a follower runs the shared signing protocol with. Only its payload and
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
        domain: request.request.domain_id,
    }
}
