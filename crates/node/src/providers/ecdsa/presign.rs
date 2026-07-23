use crate::background::InFlightGenerationTracker;
use crate::metrics::tokio_task_metrics::ECDSA_TASK_MONITORS;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::UniqueId;
use crate::protocol::run_protocol;
use crate::providers::ecdsa::triple::participants_from_triples;
use crate::providers::ecdsa::{
    EcdsaKeyshare, EcdsaSignatureProvider, EcdsaTaskId, KeygenOutput, TripleStorage,
};
use crate::providers::ecdsa_common;
use crate::tracking::AutoAbortTaskCollection;
use crate::{metrics, tracking};
use mpc_node_config::PresignatureConfig;
use mpc_primitives::domain::DomainId;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::time::Duration;
use threshold_signatures::ReconstructionThreshold as TSReconstructionThreshold;
use threshold_signatures::ecdsa::ot_based_ecdsa::triples::TripleGenerationOutput;
use threshold_signatures::ecdsa::ot_based_ecdsa::{
    PresignArguments, PresignOutput, presign::presign,
};
use threshold_signatures::participants::Participant;

pub type PresignatureStorage = ecdsa_common::PresignatureStorage<PresignOutput>;
pub type PresignOutputWithParticipants = ecdsa_common::PresignOutputWithParticipants<PresignOutput>;

impl EcdsaSignatureProvider {
    /// Continuously generates presignatures, trying to maintain the desired number of
    /// presignatures available, using the desired number of concurrent computations as
    /// specified in the config. Most of the time, this process would be waiting for
    /// more triples to be generated, as presignature generation is significantly faster
    /// than triple generation.
    ///
    /// Generated triples will be written to `presignature_store` as owned triples. Note
    /// that this function does not take care of the passive side of presignature
    /// generation (i.e. other participants of the computations this function initiates),
    /// so that needs to be separately handled.
    pub(super) async fn run_background_presignature_generation(
        client: Arc<MeshNetworkClient>,
        config: Arc<PresignatureConfig>,
        triple_store: Arc<TripleStorage>,
        domain_id: DomainId,
        keyshare: EcdsaKeyshare,
    ) -> ! {
        let keygen_out = keyshare.keygen_output;
        let presignature_store = keyshare.presignature_store;
        let reconstruction_threshold_usize: usize = keyshare
            .reconstruction_threshold
            .inner()
            .try_into()
            .expect("contract validation guarantees a valid threshold");
        let reconstruction_threshold =
            TSReconstructionThreshold::from(reconstruction_threshold_usize);

        let in_flight_generations = InFlightGenerationTracker::new();
        let progress_tracker = Arc::new(PresignatureGenerationProgressTracker {
            desired_presignatures_to_buffer: config.desired_presignatures_to_buffer,
            presignature_store: presignature_store.clone(),
            in_flight_generations: in_flight_generations.num_in_flight_atomic(),
            waiting_for_triples: AtomicBool::new(false),
        });
        let parallelism_limiter = Arc::new(tokio::sync::Semaphore::new(config.concurrency));
        let mut tasks = AutoAbortTaskCollection::new();
        loop {
            progress_tracker.update_progress();
            metrics::MPC_OWNED_NUM_PRESIGNATURES_ONLINE
                .set(presignature_store.num_owned_ready() as i64);
            metrics::MPC_OWNED_NUM_PRESIGNATURES_WITH_OFFLINE_PARTICIPANT
                .set(presignature_store.num_owned_offline() as i64);
            let my_presignatures_count: usize = presignature_store.num_owned();
            metrics::MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE.set(my_presignatures_count as i64);
            let should_generate = my_presignatures_count + in_flight_generations.num_in_flight()
                < config.desired_presignatures_to_buffer;
            if should_generate
                // There's no point to issue way too many in-flight computations, as they
                // will just be limited by the concurrency anyway.
                && in_flight_generations.num_in_flight()
                < config.concurrency * 2
            {
                let id = presignature_store.generate_and_reserve_id();
                progress_tracker.set_waiting_for_triples(true);
                let (paired_triple_id, (triple0, triple1)) = triple_store.take_owned().await;
                progress_tracker.set_waiting_for_triples(false);
                let participants = participants_from_triples(&triple0, &triple1);
                let task_id = EcdsaTaskId::Presignature {
                    id,
                    domain_id,
                    paired_triple_id,
                };
                let channel = match client.new_channel_for_task(task_id, participants.clone()) {
                    Ok(channel) => channel,
                    Err(err) => {
                        tracing::warn!(
                            "Failed to create new channel for task {:?} with error: {}",
                            task_id,
                            err
                        );
                        continue;
                    }
                };
                let in_flight = in_flight_generations.in_flight(1);
                let parallelism_limiter = parallelism_limiter.clone();
                let presignature_store = presignature_store.clone();
                let config_clone = config.clone();
                let keygen_out = keygen_out.clone();
                tasks.spawn_checked(
                    &format!("ecdsa presign; task_id: {:?}", task_id),
                    ECDSA_TASK_MONITORS
                        .presignature_generation_leader
                        .instrument(async move {
                            let _in_flight = in_flight;
                            let _semaphore_guard = parallelism_limiter.acquire().await?;
                            let presignature = PresignComputation {
                                reconstruction_threshold,
                                triple0,
                                triple1,
                                keygen_out,
                            }
                            .perform_leader_centric_computation(
                                channel,
                                Duration::from_secs(config_clone.timeout_sec),
                            )
                            .await?;
                            presignature_store.add_owned(
                                id,
                                PresignOutputWithParticipants {
                                    presignature,
                                    participants,
                                },
                            );

                            anyhow::Ok(())
                        }),
                );
                continue;
            }

            // If the store is full, try to discard some presignatures which cannot be used right now
            if my_presignatures_count == config.desired_presignatures_to_buffer {
                presignature_store.maybe_discard_owned(1).await;
            }

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    pub(super) async fn run_presignature_generation_follower(
        &self,
        channel: NetworkTaskChannel,
        id: UniqueId,
        domain_id: DomainId,
        paired_triple_id: UniqueId,
    ) -> anyhow::Result<()> {
        let leader = channel.sender().get_leader();
        // Both the new presignature id and the triples it consumes must be
        // owned by the leader, never one of ours.
        id.validate_owned_by(leader)?;
        paired_triple_id.validate_owned_by(leader)?;
        let keyshare = self.keyshare(domain_id)?;

        // The triple store is keyed by the domain's reconstruction threshold
        // `t`. For cait-sith the leader pairs exactly `t` participants, so the
        // channel participant count must match — cross-check it.
        let reconstruction_threshold = keyshare.reconstruction_threshold;
        let reconstruction_threshold_usize: usize = reconstruction_threshold.inner().try_into()?;
        if channel.participants().len() != reconstruction_threshold_usize {
            metrics::MPC_NUM_BAD_PEER_PRESIGN_REQUESTS
                .with_label_values(&[&domain_id.to_string()])
                .inc();
            anyhow::bail!(
                "CaitSith presign participant count ({}) does not match domain threshold t={}",
                channel.participants().len(),
                reconstruction_threshold_usize,
            );
        }
        let triple_store = self.triple_store_for_t(reconstruction_threshold)?;
        FollowerPresignComputation {
            reconstruction_threshold: TSReconstructionThreshold::from(
                reconstruction_threshold_usize,
            ),
            keygen_out: keyshare.keygen_output,
            triple_store,
            paired_triple_id,
            out_presignature_store: keyshare.presignature_store,
            out_presignature_id: id,
        }
        .perform_leader_centric_computation(
            channel,
            Duration::from_secs(self.config.presignature.timeout_sec),
        )
        .await?;

        Ok(())
    }
}

/// Performs an MPC presignature operation. This is shared for the initiator
/// and for passive participants.
pub struct PresignComputation {
    reconstruction_threshold: TSReconstructionThreshold,
    triple0: TripleGenerationOutput,
    triple1: TripleGenerationOutput,
    keygen_out: KeygenOutput,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<PresignOutput> for PresignComputation {
    async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<PresignOutput> {
        let cs_participants = channel
            .participants()
            .iter()
            .copied()
            .map(Participant::from)
            .collect::<Vec<_>>();
        let me = channel.my_participant_id();
        let protocol = presign(
            &cs_participants,
            me.into(),
            PresignArguments {
                triple0: self.triple0,
                triple1: self.triple1,
                keygen_out: self.keygen_out,
                threshold: self.reconstruction_threshold,
            },
        )?;
        let _timer = metrics::MPC_PRE_SIGNATURE_TIME_ELAPSED.start_timer();
        let presignature = run_protocol("presign cait-sith", channel, protocol).await?;
        Ok(presignature)
    }

    fn leader_waits_for_success(&self) -> bool {
        true
    }
}

/// Performs an MPC presignature operation as a follower.
/// The difference is: we need to read the triples from the triple store (which may fail),
/// and we need to write the presignature to the presignature store before completing.
pub struct FollowerPresignComputation {
    pub reconstruction_threshold: TSReconstructionThreshold,
    pub paired_triple_id: UniqueId,
    pub keygen_out: KeygenOutput,
    pub triple_store: Arc<TripleStorage>,

    pub out_presignature_store: Arc<PresignatureStorage>,
    pub out_presignature_id: UniqueId,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<()> for FollowerPresignComputation {
    async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<()> {
        let (triple0, triple1) = self.triple_store.take_unowned(self.paired_triple_id)?;
        let presignature = PresignComputation {
            reconstruction_threshold: self.reconstruction_threshold,
            triple0,
            triple1,
            keygen_out: self.keygen_out,
        }
        .compute(channel)
        .await?;
        self.out_presignature_store.add_unowned(
            self.out_presignature_id,
            PresignOutputWithParticipants {
                presignature,
                participants: channel.participants().to_vec(),
            },
        );
        Ok(())
    }

    fn leader_waits_for_success(&self) -> bool {
        true
    }
}

struct PresignatureGenerationProgressTracker {
    desired_presignatures_to_buffer: usize,
    presignature_store: Arc<PresignatureStorage>,
    in_flight_generations: Arc<AtomicUsize>,
    waiting_for_triples: AtomicBool,
}

impl PresignatureGenerationProgressTracker {
    pub fn set_waiting_for_triples(&self, waiting: bool) {
        self.waiting_for_triples
            .store(waiting, std::sync::atomic::Ordering::Relaxed);
        self.update_progress();
    }

    pub fn update_progress(&self) {
        tracking::set_progress(&format!(
            "Presignatures: available: {}/{}; generating: {}{}",
            self.presignature_store.num_owned(),
            self.desired_presignatures_to_buffer,
            self.in_flight_generations
                .load(std::sync::atomic::Ordering::Relaxed),
            if self
                .waiting_for_triples
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                " (waiting for triples)"
            } else {
                ""
            }
        ))
    }
}
