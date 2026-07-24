use crate::background::InFlightGenerationTracker;
use crate::config::MpcConfig;
use crate::metrics::tokio_task_metrics::ROBUST_ECDSA_TASK_MONITORS;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::UniqueId;
use crate::protocol::NamedProtocol;
use crate::providers::ecdsa_common;
use crate::providers::robust_ecdsa::{
    EcdsaKeyshare, KeygenOutput, RobustEcdsaSignatureProvider, RobustEcdsaTaskId,
    compute_thresholds,
};
use crate::tracking::AutoAbortTaskCollection;
use crate::{metrics, tracking};
use mpc_node_config::PresignatureConfig;
use mpc_primitives::domain::DomainId;
use rand::rngs::OsRng;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;
use threshold_signatures::MaxMalicious;
use threshold_signatures::ecdsa::robust_ecdsa::{
    PresignArguments, PresignOutput, presign::presign,
};
use threshold_signatures::participants::Participant;

pub type PresignatureStorage = ecdsa_common::PresignatureStorage<PresignOutput>;
pub type PresignOutputWithParticipants = ecdsa_common::PresignOutputWithParticipants<PresignOutput>;

/// Continuously generates presignatures, trying to maintain the desired number of
/// presignatures available, using the desired number of concurrent computations as
/// specified in the config.
///
/// Note that this function does not take care of the passive side of presignature
/// generation (i.e. other participants of the computations this function initiates),
/// so that needs to be separately handled.
pub(super) async fn run_background_presignature_generation(
    client: Arc<MeshNetworkClient>,
    mpc_config: Arc<MpcConfig>,
    config: Arc<PresignatureConfig>,
    domain_id: DomainId,
    keyshare: EcdsaKeyshare,
) -> ! {
    let keygen_out = keyshare.keygen_output;
    let presignature_store = keyshare.presignature_store;
    let reconstruction_threshold = keyshare.reconstruction_threshold;

    let in_flight_generations = InFlightGenerationTracker::new();
    let progress_tracker = Arc::new(PresignatureGenerationProgressTracker {
        desired_presignatures_to_buffer: config.desired_presignatures_to_buffer,
        presignature_store: presignature_store.clone(),
        in_flight_generations: in_flight_generations.num_in_flight_atomic(),
    });
    let parallelism_limiter = Arc::new(tokio::sync::Semaphore::new(config.concurrency));
    let mut tasks = AutoAbortTaskCollection::new();

    let running_participants: Vec<_> = mpc_config
        .participants
        .participants
        .iter()
        .map(|p| p.id)
        .collect();

    let (num_signers, damgard_et_al_threshold) = compute_thresholds(reconstruction_threshold)
        .expect("contract validation guarantees a valid threshold");

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
            let participants = match client
                .select_random_active_participants_including_me(num_signers, &running_participants)
            {
                Ok(participants) => participants,
                Err(e) => {
                    tracing::warn!(
                        "Can't choose active participants for a robust-ecdsa presignature: {}. Sleeping.",
                        e
                    );
                    // that should not happen often, so sleeping here is okay
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let task_id = RobustEcdsaTaskId::Presignature { id, domain_id };
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
                &format!("{:?}", task_id),
                ROBUST_ECDSA_TASK_MONITORS
                    .presignature_generation_leader
                    .instrument(async move {
                        let _in_flight = in_flight;
                        let _semaphore_guard = parallelism_limiter.acquire().await?;
                        let presignature = PresignComputation {
                            max_malicious: damgard_et_al_threshold,
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

impl RobustEcdsaSignatureProvider {
    pub(super) async fn run_presignature_generation_follower(
        &self,
        channel: NetworkTaskChannel,
        id: UniqueId,
        domain_id: DomainId,
    ) -> anyhow::Result<()> {
        id.validate_owned_by(channel.sender().get_leader())?;
        let keyshare = self.keyshare(domain_id)?;

        let (num_signers, damgard_et_al_threshold) =
            compute_thresholds(keyshare.reconstruction_threshold)?;
        if channel.participants().len() != num_signers {
            metrics::MPC_NUM_BAD_PEER_PRESIGN_REQUESTS
                .with_label_values(&[&domain_id.to_string()])
                .inc();
            anyhow::bail!(
                "robust-ECDSA presign participant count ({}) does not match required signer count {}",
                channel.participants().len(),
                num_signers,
            );
        }

        FollowerPresignComputation {
            max_malicious: damgard_et_al_threshold,
            keygen_out: keyshare.keygen_output,
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
    max_malicious: MaxMalicious,
    keygen_out: KeygenOutput,
}

impl NamedProtocol for PresignComputation {
    const NAME: &'static str = "presign robust-ecdsa";
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
                keygen_out: self.keygen_out,
                max_malicious: self.max_malicious,
            },
            OsRng,
        )?;
        let _timer = metrics::MPC_PRE_SIGNATURE_TIME_ELAPSED.start_timer();
        let presignature = Self::run(channel, protocol).await?;
        Ok(presignature)
    }

    fn leader_waits_for_success(&self) -> bool {
        true
    }
}

/// Performs an MPC presignature operation as a follower.
/// The difference is: we need to write the presignature to the presignature
/// store before completing.
pub struct FollowerPresignComputation {
    pub max_malicious: MaxMalicious,
    pub keygen_out: KeygenOutput,

    pub out_presignature_store: Arc<PresignatureStorage>,
    pub out_presignature_id: UniqueId,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<()> for FollowerPresignComputation {
    async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<()> {
        let presignature = PresignComputation {
            max_malicious: self.max_malicious,
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
}

impl PresignatureGenerationProgressTracker {
    pub fn update_progress(&self) {
        tracking::set_progress(&format!(
            "Presignatures: available: {}/{}; generating: {}",
            self.presignature_store.num_owned(),
            self.desired_presignatures_to_buffer,
            self.in_flight_generations
                .load(std::sync::atomic::Ordering::Relaxed),
        ))
    }
}
