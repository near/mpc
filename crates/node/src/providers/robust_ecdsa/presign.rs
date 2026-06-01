use crate::assets::DistributedAssetStorage;
use crate::background::InFlightGenerationTracker;
use crate::config::MpcConfig;
use crate::db::SecretDB;
use crate::metrics::tokio_task_metrics::ROBUST_ECDSA_TASK_MONITORS;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::{ParticipantId, UniqueId};
use crate::protocol::run_protocol;
use crate::providers::HasParticipants;
use crate::providers::robust_ecdsa::{
    KeygenOutput, RobustEcdsaSignatureProvider, RobustEcdsaTaskId, get_number_of_signers,
    translate_threshold,
};
use crate::tracking::AutoAbortTaskCollection;
use crate::{metrics, tracking};
use mpc_node_config::PresignatureConfig;
use mpc_primitives::domain::DomainId;
use near_time::Clock;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;
use threshold_signatures::MaxMalicious;
use threshold_signatures::ecdsa::robust_ecdsa::{
    PresignArguments, PresignOutput, presign::presign,
};
use threshold_signatures::participants::Participant;

#[derive(derive_more::Deref)]
pub struct PresignatureStorage(DistributedAssetStorage<PresignOutputWithParticipants>);

// TODO(#1680): simplify alive_participant_ids_query parameter type
impl PresignatureStorage {
    pub fn new(
        clock: Clock,
        db: Arc<SecretDB>,
        my_participant_id: ParticipantId,
        alive_participant_ids_query: Arc<dyn Fn() -> Vec<ParticipantId> + Send + Sync>,
        domain_id: DomainId,
    ) -> anyhow::Result<Self> {
        Ok(Self(DistributedAssetStorage::<
            PresignOutputWithParticipants,
        >::new(
            clock,
            db,
            crate::db::DBCol::Presignature,
            domain_id.0.to_be_bytes().to_vec(),
            None,
            my_participant_id,
            |participants, presignature| {
                presignature.is_subset_of_active_participants(participants)
            },
            alive_participant_ids_query,
        )?))
    }
}

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
    presignature_store: Arc<PresignatureStorage>,
    keygen_out: KeygenOutput,
) -> ! {
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

    let (num_signers, robust_ecdsa_threshold) = compute_thresholds(
        mpc_config.participants.threshold,
        running_participants.len(),
    )
    .expect("invalid governance threshold for robust-ECDSA");

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
                            max_malicious: robust_ecdsa_threshold,
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

/// Computes `(num_signers, robust_ecdsa_threshold)` and validates the
/// `2 * max_malicious + 1 <= num_signers` invariant. Returns an error only if
/// the configured governance threshold is invalid for robust-ECDSA.
///
/// TODO(#3164): once the node supports per-domain thresholds, this should
/// take the domain-specific threshold instead of the single governance threshold.
fn compute_thresholds(
    governance_threshold: u64,
    num_running_participants: usize,
) -> anyhow::Result<(usize, MaxMalicious)> {
    let governance_threshold: usize = governance_threshold.try_into()?;
    let num_signers = get_number_of_signers(governance_threshold, num_running_participants)?;
    let robust_ecdsa_threshold =
        translate_threshold(governance_threshold, num_running_participants)?;
    anyhow::ensure!(
        robust_ecdsa_threshold
            .value()
            .checked_mul(2)
            .and_then(|v| v.checked_add(1))
            .is_some_and(|v| v <= num_signers)
    );
    Ok((num_signers, robust_ecdsa_threshold))
}

impl RobustEcdsaSignatureProvider {
    pub(super) async fn run_presignature_generation_follower(
        &self,
        channel: NetworkTaskChannel,
        id: UniqueId,
        domain_id: DomainId,
    ) -> anyhow::Result<()> {
        id.validate_owned_by(channel.sender().get_leader())?;
        let domain_data = self.domain_data(domain_id)?;

        let number_of_participants = self.mpc_config.participants.participants.len();
        let threshold = self.mpc_config.participants.threshold.try_into()?;
        let robust_ecdsa_threshold = translate_threshold(threshold, number_of_participants)?;

        FollowerPresignComputation {
            max_malicious: robust_ecdsa_threshold,
            keygen_out: domain_data.keyshare,
            out_presignature_store: domain_data.presignature_store,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignOutputWithParticipants {
    pub presignature: PresignOutput,
    pub participants: Vec<ParticipantId>,
}

impl HasParticipants for PresignOutputWithParticipants {
    fn is_subset_of_active_participants(&self, active_participants: &[ParticipantId]) -> bool {
        self.participants
            .iter()
            .all(|p| active_participants.contains(p))
    }
}

/// Performs an MPC presignature operation. This is shared for the initiator
/// and for passive participants.
pub struct PresignComputation {
    max_malicious: MaxMalicious,
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
                keygen_out: self.keygen_out,
                max_malicious: self.max_malicious,
            },
            OsRng,
        )?;
        let _timer = metrics::MPC_PRE_SIGNATURE_TIME_ELAPSED.start_timer();
        let presignature = run_protocol("presign robust-ecdsa", channel, protocol).await?;
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

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::compute_thresholds;

    #[test]
    fn compute_thresholds__should_succeed_for_valid_governance_threshold() {
        // Given: in the current node, governance threshold == num_participants
        let governance_threshold = 5u64;
        let num_participants = 5;

        // When
        let result = compute_thresholds(governance_threshold, num_participants);

        // Then
        let (num_signers, robust_ecdsa_threshold) = result.unwrap();
        assert_eq!(num_signers, 5);
        assert!(2 * robust_ecdsa_threshold.value() < num_signers);
    }

    #[test]
    fn compute_thresholds__should_err_when_governance_threshold_too_small_for_robust_ecdsa() {
        // Given: robust-ECDSA requires the governance threshold to be at least 5
        let governance_threshold = 4u64;
        let num_participants = 4;

        // When
        let result = compute_thresholds(governance_threshold, num_participants);

        // Then
        result.unwrap_err();
    }

    #[test]
    fn compute_thresholds__should_err_when_governance_threshold_exceeds_participants() {
        // Given
        let governance_threshold = 8u64;
        let num_participants = 5;

        // When
        let result = compute_thresholds(governance_threshold, num_participants);

        // Then
        result.unwrap_err();
    }
}
