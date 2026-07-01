use crate::network::NetworkTaskChannel;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::protocol::run_protocol;
use crate::providers::cheetah::CheetahSignatureProvider;
use rand::rngs::OsRng;
use threshold_signatures::ReconstructionThreshold;
use threshold_signatures::frost::cheetah::{CheetahTip5, KeygenOutput};
use threshold_signatures::participants::Participant;

impl CheetahSignatureProvider {
    pub(super) async fn run_key_generation_client_internal(
        threshold: ReconstructionThreshold,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<KeygenOutput> {
        let key = KeyGenerationComputation { threshold }
            .perform_leader_centric_computation(channel, std::time::Duration::from_secs(60))
            .await?;
        tracing::info!("Cheetah key generation completed");

        Ok(key)
    }
}

/// Runs the key generation protocol; identical for leader and followers.
pub struct KeyGenerationComputation {
    threshold: ReconstructionThreshold,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<KeygenOutput> for KeyGenerationComputation {
    async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<KeygenOutput> {
        let cs_participants = channel
            .participants()
            .iter()
            .copied()
            .map(Participant::from)
            .collect::<Vec<_>>();
        let me = channel.my_participant_id();
        let protocol = threshold_signatures::keygen::<CheetahTip5, _, _>(
            &cs_participants,
            me.into(),
            self.threshold,
            OsRng,
        )?;
        run_protocol("cheetah key generation", channel, protocol).await
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}
