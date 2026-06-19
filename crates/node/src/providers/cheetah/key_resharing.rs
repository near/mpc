use crate::config::ParticipantsConfig;
use crate::network::NetworkTaskChannel;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::primitives::ParticipantId;
use crate::protocol::run_protocol;
use crate::providers::cheetah::CheetahSignatureProvider;
use rand::rngs::OsRng;
use threshold_signatures::ReconstructionThreshold;
use threshold_signatures::frost::cheetah::{CheetahTip5, KeygenOutput};
use threshold_signatures::frost_core::keys::SigningShare;
use threshold_signatures::frost_core::VerifyingKey;
use threshold_signatures::participants::Participant;

impl CheetahSignatureProvider {
    pub(super) async fn run_key_resharing_client_internal(
        new_threshold: ReconstructionThreshold,
        my_share: Option<SigningShare<CheetahTip5>>,
        public_key: VerifyingKey<CheetahTip5>,
        old_participants: &ParticipantsConfig,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<KeygenOutput> {
        let old_threshold: usize = old_participants.threshold.try_into()?;
        let new_keyshare = KeyResharingComputation {
            threshold: new_threshold,
            old_participants: old_participants.participants.iter().map(|p| p.id).collect(),
            old_threshold: ReconstructionThreshold::from(old_threshold),
            my_share,
            public_key,
        }
        .perform_leader_centric_computation(channel, std::time::Duration::from_secs(60))
        .await?;
        tracing::info!("Cheetah key resharing completed");

        anyhow::ensure!(
            new_keyshare.public_key == public_key,
            "Public key should not change after key resharing"
        );

        Ok(new_keyshare)
    }
}

/// Runs the key resharing protocol; identical for leader and followers. When the
/// old and new participant sets coincide this is "key refreshing".
pub struct KeyResharingComputation {
    threshold: ReconstructionThreshold,
    old_participants: Vec<ParticipantId>,
    old_threshold: ReconstructionThreshold,
    my_share: Option<SigningShare<CheetahTip5>>,
    public_key: VerifyingKey<CheetahTip5>,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<KeygenOutput> for KeyResharingComputation {
    async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<KeygenOutput> {
        let me = channel.my_participant_id();
        let new_participants = channel
            .participants()
            .iter()
            .copied()
            .map(Participant::from)
            .collect::<Vec<_>>();

        let old_participants = self
            .old_participants
            .into_iter()
            .map(Participant::from)
            .collect::<Vec<_>>();

        let protocol = threshold_signatures::reshare::<CheetahTip5, _, _, _>(
            &old_participants,
            self.old_threshold,
            self.my_share,
            self.public_key,
            &new_participants,
            self.threshold,
            me.into(),
            OsRng,
        )?;
        run_protocol("cheetah key resharing", channel, protocol).await
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}
