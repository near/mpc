use crate::config::ParticipantsConfig;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::NetworkTaskChannel;
use crate::primitives::ParticipantId;
use crate::protocol::run_protocol;
use crate::providers::eddsa::EddsaSignatureProvider;
use cait_sith::eddsa::KeygenOutput;
use cait_sith::protocol::Participant;
use frost_ed25519::keys::{PublicKeyPackage, SigningShare};

impl EddsaSignatureProvider {
    pub(super) async fn run_key_resharing_client_internal(
        new_threshold: usize,
        my_share: Option<SigningShare>,
        public_key: PublicKeyPackage,
        old_participants: &ParticipantsConfig,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<KeygenOutput> {
        let new_keyshare = KeyResharingComputation {
            threshold: new_threshold,
            old_participants: old_participants.participants.iter().map(|p| p.id).collect(),
            old_threshold: old_participants.threshold as usize,
            my_share,
            public_key,
        }
        .perform_leader_centric_computation(
            channel,
            // TODO(#195): Move timeout here instead of in Coordinator.
            std::time::Duration::from_secs(60),
        )
        .await?;
        tracing::info!("Key resharing completed");

        Ok(new_keyshare)
    }
}

/// Runs the key resharing protocol.
/// This protocol is identical for the leader and the followers.
/// When the set of old participants is the same as the set of new participants
/// then this is equivalent to "key refreshing".
/// This function would not succeed if:
///     - the number of participants common between old and new is smaller than
///       the old threshold; or
///     - the threshold is larger than the number of participants.
pub struct KeyResharingComputation {
    threshold: usize,
    old_participants: Vec<ParticipantId>,
    old_threshold: usize,
    my_share: Option<SigningShare>,
    public_key: PublicKeyPackage,
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

        let protocol = cait_sith::eddsa::dkg_ed25519::reshare(
            &old_participants,
            self.old_threshold,
            self.my_share,
            self.public_key,
            &new_participants,
            self.threshold,
            me.into(),
        )?;
        run_protocol("eddsa key resharing", channel, protocol).await
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use crate::network::computation::MpcLeaderCentricComputation;
    use crate::network::testing::run_test_clients;
    use crate::network::{MeshNetworkClient, NetworkTaskChannel};
    use crate::primitives::ParticipantId;
    use crate::tests::TestGenerators;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use mpc_contract::primitives::domain::DomainId;
    use mpc_contract::primitives::key_state::{AttemptId, EpochId, KeyEventId};
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use crate::providers::eddsa::EddsaTaskId;
    use crate::providers::eddsa::key_resharing::KeyResharingComputation;

    #[tokio::test]
    async fn test_key_resharing() {
        const THRESHOLD: usize = 3;
        const NUM_PARTICIPANTS: usize = 4;
        let gen = TestGenerators::new(NUM_PARTICIPANTS, THRESHOLD);
        let keygens = gen.make_eddsa_keygens();
        let old_participants = gen.participant_ids();
        let mut new_participants = gen.participant_ids();
        new_participants.push(ParticipantId::from_raw(rand::random()));

        let key_resharing_client_runner =
            move |client: Arc<MeshNetworkClient>,
                  mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>| {
                let client = client.clone();
                let participant_id = client.my_participant_id();
                let all_participant_ids = client.all_participant_ids();
                let keyshare = keygens.get(&participant_id.into()).map(|k| k.private_share);
                let pubkey = keygens.iter().next().unwrap().1.clone().public_key_package;
                let old_participants = old_participants.clone();
                let key_id = KeyEventId::new(
                    EpochId::new(42),
                    DomainId::legacy_ecdsa_id(),
                    AttemptId::legacy_attempt_id(),
                );
                async move {
                    // We'll have the first participant be the leader.
                    let channel = if participant_id == all_participant_ids[0] {
                        client.new_channel_for_task(
                            EddsaTaskId::KeyResharing { key_event: key_id },
                            client.all_participant_ids(),
                        )?
                    } else {
                        channel_receiver
                            .recv()
                            .await
                            .ok_or_else(|| anyhow::anyhow!("No channel"))?
                    };
                    let key = KeyResharingComputation {
                        threshold: THRESHOLD,
                        old_participants,
                        old_threshold: THRESHOLD,
                        my_share: keyshare,
                        public_key: pubkey,
                    }
                        .perform_leader_centric_computation(channel, std::time::Duration::from_secs(60))
                        .await?;
                    anyhow::Ok(key)
                }
            };

        start_root_task_with_periodic_dump(async move {
            let results = run_test_clients(new_participants, key_resharing_client_runner)
                .await
                .unwrap();
            println!("{:?}", results);
        })
            .await;
    }
}
