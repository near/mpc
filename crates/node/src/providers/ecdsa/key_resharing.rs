use crate::config::ParticipantsConfig;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::NetworkTaskChannel;
use crate::primitives::ParticipantId;
use crate::protocol::run_protocol;
use crate::providers::ecdsa::{EcdsaSignatureProvider, KeygenOutput};
use rand::rngs::OsRng;
use threshold_signatures::frost_secp256k1::keys::SigningShare;
use threshold_signatures::frost_secp256k1::{Secp256K1Sha256, VerifyingKey};
use threshold_signatures::participants::Participant;

impl EcdsaSignatureProvider {
    pub(super) async fn run_key_resharing_client_internal(
        new_threshold: usize,
        my_share: Option<SigningShare>,
        public_key: VerifyingKey,
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

        anyhow::ensure!(
            new_keyshare.public_key == public_key,
            "Public key should not change after key resharing"
        );

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
    public_key: VerifyingKey,
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

        let protocol = threshold_signatures::reshare::<Secp256K1Sha256>(
            &old_participants,
            self.old_threshold,
            self.my_share,
            self.public_key,
            &new_participants,
            self.threshold,
            me.into(),
            OsRng,
        )?;
        run_protocol("ecdsa key resharing", channel, protocol).await
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
    use crate::providers::ecdsa::key_resharing::KeyResharingComputation;
    use crate::providers::ecdsa::EcdsaTaskId;
    use crate::tests::into_participant_ids;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use mpc_contract::primitives::domain::DomainId;
    use mpc_contract::primitives::key_state::{AttemptId, EpochId, KeyEventId};
    use rand::SeedableRng as _;
    use std::sync::Arc;
    use threshold_signatures::test_utils::TestGenerators;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_key_resharing() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        const THRESHOLD: usize = 3;
        const NUM_PARTICIPANTS: usize = 4;
        let gen = TestGenerators::new(NUM_PARTICIPANTS, THRESHOLD);
        let keygens = gen.make_ecdsa_keygens(&mut rng);
        let pubkey = keygens.iter().next().unwrap().1.public_key;
        let old_participants = into_participant_ids(&gen);
        let mut new_participants = into_participant_ids(&gen);
        new_participants.push(ParticipantId::from_raw(rand::random()));

        let key_resharing_client_runner =
            move |client: Arc<MeshNetworkClient>,
                  mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>| {
                let client = client.clone();
                let participant_id = client.my_participant_id();
                let all_participant_ids = client.all_participant_ids();
                let keyshare = keygens.get(&participant_id.into()).map(|k| k.private_share);
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
                            EcdsaTaskId::KeyResharing { key_event: key_id },
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
