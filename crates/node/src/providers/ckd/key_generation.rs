use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::NetworkTaskChannel;
use crate::protocol::run_protocol;
use crate::providers::ckd::CKDProvider;
use rand::rngs::OsRng;
use threshold_signatures::confidential_key_derivation::KeygenOutput;
use threshold_signatures::confidential_key_derivation::BLS12381SHA256;
use threshold_signatures::participants::Participant;

impl CKDProvider {
    pub(super) async fn run_key_generation_client_internal(
        threshold: usize,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<KeygenOutput> {
        let key = KeyGenerationComputation { threshold }
            .perform_leader_centric_computation(
                channel,
                // TODO(#195): Move timeout here instead of in Coordinator.
                std::time::Duration::from_secs(60),
            )
            .await?;
        tracing::info!("CKD key generation completed");

        Ok(key)
    }
}

/// Runs the key generation protocol, returning the key generated.
/// This protocol is identical for the leader and the followers.
pub struct KeyGenerationComputation {
    threshold: usize,
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
        let protocol = threshold_signatures::keygen::<BLS12381SHA256>(
            &cs_participants,
            me.into(),
            self.threshold,
            OsRng,
        )?;
        run_protocol("CKD key generation", channel, protocol).await
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
    use crate::providers::ckd::key_generation::KeyGenerationComputation;
    use crate::providers::ckd::CKDTaskId;
    use crate::tests::into_participant_ids;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use mpc_contract::primitives::domain::DomainId;
    use mpc_contract::primitives::key_state::{AttemptId, EpochId, KeyEventId};
    use std::sync::Arc;
    use threshold_signatures::confidential_key_derivation::KeygenOutput;
    use threshold_signatures::frost_core::Group;
    use threshold_signatures::participants::Participant;
    use threshold_signatures::test_utils::TestGenerators;
    use threshold_signatures::{confidential_key_derivation as ckd, ParticipantList};
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn ckd_test_key_generation() {
        start_root_task_with_periodic_dump(async move {
            let participants_ids = into_participant_ids(&TestGenerators::new(4, 3));
            let results = run_test_clients(
                participants_ids.clone(),
                run_keygen_client,
            )
            .await
            .unwrap();
            let mut msk = ckd::Scalar::from(0);
            let pk = results[0].public_key.to_element();
            let participants = participants_ids.clone().iter().map(|p|Participant::from(*p)).collect::<Vec<_>>();
            let participants_list = ParticipantList::new(&participants).unwrap();
            for (key, participant) in results.iter().zip(participants) {
                msk += key.private_share.to_scalar() * participants_list.lagrange::<ckd::BLS12381SHA256>(participant).unwrap();
                assert_eq!(pk, key.public_key.to_element());
            }
            assert_eq!(<ckd::BLS12381SHA256 as threshold_signatures::frost_core::Ciphersuite>::Group::generator() * msk, pk);
        })
        .await;
    }

    async fn run_keygen_client(
        client: Arc<MeshNetworkClient>,
        mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
    ) -> anyhow::Result<KeygenOutput> {
        let participant_id = client.my_participant_id();
        let all_participant_ids = client.all_participant_ids();
        // We'll have the first participant be the leader.
        let channel = if participant_id == all_participant_ids[0] {
            client.new_channel_for_task(
                CKDTaskId::KeyGeneration {
                    key_event: KeyEventId::new(
                        EpochId::new(42),
                        DomainId::default(),
                        AttemptId::default(),
                    ),
                },
                client.all_participant_ids(),
            )?
        } else {
            channel_receiver
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("No channel"))?
        };
        let key = KeyGenerationComputation { threshold: 3 }
            .perform_leader_centric_computation(channel, std::time::Duration::from_secs(60))
            .await?;

        Ok(key)
    }
}
