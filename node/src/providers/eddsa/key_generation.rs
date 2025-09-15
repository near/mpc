use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::NetworkTaskChannel;
use crate::protocol::run_protocol;
use crate::providers::eddsa::EddsaSignatureProvider;
use threshold_signatures::eddsa::KeygenOutput;
use threshold_signatures::frost_ed25519::Ed25519Sha512;
use threshold_signatures::protocol::Participant;

impl EddsaSignatureProvider {
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
        tracing::info!("Eddsa key generation completed");

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
        let protocol = threshold_signatures::keygen::<Ed25519Sha512>(
            &cs_participants,
            me.into(),
            self.threshold,
        )?;
        run_protocol("eddsa key generation", channel, protocol).await
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
    use crate::providers::eddsa::key_generation::KeyGenerationComputation;
    use crate::providers::eddsa::EddsaTaskId;
    use crate::tests::TestGenerators;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use mpc_contract::primitives::domain::DomainId;
    use mpc_contract::primitives::key_state::{AttemptId, EpochId, KeyEventId};
    use std::sync::Arc;
    use threshold_signatures::eddsa::KeygenOutput;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn eddsa_test_key_generation() {
        start_root_task_with_periodic_dump(async move {
            let results = run_test_clients(
                TestGenerators::new(4, 3).participant_ids(),
                run_keygen_client,
            )
            .await
            .unwrap();
            println!("{:?}", results);
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
                EddsaTaskId::KeyGeneration {
                    key_event: KeyEventId::new(
                        EpochId::new(42),
                        DomainId::legacy_ecdsa_id(),
                        AttemptId::legacy_attempt_id(),
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
