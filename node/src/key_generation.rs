use crate::network::NetworkTaskChannel;
use crate::primitives::ParticipantId;
use crate::protocol::run_protocol;
use cait_sith::protocol::Participant;
use cait_sith::KeygenOutput;
use k256::Secp256k1;

/// Runs the key generation protocol, returning the key generated.
/// This protocol is identical for the leader and the followers.
pub async fn run_key_generation(
    channel: NetworkTaskChannel,
    participants: Vec<ParticipantId>,
    me: ParticipantId,
    threshold: usize,
) -> anyhow::Result<KeygenOutput<Secp256k1>> {
    let cs_participants = participants
        .iter()
        .copied()
        .map(Participant::from)
        .collect::<Vec<_>>();
    let protocol = cait_sith::keygen::<Secp256k1>(&cs_participants, me.into(), threshold)?;
    run_protocol("key generation", channel, participants, me, protocol).await
}

#[cfg(test)]
mod tests {
    use super::run_key_generation;
    use crate::network::testing::run_test_clients;
    use crate::network::{MeshNetworkClient, NetworkTaskChannel};
    use crate::primitives::MpcTaskId;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use cait_sith::KeygenOutput;
    use k256::Secp256k1;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_key_generation() {
        start_root_task_with_periodic_dump(async move {
            let results = run_test_clients(4, run_keygen_client).await.unwrap();
            println!("{:?}", results);
        })
        .await;
    }

    async fn run_keygen_client(
        client: Arc<MeshNetworkClient>,
        mut channel_receiver: mpsc::Receiver<NetworkTaskChannel>,
    ) -> anyhow::Result<KeygenOutput<Secp256k1>> {
        let participant_id = client.my_participant_id();
        let all_participant_ids = client.all_participant_ids();

        // We'll have the first participant be the leader.
        let channel = if participant_id == all_participant_ids[0] {
            client.new_channel_for_task(MpcTaskId::KeyGeneration)?
        } else {
            channel_receiver
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("No channel"))?
        };
        let key =
            run_key_generation(channel, all_participant_ids.clone(), participant_id, 3).await?;

        Ok(key)
    }
}
