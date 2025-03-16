use crate::config::MpcConfig;
use crate::keyshare::{KeyshareStorage, RootKeyshareData};
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::{EcdsaTaskId, MpcTaskId};
use crate::protocol::run_protocol;
use anyhow::Context;
use cait_sith::protocol::Participant;
use cait_sith::KeygenOutput;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, Secp256k1};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Runs the key generation protocol, returning the key generated.
/// This protocol is identical for the leader and the followers.
pub struct KeyGenerationComputation {
    threshold: usize,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<KeygenOutput<Secp256k1>> for KeyGenerationComputation {
    async fn compute(
        self,
        channel: &mut NetworkTaskChannel,
    ) -> anyhow::Result<KeygenOutput<Secp256k1>> {
        let cs_participants = channel
            .participants()
            .iter()
            .copied()
            .map(Participant::from)
            .collect::<Vec<_>>();
        let me = channel.my_participant_id();
        let protocol = cait_sith::keygen::<Secp256k1>(&cs_participants, me.into(), self.threshold)?;
        run_protocol("key generation", channel, protocol).await
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}

/// Performs the key generation protocol, saving the keyshare to disk.
/// Returns when the key generation is complete or runs into an error.
/// This is expected to only succeed if all participants are online
/// and running this function.
pub async fn run_key_generation_client(
    config: Arc<MpcConfig>,
    client: Arc<MeshNetworkClient>,
    keyshare_storage: Box<dyn KeyshareStorage>,
    mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
) -> anyhow::Result<()> {
    if keyshare_storage.load().await?.is_some() {
        anyhow::bail!("Keyshare already exists, refusing to run key generation");
    }

    let channel = if config.is_leader_for_keygen() {
        client.new_channel_for_task(EcdsaTaskId::KeyGeneration, client.all_participant_ids())?
    } else {
        loop {
            let channel = channel_receiver.recv().await.unwrap();
            if channel.task_id() != MpcTaskId::EcdsaTaskId(EcdsaTaskId::KeyGeneration) {
                tracing::info!(
                    "Received task ID is not key generation: {:?}; ignoring.",
                    channel.task_id()
                );
                continue;
            }
            break channel;
        }
    };
    let key = KeyGenerationComputation {
        threshold: config.participants.threshold as usize,
    }
    .perform_leader_centric_computation(
        channel,
        // TODO(#195): Move timeout here instead of in Coordinator.
        std::time::Duration::from_secs(60),
    )
    .await?;
    keyshare_storage
        .store(&RootKeyshareData::new(0, key.clone()))
        .await?;
    tracing::info!("Key generation completed");

    Ok(())
}

pub fn affine_point_to_public_key(point: AffinePoint) -> anyhow::Result<near_crypto::PublicKey> {
    Ok(near_crypto::PublicKey::SECP256K1(
        near_crypto::Secp256K1PublicKey::try_from(&point.to_encoded_point(false).as_bytes()[1..65])
            .context("Failed to convert affine point to public key")?,
    ))
}

#[cfg(test)]
mod tests {
    use crate::key_generation::KeyGenerationComputation;
    use crate::network::computation::MpcLeaderCentricComputation;
    use crate::network::testing::run_test_clients;
    use crate::network::{MeshNetworkClient, NetworkTaskChannel};
    use crate::primitives::EcdsaTaskId;
    use crate::tests::TestGenerators;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use cait_sith::KeygenOutput;
    use k256::Secp256k1;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_key_generation() {
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
    ) -> anyhow::Result<KeygenOutput<Secp256k1>> {
        let participant_id = client.my_participant_id();
        let all_participant_ids = client.all_participant_ids();

        // We'll have the first participant be the leader.
        let channel = if participant_id == all_participant_ids[0] {
            client.new_channel_for_task(EcdsaTaskId::KeyGeneration, client.all_participant_ids())?
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
