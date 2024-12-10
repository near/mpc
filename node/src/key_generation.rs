use crate::config::Config;
use crate::db;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::{MpcTaskId, ParticipantId};
use crate::protocol::run_protocol;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{Aes128Gcm, KeyInit};
use anyhow::Context;
use cait_sith::protocol::Participant;
use cait_sith::KeygenOutput;
use k256::elliptic_curve::CurveArithmetic;
use k256::{Secp256k1,Scalar, AffinePoint};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Runs the key generation protocol, returning the key generated.
/// This protocol is identical for the leader and the followers.
pub async fn run_key_generation(
    channel: NetworkTaskChannel,
    me: ParticipantId,
    threshold: usize,
) -> anyhow::Result<KeygenOutput<Secp256k1>> {
    let cs_participants = channel
        .participants
        .iter()
        .copied()
        .map(Participant::from)
        .collect::<Vec<_>>();
    let protocol = cait_sith::keygen::<Secp256k1>(&cs_participants, me.into(), threshold)?;
    run_protocol("key generation", channel, me, protocol).await
}

/// Runs the key resharing protocol,
/// This protocol is identical for the leader and the followers.
/// When the set of old participants is the same as the set of new participants
/// then we talk about "key refresh"
/// This function would not succeed if:
///     - the number of participants common between old and new is smaller
///     than the old threshold
///     - the threshold is larger than the number of participants
pub async fn reshare(
    channel: NetworkTaskChannel,
    me: ParticipantId,
    new_threshold: usize,
    old_participants: &[Participant],
    old_threshold: usize,
    my_share: Option<Scalar>,
    public_key: AffinePoint,
)-> anyhow::Result<<Secp256k1 as CurveArithmetic>::Scalar> {
    let new_participants = channel
        .participants
        .iter()
        .copied()
        .map(Participant::from)
        .collect::<Vec<_>>();
    let protocol = cait_sith::reshare::<Secp256k1>(
            &old_participants,
            old_threshold,
            &new_participants,
            new_threshold,
            me.into(),
            my_share,
            public_key,
        )?;
    run_protocol("key resharing", channel, me, protocol).await
}


/// Reads the root keyshare (keygen output) from disk.
pub fn load_root_keyshare(
    home_dir: &Path,
    encryption_key: [u8; 16],
) -> anyhow::Result<KeygenOutput<Secp256k1>> {
    let key_path = home_dir.join("key");
    let cipher = Aes128Gcm::new(GenericArray::from_slice(&encryption_key));
    let data = std::fs::read(key_path).context("Failed to read keygen file")?;
    let decrypted = db::decrypt(&cipher, &data).context("Failed to decrypt keygen")?;
    serde_json::from_slice(&decrypted).context("Failed to parse keygen")
}

/// Saves the root keyshare to disk independently of whether it already exist or not.
fn save_root_keyshare(
    home_dir: &Path,
    encryption_key: [u8; 16],
    keygen_out: &KeygenOutput<Secp256k1>,
) -> anyhow::Result<()> {
    let key_path = home_dir.join("key");
    let cipher = Aes128Gcm::new(GenericArray::from_slice(&encryption_key));
    let data = serde_json::to_vec(keygen_out).context("Failed to serialize keygen")?;
    let encrypted = db::encrypt(&cipher, &data);
    std::fs::write(key_path, &encrypted).context("Failed to write keygen file")
}
// verifies that no root key exists then encrypts the root keyshare (keygen output) to disk
fn keygen_save_root_keyshare(
    home_dir: &Path,
    encryption_key: [u8; 16],
    keygen_out: &KeygenOutput<Secp256k1>,
) -> anyhow::Result<()> {
    assert_root_key_does_not_exist(home_dir);
    save_root_keyshare(home_dir, encryption_key, keygen_out)
}

/// Panics if the root keyshare file already exists.
fn assert_root_key_does_not_exist(home_dir: &Path) {
    if home_dir.join("key").exists() {
        panic!("Root keyshare file already exists; refusing to overwrite");
    }
}

/// Opens a channel between client and protocol participants w.r.t. a specific task
async fn create_channel(
        config: &Arc<Config>,
        client: &Arc<MeshNetworkClient>,
        mut channel_receiver: mpsc::Receiver<NetworkTaskChannel>,
        task: MpcTaskId,
) -> anyhow::Result<NetworkTaskChannel>{
    let my_participant_id = client.my_participant_id();
    let is_leader = my_participant_id
        == config
            .mpc
            .participants
            .participants
            .iter()
            .map(|p| p.id)
            .min()
            .unwrap();

    let channel = if is_leader {
        client.new_channel_for_task(task, client.all_participant_ids())?
    } else {
        let channel = channel_receiver.recv().await.unwrap();
        if channel.task_id != task {
            anyhow::bail!(
                "Received task ID is not key generation: {:?}",
                channel.task_id
            );
        }
        channel
    };
    Ok(channel)
}

/// Performs the key generation protocol, saving the keyshare to disk.
/// Returns when the key generation is complete or runs into an error.
/// This is expected to only succeed if all participants are online
/// and running this function.
pub async fn run_key_generation_client(
    home_dir: PathBuf,
    config: Arc<Config>,
    client: Arc<MeshNetworkClient>,
    channel_receiver: mpsc::Receiver<NetworkTaskChannel>,
) -> anyhow::Result<()> {
    assert_root_key_does_not_exist(&home_dir);
    let channel = create_channel(&config, &client, channel_receiver, MpcTaskId::KeyGeneration).await?;

    let key = run_key_generation(
        channel,
        client.my_participant_id(),
        config.mpc.participants.threshold as usize,
    )
    .await?;
    keygen_save_root_keyshare(&home_dir, config.secret_storage.aes_key, &key)?;
    tracing::info!("Key generation completed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{run_key_generation, save_root_keyshare};
    use crate::network::testing::run_test_clients;
    use crate::network::{MeshNetworkClient, NetworkTaskChannel};
    use crate::primitives::MpcTaskId;
    use crate::tests::TestGenerators;
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
            client.new_channel_for_task(MpcTaskId::KeyGeneration, client.all_participant_ids())?
        } else {
            channel_receiver
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("No channel"))?
        };
        let key = run_key_generation(channel, participant_id, 3).await?;

        Ok(key)
    }

    #[test]
    fn test_keygen_store() {
        let dir = tempfile::tempdir().unwrap();
        let encryption_key = [1; 16];
        let generated_key = TestGenerators::new(2, 2)
            .make_keygens()
            .into_iter()
            .next()
            .unwrap()
            .1;

        save_root_keyshare(dir.path(), encryption_key, &generated_key).unwrap();
        let loaded_key = super::load_root_keyshare(dir.path(), encryption_key).unwrap();
        assert_eq!(generated_key.private_share, loaded_key.private_share);
        assert_eq!(generated_key.public_key, loaded_key.public_key);
    }
}
