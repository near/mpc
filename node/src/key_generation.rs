use crate::db::{DBCol, SecretDB};
use crate::network::NetworkTaskChannel;
use crate::primitives::ParticipantId;
use crate::protocol::run_protocol;
use cait_sith::protocol::Participant;
use cait_sith::KeygenOutput;
use k256::Secp256k1;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

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

/// Stores a single generated root key.
pub struct KeygenStorage {
    db: Arc<SecretDB>,
    generated: CancellationToken,
    key: Arc<tokio::sync::OnceCell<KeygenOutput<Secp256k1>>>,
}

impl KeygenStorage {
    /// Reads the generated key from the database, if it exists.
    /// If it exists, returns (self, None). Otherwise, returns (self, Some(KeygenNeeded))
    /// where the latter can be used to commit the key once it is generated.
    pub fn new(db: Arc<SecretDB>) -> anyhow::Result<(Arc<Self>, Option<KeygenNeeded>)> {
        let existing_key = read_generated_key_from_db(&db)?;
        let generated = CancellationToken::new();
        let key = Arc::new(tokio::sync::OnceCell::new());
        Ok(if let Some(existing_key) = existing_key {
            key.set(existing_key).ok();
            generated.cancel();
            (Self { db, generated, key }.into(), None)
        } else {
            let store = Arc::new(Self {
                db: db.clone(),
                generated: generated.clone(),
                key: key.clone(),
            });
            (store.clone(), Some(KeygenNeeded { store }))
        })
    }

    /// Retrieves the generated key, blocking until it is generated.
    pub async fn get_generated_key(&self) -> KeygenOutput<Secp256k1> {
        self.generated.cancelled().await;
        self.key.get().cloned().unwrap()
    }
}

pub struct KeygenNeeded {
    store: Arc<KeygenStorage>,
}

impl Drop for KeygenNeeded {
    fn drop(&mut self) {
        if !self.store.generated.is_cancelled() {
            panic!("Key generation was not completed");
        }
    }
}

impl KeygenNeeded {
    pub fn commit(self, keygen_out: KeygenOutput<Secp256k1>) {
        write_generated_key_to_db(&self.store.db, &keygen_out);
        self.store.key.set(keygen_out).ok();
        self.store.generated.cancel();
    }
}

fn read_generated_key_from_db(db: &SecretDB) -> anyhow::Result<Option<KeygenOutput<Secp256k1>>> {
    let keygen = db.get(DBCol::GeneratedKey, b"")?;
    Ok(keygen
        .map(|keygen| serde_json::from_slice(&keygen))
        .transpose()?)
}

fn write_generated_key_to_db(db: &Arc<SecretDB>, keygen: &KeygenOutput<Secp256k1>) {
    let mut update = db.update();
    update.put(
        DBCol::GeneratedKey,
        b"",
        &serde_json::to_vec(keygen).unwrap(),
    );
    update
        .commit()
        .expect("Failed to commit generated key to db");
}

#[cfg(test)]
mod tests {
    use super::run_key_generation;
    use crate::db::SecretDB;
    use crate::key_generation::KeygenStorage;
    use crate::network::testing::run_test_clients;
    use crate::network::{MeshNetworkClient, NetworkTaskChannel};
    use crate::primitives::MpcTaskId;
    use crate::tests::TestGenerators;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use cait_sith::KeygenOutput;
    use futures::future::{maybe_done, MaybeDone};
    use futures::FutureExt;
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
        let key =
            run_key_generation(channel, participant_id, 3).await?;

        Ok(key)
    }

    #[test]
    fn test_keygen_store() {
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let (store, needed) = KeygenStorage::new(db.clone()).unwrap();
        assert!(needed.is_some());

        // Getting the key should asynchronously block until the key is committed.
        let MaybeDone::Future(key) = maybe_done(store.get_generated_key()) else {
            panic!("Key should not already be available");
        };
        let generated_key = TestGenerators::new(2, 2)
            .make_keygens()
            .into_iter()
            .next()
            .unwrap()
            .1;
        needed.unwrap().commit(generated_key.clone());
        let key = key.now_or_never().unwrap();
        assert_eq!(key.private_share, generated_key.private_share);
        assert_eq!(key.public_key, generated_key.public_key);
        drop(store);

        // Reload the store; the key should be available immediately.
        let (store, needed) = KeygenStorage::new(db.clone()).unwrap();
        assert!(needed.is_none());
        let key = store.get_generated_key().now_or_never().unwrap();
        assert_eq!(key.private_share, generated_key.private_share);
    }
}
