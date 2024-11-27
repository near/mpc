use crate::db::{DBCol, SecretDB};
use crate::primitives::{HasParticipants, ParticipantId};
use anyhow::Context;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::oneshot;

/// A unique ID representing an asset (a triple, a presignature, or a signature).
/// The ID shall be globally unique across all participants and across time.
///
/// The ID does not need to be globally unique across different *types* of assets,
/// as in, it is OK for a triple to have the same unique ID as a presignature.
///
/// The uniqueness of the unique ID is based on some assumptions:
///  - Participants follow the correct unique ID generation algorithm;
///    specifically, they each only pick unique IDs they are allowed to pick from.
///  - At least one second passes during a restart of the binary.
///
/// The unique ID contains three parts: the participant ID, the timestamp, and a
/// counter. The counter is used to distinguish between multiple assets generated
/// by the same participant during the same second.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UniqueId(u128);

impl UniqueId {
    /// Only for testing. Use `generate` or `pick_new_after` instead.
    pub fn new(participant_id: ParticipantId, timestamp: u64, counter: u32) -> Self {
        let id =
            ((participant_id.raw() as u128) << 96) | ((timestamp as u128) << 32) | counter as u128;
        Self(id)
    }

    /// Generates a unique ID using the current wall time.
    pub fn generate(participant_id: ParticipantId) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self::new(participant_id, now, 0)
    }

    pub fn participant_id(&self) -> ParticipantId {
        ParticipantId::from_raw((self.0 >> 96) as u32)
    }

    pub fn timestamp(&self) -> u64 {
        ((self.0 >> 32) & ((1u128 << 64) - 1)) as u64
    }

    pub fn counter(&self) -> u32 {
        (self.0 & ((1u128 << 32) - 1)) as u32
    }

    /// Returns the key prefix for the given participant ID. It can be used to
    /// perform a range query in the database for all keys for this participant.
    pub fn prefix_for_participant_id(participant_id: ParticipantId) -> Vec<u8> {
        participant_id.raw().to_be_bytes().to_vec()
    }

    /// Pick a new unique ID based on the current time, but ensuring that it is
    /// after the current unique ID. All unique IDs should be picked this way,
    /// except the very first one, which should be generated with `generate`.
    pub fn pick_new_after(&self) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now > self.timestamp() {
            Self::new(self.participant_id(), now, 0)
        } else {
            Self::new(self.participant_id(), self.timestamp(), self.counter() + 1)
        }
    }

    /// Add the given delta to the counter, returning a new unique ID.
    /// This is useful for generating multiple unique IDs in a row, for batched
    /// generation of multiple assets at once.
    pub fn add_to_counter(&self, delta: u32) -> anyhow::Result<Self> {
        let new_counter = self
            .counter()
            .checked_add(delta)
            .context("Counter overflow")?;
        Ok(Self::new(
            self.participant_id(),
            self.timestamp(),
            new_counter,
        ))
    }
}

impl Debug for UniqueId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("UniqueId")
            .field(&self.participant_id())
            .field(&self.timestamp())
            .field(&self.counter())
            .finish()
    }
}

impl BorshSerialize for UniqueId {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // We must serialize in big-endian order to ensure that the
        // lexicalgraphical order of the keys is the same as the numerical
        // order.
        writer.write_all(&self.0.to_be_bytes())
    }
}

impl BorshDeserialize for UniqueId {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut bytes = [0u8; 16];
        reader.read_exact(&mut bytes)?;
        Ok(Self(u128::from_be_bytes(bytes)))
    }
}


pub struct DoubleQueue<T>
    where T: Send + 'static {
    senders: [flume::Sender<(UniqueId, T)>; 2],
    receivers: [flume::Receiver<(UniqueId, T)>; 2],
    active_owned_queue_index: AtomicUsize,
}

impl<T> DoubleQueue<T>
    where T: Send + 'static {
    pub fn new() -> Self {
        let (sender1, receiver1) = flume::unbounded();
        let (sender2, receiver2) = flume::unbounded();
        Self {
            senders: [sender1, sender2],
            receivers: [receiver1, receiver2],
            active_owned_queue_index: AtomicUsize::new(0),
        }
    }

    fn take_owned_conditioned_from_queue(&self, queue_index: usize, condition: &impl Fn (&UniqueId, &T) -> bool) -> anyhow::Result<(UniqueId, T)> {
        loop {
            let (id, value) = self.receivers[queue_index].try_recv()?;
            if condition(&id, &value) {
                return Ok((id, value));
            } else {
                self.senders[1 - queue_index].send((id, value)).unwrap()
            }
        }
    }

    pub fn add_owned(&self, id: UniqueId, value: T) {
        let active_owned_queue_index = self.active_owned_queue_index.load(Ordering::SeqCst);
        self.senders[active_owned_queue_index].send((id, value)).unwrap()
    }

    pub fn take_owned_conditioned(&self, condition: impl Fn (&UniqueId, &T) -> bool) -> anyhow::Result<(UniqueId, T)> {
        let active_owned_queue_index = self.active_owned_queue_index.load(Ordering::SeqCst);
        let result = self.take_owned_conditioned_from_queue(active_owned_queue_index, &condition);

        if result.is_ok() {
            return result;
        }

        let new_active_owned_queue_index = 1 - active_owned_queue_index;
        let _ = self.active_owned_queue_index.compare_exchange(active_owned_queue_index, new_active_owned_queue_index, Ordering::SeqCst, Ordering::SeqCst);
        self.take_owned_conditioned_from_queue(new_active_owned_queue_index, &condition)
    }

    pub fn len(&self) -> usize {
        self.receivers[0].len() + self.receivers[1].len()
    }
}

/// Persistent storage for a single type of asset (triples or presignatures).
/// The storage is distributed across all participants, with each participant
/// owning some of the assets. Each asset has exactly one owner.
///
/// Only the owner of an asset may pick the asset for use in an MPC computation.
/// As the owner, the `take_owned` method removes the oldest asset from the
/// storage and returns it, waiting if there isn't one available yet.
/// As a passive participant of a computation, unowned assets are taken using
/// `take_unowned`.
pub struct DistributedAssetStorage<T>
where
    T: Serialize + DeserializeOwned + Send + 'static,
{
    db: Arc<SecretDB>,
    col: DBCol,
    my_participant_id: ParticipantId,
    owned_queue: DoubleQueue<T>,
    last_id: Mutex<Option<UniqueId>>,
    pending_unowned_assets: Arc<Mutex<HashMap<UniqueId, oneshot::Receiver<()>>>>,
}

impl<T> DistributedAssetStorage<T>
where
    T: Serialize + DeserializeOwned + Send + 'static,
{
    pub fn new(
        db: Arc<SecretDB>,
        col: DBCol,
        my_participant_id: ParticipantId,
    ) -> anyhow::Result<Self> {
        let owned_queue= DoubleQueue::new();

        // We're just going to replicate the owned assets to memory. It's not the most efficient,
        // but it's the simplest way to implement a multi-consumer, multi-producer queue that
        // supports asynchronous blocking when an asset isn't available.
        let mut last_id = None;
        for item in db.iter_range(
            col,
            &UniqueId::prefix_for_participant_id(my_participant_id),
            &UniqueId::prefix_for_participant_id(ParticipantId::from_raw(
                my_participant_id.raw().checked_add(1).unwrap(),
            )),
        ) {
            let (key, value) = item?;
            let id = UniqueId::try_from_slice(&key)?;
            let value = serde_json::from_slice(&value)?;
            owned_queue.add_owned(id, value);
            last_id = Some(id);
        }

        Ok(Self {
            db,
            col,
            my_participant_id,
            owned_queue,
            last_id: Mutex::new(last_id),
            pending_unowned_assets: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Generates an ID that won't conflict with existing ones, and reserves it
    /// so that the next call to the same function will return a different one.
    /// TODO(#10): This reservation does not persist across restarts, leading to
    /// the assumption that the clock moves forward at least a second across
    /// restarts.
    #[allow(dead_code)] // will be used for presignatures
    pub fn generate_and_reserve_id(&self) -> UniqueId {
        self.generate_and_reserve_id_range(1)
    }

    /// Same as `generate_and_reserve_id`, but for a range of IDs.
    /// The returned ID represents a range that starts from that ID and ending at
    /// that ID .add_to_counter(count - 1).
    pub fn generate_and_reserve_id_range(&self, count: u32) -> UniqueId {
        assert!(count > 0);
        let mut last_id = self.last_id.lock().unwrap();
        let start = match *last_id {
            Some(last_id) => last_id.pick_new_after(),
            None => UniqueId::generate(self.my_participant_id),
        };
        let end = start.add_to_counter(count - 1).unwrap();
        *last_id = Some(end);
        start
    }

    /// Returns the current number of owned assets in the database.
    pub fn num_owned(&self) -> usize {
        self.owned_queue.len()
    }

    pub fn take_owned_with_condition(&self, cond: impl Fn(&UniqueId, &T) -> bool) -> anyhow::Result<(UniqueId, T)> {
        // Can't fail, because we keep a sender alive.
        let (id, asset) = self.owned_queue.take_owned_conditioned(cond)?;
        let mut update = self.db.update();
        update.delete(self.col, &borsh::to_vec(&id).unwrap());
        update
            .commit()
            .expect("Unrecoverable error writing to database");
        Ok((id, asset))
    }


    /// used for tests
    #[allow(dead_code)]
    pub fn take_owned(&self) -> anyhow::Result<(UniqueId, T)> {
        self.take_owned_with_condition(|_, _| true)
    }

    /// Adds an owned asset to the storage.
    pub fn add_owned(&self, id: UniqueId, value: T) {
        let key = borsh::to_vec(&id).unwrap();
        let value_ser = serde_json::to_vec(&value).unwrap();
        let mut update = self.db.update();
        update.put(self.col, &key, &value_ser);
        update
            .commit()
            .expect("Unrecoverable error writing to database");
        // Can't fail, because we keep a receiver alive.
        self.owned_queue.add_owned(id, value);
    }

    /// For unowned assets, this should be called first before participating
    /// (passively) in the MPC computation for this asset. This is because the
    /// owner of the asset may see the computation as completed, and start using
    /// this asset, before we (as a passive participant) see the computation as
    /// completed. If the owner then starts using this asset in another
    /// computation, we would need to know that this asset is not yet available
    /// but is going to be. That's why this method marks the unowned asset as
    /// pending until the asset's computation is complete (successfully or not).
    pub fn prepare_unowned(&self, id: UniqueId) -> PendingUnownedAsset<T> {
        let (sender, receiver) = oneshot::channel();
        self.pending_unowned_assets
            .lock()
            .unwrap()
            .insert(id, receiver);
        PendingUnownedAsset {
            id,
            _done: sender,
            all_pending_unowned_assets: self.pending_unowned_assets.clone(),
            db: self.db.clone(),
            col: self.col,
            _phantom_data: std::marker::PhantomData,
        }
    }

    /// Removes an unowned asset from the storage and returns it. It blocks if
    /// the asset is pending, waiting for the computation to complete. It
    /// returns an error if we do not have the asset in our database.
    pub async fn take_unowned(&self, id: UniqueId) -> anyhow::Result<T> {
        let pending = self.pending_unowned_assets.lock().unwrap().remove(&id);
        if let Some(pending) = pending {
            // We aren't receiving anything, just waiting for the sender to be dropped.
            pending.await.ok();
        }
        let key = borsh::to_vec(&id).unwrap();
        let value_ser = self.db.get(self.col, &key)?.ok_or_else(|| {
            anyhow::anyhow!("Unowned {} not found in the database: {:?}", self.col, id)
        })?;
        let mut update = self.db.update();
        update.delete(self.col, &key);
        update
            .commit()
            .expect("Unrecoverable error writing to database");
        Ok(serde_json::from_slice(&value_ser)?)
    }
}

/// Dropping this marks the unowned asset as no longer pending.
/// Also provides a way to write the unowned asset to the db.
pub struct PendingUnownedAsset<T>
where
    T: Serialize + DeserializeOwned + Send + 'static,
{
    id: UniqueId,
    _done: oneshot::Sender<()>,
    all_pending_unowned_assets: Arc<Mutex<HashMap<UniqueId, oneshot::Receiver<()>>>>,
    db: Arc<SecretDB>,
    col: DBCol,
    _phantom_data: std::marker::PhantomData<fn() -> T>,
}

impl<T> Drop for PendingUnownedAsset<T>
where
    T: Serialize + DeserializeOwned + Send + 'static,
{
    fn drop(&mut self) {
        self.all_pending_unowned_assets
            .lock()
            .unwrap()
            .remove(&self.id);
    }
}

impl<T> PendingUnownedAsset<T>
where
    T: Serialize + DeserializeOwned + Send + 'static,
{
    /// Writes the unowned asset to the db, marking the asset as no longer
    /// pending.
    pub fn commit(self, value: T) {
        let key = borsh::to_vec(&self.id).unwrap();
        let value_ser = serde_json::to_vec(&value).unwrap();
        let mut update = self.db.update();
        update.put(self.col, &key, &value_ser);
        update
            .commit()
            .expect("Unrecoverable error writing to database");
    }
}


pub struct ProtocolsStorage<T>
where T: Serialize + DeserializeOwned + Send + HasParticipants + 'static {
    storage: DistributedAssetStorage<T>,
    last_alive_participants: Arc<Mutex<Vec<ParticipantId>>>
}

impl<T> ProtocolsStorage<T>
    where T: Serialize + DeserializeOwned + Send + HasParticipants + 'static {
    pub fn new(
        db: Arc<SecretDB>,
        col: DBCol,
        my_participant_id: ParticipantId,
        all_participant_ids: Vec<ParticipantId>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            storage: DistributedAssetStorage::<T>::new(db, col, my_participant_id)?,
            last_alive_participants: Arc::new(Mutex::new(all_participant_ids)),
        })
    }

    pub fn set_alive_participants_ids(
        &self,
        participants: Vec<ParticipantId>,
    ) {
        let mut last_alive_participants = self.last_alive_participants.lock().unwrap();
        if *last_alive_participants != participants {
            tracing::info!("Set of active participants changed from {:?} to {:?}", last_alive_participants, participants);
            *last_alive_participants = participants;
        }
    }

    pub fn generate_and_reserve_id_range(&self, count: u32) -> UniqueId {
        self.storage.generate_and_reserve_id_range(count)
    }

    pub fn generate_and_reserve_id(&self) -> UniqueId {
        self.storage.generate_and_reserve_id()
    }


    pub fn num_owned(&self) -> usize {
        self.storage.num_owned() * 2
    }

    pub async fn take_owned(&self, alive_participants_ids: Vec<ParticipantId>) -> (UniqueId, T) {
        self.set_alive_participants_ids(alive_participants_ids);
        loop {
            {
                let active_participants = self.last_alive_participants.lock().unwrap();
                let is_subset_of_active_participants = |_: &UniqueId, value: &T| {
                    value.is_subset_of_active_participants(&active_participants)
                };
                if let Ok((id, value)) = self.storage.take_owned_with_condition(is_subset_of_active_participants) {
                    return (id, value);
                }
            }
            tokio::task::yield_now().await;
        }
    }

    /// Adds an owned asset to the storage.
    pub fn add_owned(&self, id: UniqueId, value: T) {
        self.storage.add_owned(id, value)
    }

    pub fn prepare_unowned(&self, id: UniqueId) -> PendingUnownedAsset<T> {
        self.storage.prepare_unowned(id)
    }

    pub async fn take_unowned(&self, id: UniqueId) -> anyhow::Result<T> {
        self.storage.take_unowned(id).await
    }
}


#[cfg(test)]
mod tests {
    use super::{DoubleQueue, UniqueId};
    use crate::primitives::ParticipantId;
    use borsh::BorshDeserialize;
    use futures::future::{maybe_done, MaybeDone};
    use futures::FutureExt;

    #[test]
    fn test_double_queue() {
        let queue = DoubleQueue::<i32>::new();
        let common_id = UniqueId::new(ParticipantId::from_raw(42), 123, 456);
        queue.add_owned(common_id, 0);
        queue.add_owned(common_id, 1);
        queue.add_owned(common_id, 2);
        let Err(_) = queue.take_owned_conditioned(|_, _| false) else {
            panic!("should not be able to take value with false condition");
        };
        let Ok((id, value)) = queue.take_owned_conditioned(|_, value| value == &1) else {
            panic!("should be able to take presented value");
        };
        assert_eq!(id, common_id);
        assert_eq!(value, 1);

        let (id, value) = queue.take_owned_conditioned(|_, _| true).unwrap();
        assert_eq!(id, common_id);
        assert_eq!(value, 2);

        let Err(_) = queue.take_owned_conditioned(|_, _| false) else {
            panic!("should not be able to take value with false condition");
        };

        let (id, value) = queue.take_owned_conditioned(|_, _| true).unwrap();
        assert_eq!(id, common_id);
        assert_eq!(value, 0);

        let Err(_) = queue.take_owned_conditioned(|_, _| true) else {
            panic!("should not be able to take value from empty queue");
        };
    }

    #[test]
    fn test_unique_id() {
        let participant_id = ParticipantId::from_raw(42);
        let id = UniqueId::new(participant_id, 123, 456);
        assert_eq!(id.participant_id(), participant_id);
        assert_eq!(id.timestamp(), 123);
        assert_eq!(id.counter(), 456);
        assert_eq!(id.add_to_counter(2).unwrap().counter(), 458);
        assert_eq!(
            borsh::to_vec(&id).unwrap(),
            [0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0, 123, 0, 0, 1, 200]
        );
        assert_eq!(
            UniqueId::try_from_slice(&[0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0, 123, 0, 0, 1, 200])
                .unwrap(),
            id
        );
        assert_eq!(
            UniqueId::prefix_for_participant_id(participant_id),
            [0, 0, 0, 42]
        );
        let time_based_1 = UniqueId::generate(participant_id);
        let time_based_2 = time_based_1.pick_new_after();
        assert!(time_based_2 > time_based_1);
        std::thread::sleep(std::time::Duration::from_secs(1));
        let time_based_3 = time_based_2.pick_new_after();
        assert!(time_based_3.timestamp() > time_based_2.timestamp());
    }

    #[test]
    fn test_distributed_store_add_take_owned() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::SecretDB::new(dir.path(), [1; 16]).unwrap();
        let store = super::DistributedAssetStorage::<u32>::new(
            db,
            crate::db::DBCol::Triple,
            ParticipantId::from_raw(42),
        )
        .unwrap();
        assert_eq!(store.num_owned(), 0);

        // Put in two assets, then dequeue them.
        let id1 = store.generate_and_reserve_id();
        let id2 = store.generate_and_reserve_id_range(2);
        assert!(id2 > id1);
        store.add_owned(id1, 123);
        assert_eq!(store.num_owned(), 1);
        store.add_owned(id2, 456);
        assert_eq!(store.num_owned(), 2);
        let asset1 = store.take_owned().expect("queue is expected to have value");
        assert_eq!(asset1, (id1, 123));
        assert_eq!(store.num_owned(), 1);
        let asset2 = store.take_owned().expect("queue is expected to have value");
        assert_eq!(asset2, (id2, 456));
        assert_eq!(store.num_owned(), 0);

        // Dequeuing an asset before it's available will block.
        let Err(_) = store.take_owned() else {
            panic!("id3 should not be ready");
        };

        let id3 = id2.add_to_counter(1).unwrap();
        store.add_owned(id3, 789);
        let asset3 = store.take_owned().expect("queue is expected to have value");
        assert_eq!(asset3, (id3, 789));

        // Sanity check that generated IDs are monotonically increasing.
        let id4 = store.generate_and_reserve_id();
        assert!(id4 > id3);
    }

    #[test]
    fn test_distributed_store_add_owned_different_order() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::SecretDB::new(dir.path(), [1; 16]).unwrap();
        let store = super::DistributedAssetStorage::<u32>::new(
            db.clone(),
            crate::db::DBCol::Triple,
            ParticipantId::from_raw(42),
        )
        .unwrap();

        // Adding assets in a different order from when the IDs are generated
        // is fine. They are dequeued in the order that they are queued.
        let id1 = store.generate_and_reserve_id_range(3);
        let id2 = id1.add_to_counter(1).unwrap();
        let id3 = id1.add_to_counter(2).unwrap();

        let Err(_) = store.take_owned() else {
            panic!("nothing should not be ready");
        };
        let Err(_) = store.take_owned() else {
            panic!("nothing should not be ready");
        };

        store.add_owned(id3, 3);
        store.add_owned(id2, 2);

        assert_eq!(store.take_owned().expect("queue is expected to have value"), (id3, 3));
        assert_eq!(store.take_owned().expect("queue is expected to have value"), (id2, 2));

        store.add_owned(id1, 1);
        assert_eq!(store.take_owned().expect("queue is expected to have value"), (id1, 1));

        // Make sure that ID generation does not depend on the order of adding
        // them.
        let id4 = store.generate_and_reserve_id();
        assert!(id4 > id3);

        let id5 = store.generate_and_reserve_id();
        let id6 = store.generate_and_reserve_id();

        store.add_owned(id6, 6);
        store.add_owned(id5, 5);

        // If we reload the store from the db, then the order of the queue would
        // be based on the key. It doesn't have to be this way, but we test it
        // here just to clarify the current behavior.
        drop(store);
        let store = super::DistributedAssetStorage::<u32>::new(
            db,
            crate::db::DBCol::Triple,
            ParticipantId::from_raw(42),
        )
        .unwrap();
        assert_eq!(store.take_owned().expect("queue is expected to have value"), (id5, 5));
        assert_eq!(store.take_owned().expect("queue is expected to have value"), (id6, 6));
    }

    #[test]
    fn test_distribtued_store_add_take_unowned() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::SecretDB::new(dir.path(), [1; 16]).unwrap();
        let store = super::DistributedAssetStorage::<u32>::new(
            db,
            crate::db::DBCol::Triple,
            ParticipantId::from_raw(42),
        )
        .unwrap();

        let other = ParticipantId::from_raw(43);
        let id1 = UniqueId::new(other, 1, 0);

        // Put an unowned asset in, take it right after.
        store.prepare_unowned(id1).commit(123);
        assert_eq!(store.num_owned(), 0); // does not affect owned
        let asset1 = store.take_unowned(id1).now_or_never().unwrap().unwrap();
        assert_eq!(asset1, 123);
        // Taking it again would fail.
        assert!(store.take_unowned(id1).now_or_never().unwrap().is_err());

        // Taking an asset that never existed would immediately fail.
        let id2 = UniqueId::new(other, 2, 0);
        assert!(store.take_unowned(id2).now_or_never().unwrap().is_err());

        // Make an unowned asset pending, then take it. It should block
        // until we either commit or abandon it.
        let id3 = UniqueId::new(other, 3, 0);
        let id4 = UniqueId::new(other, 4, 0);
        let pending3 = store.prepare_unowned(id3);
        let pending4 = store.prepare_unowned(id4);
        let take3_fut = store.take_unowned(id3);
        let take4_fut = store.take_unowned(id4);
        let MaybeDone::Future(take3_fut) = maybe_done(take3_fut) else {
            panic!("id3 should not be ready");
        };
        let MaybeDone::Future(take4_fut) = maybe_done(take4_fut) else {
            panic!("id4 should not be ready");
        };
        pending3.commit(456);
        drop(pending4);
        let asset3 = take3_fut.now_or_never().unwrap().unwrap();
        let asset4 = take4_fut.now_or_never().unwrap();
        assert_eq!(asset3, 456);
        assert!(asset4.is_err());
    }

    #[test]
    fn test_distributed_store_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::SecretDB::new(dir.path(), [1; 16]).unwrap();
        let myself = ParticipantId::from_raw(42);
        let store = super::DistributedAssetStorage::<u32>::new(
            db.clone(),
            crate::db::DBCol::Triple,
            myself,
        )
        .unwrap();

        let id1 = store.generate_and_reserve_id_range(4);
        store.add_owned(id1, 1);
        store.add_owned(id1.add_to_counter(1).unwrap(), 2);
        store.add_owned(id1.add_to_counter(2).unwrap(), 3);
        store.add_owned(id1.add_to_counter(3).unwrap(), 4);

        let other = ParticipantId::from_raw(43);
        store.prepare_unowned(UniqueId::new(other, 1, 0)).commit(5);
        store.prepare_unowned(UniqueId::new(other, 2, 0)).commit(6);
        store.prepare_unowned(UniqueId::new(other, 3, 0)).commit(7);
        store.prepare_unowned(UniqueId::new(other, 4, 0)).commit(8);

        drop(store);
        let store =
            super::DistributedAssetStorage::<u32>::new(db, crate::db::DBCol::Triple, myself)
                .unwrap();
        assert_eq!(store.num_owned(), 4);
        assert_eq!(store.take_owned().expect("queue is expected to have value"), (id1, 1));
        assert_eq!(
            store.take_owned().expect("queue is expected to have value"),
            (id1.add_to_counter(1).unwrap(), 2)
        );
        assert_eq!(
            store.take_owned().expect("queue is expected to have value"),
            (id1.add_to_counter(2).unwrap(), 3)
        );
        assert_eq!(
            store.take_owned().expect("queue is expected to have value"),
            (id1.add_to_counter(3).unwrap(), 4)
        );

        assert_eq!(
            store
                .take_unowned(UniqueId::new(other, 1, 0))
                .now_or_never()
                .unwrap()
                .unwrap(),
            5
        );
    }
}
