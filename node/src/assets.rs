use crate::asset_queues::owned::{OnlineParticipantsQuery, OwnedAssetStorage};
use crate::asset_queues::AssetPrefix;
use crate::config::MpcConfig;
use crate::db::{DBCol, SecretDB};
use crate::primitives::ParticipantId;
use anyhow::Context;
use borsh::{BorshDeserialize, BorshSerialize};
use futures::FutureExt;
use mpc_contract::primitives::domain::DomainId;
use near_time::Clock;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::{Arc, Mutex};

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

/// Persistent storage for a single type of asset (triples or presignatures).
/// The storage is distributed across all participants, with each participant
/// owning some of the assets. Each asset has exactly one owner.
///
/// Only the owner of an asset may pick the asset for use in an MPC computation.
/// As the owner, the `take_owned` method removes a usable asset from the
/// storage and returns it, waiting if there isn't one available yet. An asset is
/// usable iff the set of participants associated with it are all alive.
///
/// As a passive participant of a computation, unowned assets are taken using
/// `take_unowned`.
pub struct UnownedAssetStorage<T>
where
    T: Serialize + DeserializeOwned + Send + 'static,
{
    db: Arc<SecretDB>,
    asset_prefix: AssetPrefix,
    _marker: std::marker::PhantomData<fn(*const T)>,
}

impl<T> UnownedAssetStorage<T>
where
    T: Serialize + DeserializeOwned + Send + 'static,
{
    pub fn new(db: Arc<SecretDB>, asset_prefix: AssetPrefix) -> anyhow::Result<Self> {
        Ok(Self {
            db,
            asset_prefix,
            _marker: std::marker::PhantomData,
        })
    }

    fn make_unowned_key(&self, id: UniqueId) -> Vec<u8> {
        let mut key = Vec::new();
        key.extend_from_slice(&borsh::to_vec(&self.asset_prefix).unwrap());
        key.extend_from_slice(&borsh::to_vec(&id).unwrap());
        key
    }

    /// Adds an unowned asset to the storage.
    pub fn add_unowned(&self, id: UniqueId, value: T) {
        let key = self.make_unowned_key(id);
        let value_ser = serde_json::to_vec(&value).unwrap();
        let mut update = self.db.update();
        update.put(DBCol::UnownedAsset, &key, &value_ser);
        update
            .commit()
            .expect("Unrecoverable error writing to database");
    }

    /// Removes an unowned asset from the storage and returns it. Returns
    /// an error if we do not have the asset in our database.
    pub fn consume_unowned(&self, id: UniqueId) -> anyhow::Result<T> {
        let key = self.make_unowned_key(id);
        let value_ser = self.db.get(DBCol::UnownedAsset, &key)?.ok_or_else(|| {
            anyhow::anyhow!(
                "Unowned asset kind {:?} not found in the database: {:?}",
                self.asset_prefix,
                id
            )
        })?;
        let mut update = self.db.update();
        update.delete(DBCol::UnownedAsset, &key);
        update
            .commit()
            .expect("Unrecoverable error writing to database");
        Ok(serde_json::from_slice(&value_ser)?)
    }
}

pub struct DistributedAssetStorage<T>
where
    T: Clone + Serialize + DeserializeOwned + Send + 'static,
{
    pub owned: OwnedAssetStorage<T>,
    pub unowned: UnownedAssetStorage<T>,
}

impl<T> DistributedAssetStorage<T>
where
    T: Clone + Serialize + DeserializeOwned + Send + 'static,
{
    pub fn new(
        clock: Clock,
        mpc_config: &MpcConfig,
        db: Arc<SecretDB>,
        asset_prefix: AssetPrefix,
        online_participants_query: OnlineParticipantsQuery,
    ) -> anyhow::Result<Self> {
        let owned = OwnedAssetStorage::new(
            clock,
            mpc_config,
            db.clone(),
            asset_prefix.clone(),
            online_participants_query,
        )?;
        let unowned = UnownedAssetStorage::new(db, asset_prefix)?;
        Ok(Self { owned, unowned })
    }
}

#[cfg(test)]
mod tests {
    use super::{DomainId, UniqueId};
    use crate::assets::DistributedAssetStorage;
    use crate::async_testing::{run_future_once, MaybeReady};
    use crate::primitives::ParticipantId;
    use crate::providers::HasParticipants;
    use borsh::BorshDeserialize;
    use futures::FutureExt;
    use near_time::FakeClock;
    use serde::{Deserialize, Serialize};
    use std::cmp::Eq;
    use std::default::Default;
    use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    struct ParticipantsWithI32(Vec<ParticipantId>, i32);

    impl HasParticipants for ParticipantsWithI32 {
        fn is_subset_of_active_participants(&self, active_participants: &[ParticipantId]) -> bool {
            self.0.iter().all(|p| active_participants.contains(p))
        }
    }

    // This test covers tricky cases around updates to the online participants
    #[test]
    fn test_owned_store_online_condition() {
        let clock = FakeClock::default();
        let cond_value = Arc::new(AtomicI32::new(0));
        let cond_value_query_count = Arc::new(AtomicUsize::new(0));
        let queue = DoubleQueue::new(clock.clock(), |cond, val| val % 2 == *cond, {
            let cond_value = cond_value.clone();
            let cond_value_query_count = cond_value_query_count.clone();
            Arc::new(move || {
                cond_value_query_count.fetch_add(1, Ordering::Relaxed);
                cond_value.load(Ordering::Relaxed)
            })
        });
        let id1 = UniqueId::new(ParticipantId::from_raw(42), 123, 456);
        let id2 = id1.add_to_counter(1).unwrap();
        let id3 = id1.add_to_counter(2).unwrap();
        let id4 = id1.add_to_counter(3).unwrap();
        queue.add_owned(id1, 1);
        queue.add_owned(id2, 3);
        queue.add_owned(id3, 5);

        // Make condition "% 2 == 1".
        cond_value.store(1, Ordering::Relaxed);
        assert_eq!(queue.take_owned().now_or_never().unwrap(), (id1, 1));
        assert_eq!(cond_value_query_count.load(Ordering::Relaxed), 1);

        // Make condition "% 2 == 0" and start taking an element.
        cond_value.store(0, Ordering::Relaxed);
        let fut = queue.take_owned();
        let MaybeReady::Future(fut) = run_future_once(fut) else {
            panic!("should not be able to take value when no element meets condition");
        };
        assert_eq!(cond_value_query_count.load(Ordering::Relaxed), 2);

        // Change the condition to "% 2 == 1". The task that has been waiting for an element
        // does not immediately notice the condition change, until a timer has passed.
        cond_value.store(1, Ordering::Relaxed);
        let MaybeReady::Future(fut) = run_future_once(fut) else {
            panic!("should not be able to take value even when cond value changed");
        };
        assert_eq!(cond_value_query_count.load(Ordering::Relaxed), 2);

        // Advance the clock so that the waiting task notices the condition change.
        clock.advance(near_time::Duration::seconds(1));
        assert_eq!(fut.now_or_never().unwrap(), (id2, 3));
        assert_eq!(cond_value_query_count.load(Ordering::Relaxed), 3);

        // This time change the condition before starting to take an element.
        // It will be observed immediately even though the clock has not been advanced.
        cond_value.store(0, Ordering::Relaxed);
        let fut = queue.take_owned();
        let MaybeReady::Future(fut) = run_future_once(fut) else {
            panic!("should not be able to take value when no element meets condition");
        };
        assert_eq!(cond_value_query_count.load(Ordering::Relaxed), 4);

        // Change the condition without advancing the clock. The waiting task won't notice.
        cond_value.store(1, Ordering::Relaxed);
        let MaybeReady::Future(fut) = run_future_once(fut) else {
            panic!("should not be able to take value even when cond value changed");
        };
        assert_eq!(cond_value_query_count.load(Ordering::Relaxed), 4);
        queue.add_owned(id4, 4);
        // Even though the condition changed, we may get an element returned that satisfied a
        // stale condition (there's no point to prevent that because there can always be
        // races).
        assert_eq!(fut.now_or_never().unwrap(), (id4, 4));
        assert_eq!(cond_value_query_count.load(Ordering::Relaxed), 4);

        // However, if we take_owned() again, we'll use the correct condition.
        assert_eq!(queue.take_owned().now_or_never().unwrap(), (id3, 5));
        assert_eq!(cond_value_query_count.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn test_distributed_assets_storage() {
        let clock = FakeClock::default();
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::SecretDB::new(dir.path(), [1; 16]).unwrap();
        let all_participants = vec![
            ParticipantId::from_raw(0),
            ParticipantId::from_raw(1),
            ParticipantId::from_raw(2),
            ParticipantId::from_raw(3),
        ];
        let first_participants_subset = vec![
            ParticipantId::from_raw(0),
            ParticipantId::from_raw(1),
            ParticipantId::from_raw(2),
        ];
        let second_participants_subset = vec![
            ParticipantId::from_raw(1),
            ParticipantId::from_raw(2),
            ParticipantId::from_raw(3),
        ];
        let alive_participants = Arc::new(Mutex::new(all_participants.clone()));
        let store = DistributedAssetStorage::<ParticipantsWithI32>::new(
            clock.clock(),
            db,
            vec![1, 2],
            |cond, val| val.is_subset_of_active_participants(cond),
            {
                let alive_participants = alive_participants.clone();
                Arc::new(move || alive_participants.lock().unwrap().clone())
            },
        )
        .unwrap();
        assert_eq!(store.num_owned(), 0);

        let id1 = store.generate_and_reserve_id();
        let id2 = store.generate_and_reserve_id();
        let id3 = store.generate_and_reserve_id();
        let id4 = store.generate_and_reserve_id();
        let id5 = store.generate_and_reserve_id();
        store.add_owned(id1, ParticipantsWithI32(all_participants.clone(), 123));
        assert_eq!(store.num_owned(), 1);
        store.add_owned(id2, ParticipantsWithI32(all_participants.clone(), 456));
        assert_eq!(store.num_owned(), 2);
        let asset1 = store.take_owned().now_or_never().unwrap();
        assert_eq!(
            asset1,
            (id1, ParticipantsWithI32(all_participants.clone(), 123))
        );
        assert_eq!(store.num_owned(), 1);
        store.add_owned(
            id3,
            ParticipantsWithI32(second_participants_subset.clone(), 789),
        );
        assert_eq!(store.num_owned(), 2);

        *alive_participants.lock().unwrap() = first_participants_subset.clone();
        let asset_fut = store.take_owned();

        let MaybeReady::Future(asset_fut) = run_future_once(asset_fut) else {
            panic!("Cannot take value since set of participants has changed");
        };

        store.add_owned(
            id4,
            ParticipantsWithI32(first_participants_subset.clone(), 101112),
        );

        let asset3 = store.take_owned().now_or_never().unwrap();
        assert_eq!(
            asset3,
            (
                id4,
                ParticipantsWithI32(first_participants_subset.clone(), 101112)
            )
        );

        let MaybeReady::Future(asset_fut) = run_future_once(asset_fut) else {
            panic!("Cannot take value since set of participants has changed");
        };

        store.add_owned(
            id4,
            ParticipantsWithI32(first_participants_subset.clone(), 131415),
        );
        assert_eq!(
            asset_fut.now_or_never().unwrap(),
            (
                id4,
                ParticipantsWithI32(first_participants_subset.clone(), 131415)
            )
        );
        assert_eq!(store.num_owned(), 0);

        // Now go back to all participants being available.
        *alive_participants.lock().unwrap() = all_participants.clone();
        store.add_owned(id5, ParticipantsWithI32(all_participants.clone(), 161718));
        assert_eq!(store.num_owned(), 1);

        // Previously ineligible assets (456, 789, and 161718) should now be available.
        assert_eq!(
            store.take_owned().now_or_never().unwrap(),
            (id2, ParticipantsWithI32(all_participants.clone(), 456))
        );
        assert_eq!(store.num_owned(), 2);

        assert_eq!(
            store.take_owned().now_or_never().unwrap(),
            (
                id3,
                ParticipantsWithI32(second_participants_subset.clone(), 789)
            )
        );
        assert_eq!(store.num_owned(), 1);

        assert_eq!(
            store.take_owned().now_or_never().unwrap(),
            (id5, ParticipantsWithI32(all_participants.clone(), 161718))
        );
        assert_eq!(store.num_owned(), 0);
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
        let store = DistributedAssetStorage::<u32>::new(
            FakeClock::default().clock(),
            db,
            crate::db::DBCol::Triple,
            None,
            ParticipantId::from_raw(42),
            |_, _| true,
            Arc::new(std::vec::Vec::new),
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
        let asset1 = store.take_owned().now_or_never().unwrap();
        assert_eq!(asset1, (id1, 123));
        assert_eq!(store.num_owned(), 1);
        let asset2 = store.take_owned().now_or_never().unwrap();
        assert_eq!(asset2, (id2, 456));
        assert_eq!(store.num_owned(), 0);

        // Dequeuing an asset before it's available will block.
        let asset3_fut = store.take_owned();
        let MaybeReady::Future(asset3_fut) = run_future_once(asset3_fut) else {
            panic!("id3 should not be ready");
        };

        let id3 = id2.add_to_counter(1).unwrap();
        store.add_owned(id3, 789);
        let asset3 = asset3_fut.now_or_never().unwrap();
        assert_eq!(asset3, (id3, 789));

        // Sanity check that generated IDs are monotonically increasing.
        let id4 = store.generate_and_reserve_id();
        assert!(id4 > id3);
    }

    #[test]
    fn test_distributed_store_add_owned_different_order() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::SecretDB::new(dir.path(), [1; 16]).unwrap();
        let store = DistributedAssetStorage::<u32>::new(
            FakeClock::default().clock(),
            db.clone(),
            crate::db::DBCol::Triple,
            None,
            ParticipantId::from_raw(42),
            |_, _| true,
            Arc::new(std::vec::Vec::new),
        )
        .unwrap();

        // Adding assets in a different order from when the IDs are generated
        // is fine. They are dequeued in the order that they are queued.
        let id1 = store.generate_and_reserve_id_range(3);
        let id2 = id1.add_to_counter(1).unwrap();
        let id3 = id1.add_to_counter(2).unwrap();

        let asset1_fut = store.take_owned();
        let MaybeReady::Future(asset1_fut) = run_future_once(asset1_fut) else {
            panic!("nothing should not be ready");
        };
        let asset2_fut = store.take_owned();
        let MaybeReady::Future(asset2_fut) = run_future_once(asset2_fut) else {
            panic!("nothing should not be ready");
        };

        store.add_owned(id3, 3);
        store.add_owned(id2, 2);

        assert_eq!(asset1_fut.now_or_never().unwrap(), (id3, 3));
        assert_eq!(asset2_fut.now_or_never().unwrap(), (id2, 2));

        store.add_owned(id1, 1);
        assert_eq!(store.take_owned().now_or_never().unwrap(), (id1, 1));

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
        let store = DistributedAssetStorage::<u32>::new(
            FakeClock::default().clock(),
            db,
            crate::db::DBCol::Triple,
            None,
            ParticipantId::from_raw(42),
            |_, _| true,
            Arc::new(std::vec::Vec::new),
        )
        .unwrap();
        assert_eq!(store.take_owned().now_or_never().unwrap(), (id5, 5));
        assert_eq!(store.take_owned().now_or_never().unwrap(), (id6, 6));
    }

    #[test]
    fn test_distribtued_store_add_take_unowned() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::SecretDB::new(dir.path(), [1; 16]).unwrap();
        let store = DistributedAssetStorage::<u32>::new(
            FakeClock::default().clock(),
            db,
            crate::db::DBCol::Triple,
            None,
            ParticipantId::from_raw(42),
            |_, _| true,
            Arc::new(std::vec::Vec::new),
        )
        .unwrap();

        let other = ParticipantId::from_raw(43);
        let id1 = UniqueId::new(other, 1, 0);
        let id2 = UniqueId::new(other, 2, 0);
        let id3 = UniqueId::new(other, 3, 0);
        store.add_unowned(id1, 123);
        store.add_unowned(id2, 234);
        assert_eq!(store.num_owned(), 0); // does not affect owned

        assert_eq!(store.take_unowned(id1).unwrap(), 123);
        assert!(store.take_unowned(id1).is_err());

        assert!(store.take_unowned(id3).is_err());
        assert_eq!(store.take_unowned(id2).unwrap(), 234);
        assert!(store.take_unowned(id2).is_err());
        assert!(store.take_unowned(id1).is_err());
    }

    #[test]
    fn test_distributed_store_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::SecretDB::new(dir.path(), [1; 16]).unwrap();
        let myself = ParticipantId::from_raw(42);
        let store = DistributedAssetStorage::<u32>::new(
            FakeClock::default().clock(),
            db.clone(),
            crate::db::DBCol::Triple,
            None,
            myself,
            |_, _| true,
            Arc::new(std::vec::Vec::new),
        )
        .unwrap();

        let id1 = store.generate_and_reserve_id_range(4);
        store.add_owned(id1, 1);
        store.add_owned(id1.add_to_counter(1).unwrap(), 2);
        store.add_owned(id1.add_to_counter(2).unwrap(), 3);
        store.add_owned(id1.add_to_counter(3).unwrap(), 4);

        let other = ParticipantId::from_raw(43);
        store.add_unowned(UniqueId::new(other, 1, 0), 5);
        store.add_unowned(UniqueId::new(other, 2, 0), 6);
        store.add_unowned(UniqueId::new(other, 3, 0), 7);
        store.add_unowned(UniqueId::new(other, 4, 0), 8);

        drop(store);
        let store = DistributedAssetStorage::<u32>::new(
            FakeClock::default().clock(),
            db,
            crate::db::DBCol::Triple,
            None,
            myself,
            |_, _| true,
            Arc::new(std::vec::Vec::new),
        )
        .unwrap();
        assert_eq!(store.num_owned(), 4);
        assert_eq!(store.take_owned().now_or_never().unwrap(), (id1, 1));
        assert_eq!(
            store.take_owned().now_or_never().unwrap(),
            (id1.add_to_counter(1).unwrap(), 2)
        );
        assert_eq!(
            store.take_owned().now_or_never().unwrap(),
            (id1.add_to_counter(2).unwrap(), 3)
        );
        assert_eq!(
            store.take_owned().now_or_never().unwrap(),
            (id1.add_to_counter(3).unwrap(), 4)
        );

        assert_eq!(store.take_unowned(UniqueId::new(other, 1, 0)).unwrap(), 5);
    }

    #[test]
    fn test_maybe_discard_unowned_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::SecretDB::new(dir.path(), [1; 16]).unwrap();
        let myself = ParticipantId::from_raw(42);

        let store = DistributedAssetStorage::<u32>::new(
            FakeClock::default().clock(),
            db.clone(),
            crate::db::DBCol::Triple,
            None,
            myself,
            |_, x| *x != 1,
            Arc::new(Vec::new),
        )
        .unwrap();

        // Push asset to the cold queue
        let id1 = store.generate_and_reserve_id_range(2);
        store.add_owned(id1, 1);
        store.add_owned(id1.add_to_counter(1).unwrap(), 2);
        assert_eq!(store.take_owned().now_or_never().unwrap().1, 2);
        assert_eq!(store.num_owned_offline(), 1);

        store.maybe_discard_owned(1).now_or_never().unwrap();

        drop(store);
        let store = DistributedAssetStorage::<u32>::new(
            FakeClock::default().clock(),
            db,
            crate::db::DBCol::Triple,
            None,
            myself,
            |_, _| true,
            Arc::new(std::vec::Vec::new),
        )
        .unwrap();

        assert_eq!(store.num_owned(), 0);
    }

    #[test]
    fn test_multiple_domains() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::SecretDB::new(dir.path(), [1; 16]).unwrap();
        let myself = ParticipantId::from_raw(42);
        let other = ParticipantId::from_raw(43);

        for i in 0..4 {
            let domain_id = Some(DomainId(i));
            let store = DistributedAssetStorage::<u64>::new(
                FakeClock::default().clock(),
                db.clone(),
                crate::db::DBCol::Presignature,
                domain_id,
                myself,
                |_, _| true,
                Arc::new(std::vec::Vec::new),
            )
            .unwrap();

            for j in 0..10 {
                store.add_owned(UniqueId::new(myself, j, 0), 10000 + i * 100 + j);
                store.add_unowned(UniqueId::new(other, j, 0), 20000 + i * 100 + j);
            }
            for j in 0..10 {
                assert_eq!(
                    store.take_owned().now_or_never().unwrap().1,
                    10000 + i * 100 + j
                );
                assert_eq!(
                    store.take_unowned(UniqueId::new(other, j, 0)).unwrap(),
                    20000 + i * 100 + j
                );
            }
            for j in 0..10 {
                store.add_owned(UniqueId::new(myself, 100 + j, 0), 30000 + i * 100 + j);
                store.add_unowned(UniqueId::new(other, 100 + j, 0), 40000 + i * 100 + j);
            }
        }

        for i in 0..4 {
            let domain_id = Some(DomainId(i));
            let store = DistributedAssetStorage::<u64>::new(
                FakeClock::default().clock(),
                db.clone(),
                crate::db::DBCol::Presignature,
                domain_id,
                myself,
                |_, _| true,
                Arc::new(std::vec::Vec::new),
            )
            .unwrap();

            for j in 0..10 {
                assert_eq!(
                    store.take_owned().now_or_never().unwrap().1,
                    30000 + i * 100 + j
                );
                assert_eq!(
                    store
                        .take_unowned(UniqueId::new(other, 100 + j, 0))
                        .unwrap(),
                    40000 + i * 100 + j
                );
            }
        }
    }
}
