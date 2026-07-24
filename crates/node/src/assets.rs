pub mod cleanup;
#[cfg(test)]
pub mod test_utils;

use crate::db::{DBCol, SecretDB, SecretDBUpdate};
use crate::primitives::{ParticipantId, UniqueId};
use crate::providers::HasParticipants;
use borsh::BorshDeserialize;
use futures::FutureExt;
use near_time::Clock;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};

/// The cold queue contains a collection of assets and a condition function.
/// The queue is divided into three sections by two barriers:
///
/// 0                            cold_ready           cold_available              queue.len()
///  -------------------------------- -------------------- -----------------------------
/// │  Condition-satisfying assets   |   Unknown assets   │   Non-satisfying assets     |
///  -----------------------------------------------------------------------------------
///
/// The queue may be modified in the following ways:
///   1. When taking assets which satisfy the condition we poll the front
///      of the queue, but not beyond the cold_available barrier.
///   2. When discarding assets *not* satisfying the condition we poll the back
///      of the queue, but not beyond the cold_ready barrier.
///   3. The condition is always evaluated before adding elements to the queue.
///      If the element *satisfies* the condition it is inserted at the front.
///      If the element *doesn't satisfy* the condition it is inserted at the back.
///   4. When the condition changes the barriers are reset, marking
///      the entire queue as unknown.
///
/// NB: Assets may be reordered by these operations. No guarantees are made on the order in which
/// assets are taken or discarded from the queue.
///
struct ColdQueue<T, CondVal: Default + Eq> {
    cold_ready: usize,
    cold_available: usize,
    cold_queue: VecDeque<(UniqueId, T)>,

    /// The last condition value that was used to check against the cold queue elements.
    /// Whenever the current condition value changes, we need to update the cold_available barrier.
    last_condition_value: CondVal,
    /// The actual condition function; this doesn't change.
    condition: fn(&CondVal, &T) -> bool,
    /// Function to fetch the condition value.
    condition_value_fetcher: Arc<dyn Fn() -> CondVal + Send + Sync>,
    /// The time when we should next fetch the condition value.
    next_fetch_due: near_time::Instant,
    clock: Clock,
}

impl<T, CondVal: Default + Eq> ColdQueue<T, CondVal> {
    pub(self) fn new(
        clock: Clock,
        condition: fn(&CondVal, &T) -> bool,
        condition_value_fetcher: Arc<dyn Fn() -> CondVal + Send + Sync>,
    ) -> Self {
        Self {
            cold_ready: 0,
            cold_available: 0,
            cold_queue: VecDeque::new(),
            last_condition_value: Default::default(),
            condition,
            condition_value_fetcher,
            next_fetch_due: clock.now(),
            clock,
        }
    }

    /// Unconditionally update the condition value;
    /// If the condition value changed, reset the barriers.
    pub(self) fn update_condition_value(&mut self) {
        const CONDITION_REFRESH_INTERVAL: near_time::Duration = near_time::Duration::seconds(1);
        self.next_fetch_due = self.clock.now() + CONDITION_REFRESH_INTERVAL;
        let new_condition_value = (self.condition_value_fetcher)();
        if new_condition_value != self.last_condition_value {
            self.last_condition_value = new_condition_value;
            self.cold_ready = 0;
            self.cold_available = self.cold_queue.len();
        }
    }

    fn update_condition_value_if_due(&mut self) {
        if self.clock.now() < self.next_fetch_due {
            return;
        }
        self.update_condition_value();
    }

    /// Try to remove and return an element that satisfies the current condition.
    /// If the element doesn't match, it will be moved to the end of the queue.
    pub(self) fn take(&mut self) -> ColdQueueTakeResult<T> {
        self.update_condition_value_if_due();
        if self.cold_available == 0 {
            return ColdQueueTakeResult::NotTakenAndNoneAvailable;
        }
        let (id, value) = self.cold_queue.pop_front().unwrap(); // can't fail
        self.cold_available -= 1;
        if self.cold_ready > 0 {
            self.cold_ready -= 1;
            return ColdQueueTakeResult::Taken((id, value));
        }
        if (self.condition)(&self.last_condition_value, &value) {
            return ColdQueueTakeResult::Taken((id, value));
        }
        self.cold_queue.push_back((id, value));
        ColdQueueTakeResult::NotTakenButSomeMayBeAvailable
    }

    /// Try to remove and return an element that *doesn't* satisfy the current condition.
    /// If the element does satisfy it, it will be moved to the front of the queue.
    pub(self) fn discard(&mut self) -> ColdQueueDiscardResult<T> {
        self.update_condition_value_if_due();
        if self.cold_ready == self.cold_queue.len() {
            return ColdQueueDiscardResult::NotDiscardedAndNoneAvailable;
        }
        let (id, value) = self.cold_queue.pop_back().unwrap(); // can't fail
        let condition_satisfied = if self.cold_available > self.cold_queue.len() {
            self.cold_available -= 1;
            (self.condition)(&self.last_condition_value, &value)
        } else {
            false
        };
        if !condition_satisfied {
            return ColdQueueDiscardResult::Discarded((id, value));
        }
        self.cold_queue.push_front((id, value));
        self.cold_ready += 1;
        self.cold_available += 1;
        ColdQueueDiscardResult::NotDiscardedButSomeMayBeAvailable
    }

    /// Adds an element to the cold queue. If the condition is *not* satisfied,
    /// instead of adding, it is returned. Otherwise, adds it to the front of the queue.
    pub(self) fn add_if_condition_satisfied(
        &mut self,
        id: UniqueId,
        value: T,
    ) -> ColdQueueAddIfSatisfiedResult<T> {
        self.update_condition_value_if_due();
        if (self.condition)(&self.last_condition_value, &value) {
            self.cold_queue.push_front((id, value));
            self.cold_ready += 1;
            self.cold_available += 1;
            return ColdQueueAddIfSatisfiedResult::Enqueued;
        }
        ColdQueueAddIfSatisfiedResult::ConditionNotSatisfied(value)
    }

    /// Adds an element to the cold queue. If the condition is satisfied,
    /// instead of adding, it is returned. Otherwise, adds it to the end of the cold
    /// queue after the barrier.
    pub(self) fn add_if_condition_not_satisfied(
        &mut self,
        id: UniqueId,
        value: T,
    ) -> ColdQueueAddIfNotSatisfiedResult<T> {
        self.update_condition_value_if_due();
        if (self.condition)(&self.last_condition_value, &value) {
            return ColdQueueAddIfNotSatisfiedResult::ConditionSatisfied(value);
        }
        self.cold_queue.push_back((id, value));
        ColdQueueAddIfNotSatisfiedResult::Enqueued
    }

    /// Adds an element whose status against the stored condition is unknown:
    /// inserted at the `cold_available` barrier so both sweep barriers stay
    /// valid for `take`/`discard`.
    pub(self) fn ingest(&mut self, id: UniqueId, value: T) {
        self.cold_queue.insert(self.cold_available, (id, value));
        self.cold_available += 1;
    }

    /// Removes the first element matching `cond_val` (a caller-supplied value,
    /// independent of the stored condition value), shifting the barriers that
    /// lie beyond the removed position.
    pub(self) fn take_first_matching(&mut self, cond_val: &CondVal) -> Option<(UniqueId, T)> {
        let pos = self
            .cold_queue
            .iter()
            .position(|(_, value)| (self.condition)(cond_val, value))?;
        let result = self.cold_queue.remove(pos);
        if pos < self.cold_ready {
            self.cold_ready -= 1;
        }
        if pos < self.cold_available {
            self.cold_available -= 1;
        }
        result
    }
}

enum ColdQueueTakeResult<T> {
    Taken((UniqueId, T)),
    NotTakenButSomeMayBeAvailable,
    NotTakenAndNoneAvailable,
}

enum ColdQueueDiscardResult<T> {
    Discarded((UniqueId, T)),
    NotDiscardedButSomeMayBeAvailable,
    NotDiscardedAndNoneAvailable,
}

enum ColdQueueAddIfSatisfiedResult<T> {
    ConditionNotSatisfied(T),
    Enqueued,
}

enum ColdQueueAddIfNotSatisfiedResult<T> {
    ConditionSatisfied(T),
    Enqueued,
}

pub struct DoubleQueue<T, CondVal: Default + Eq>
where
    T: Send + 'static,
{
    hot_sender: flume::Sender<(UniqueId, T)>,
    hot_receiver: flume::Receiver<(UniqueId, T)>,
    cold_queue: Arc<Mutex<ColdQueue<T, CondVal>>>,
    clock: Clock,
}

impl<T, CondVal: Default + Eq> DoubleQueue<T, CondVal>
where
    T: Send + 'static,
{
    pub fn new(
        clock: Clock,
        condition: fn(&CondVal, &T) -> bool,
        condition_value_fetcher: Arc<dyn Fn() -> CondVal + Send + Sync>,
    ) -> Self {
        let (hot_sender, hot_receiver) = flume::unbounded();
        Self {
            hot_sender,
            hot_receiver,
            cold_queue: Arc::new(Mutex::new(ColdQueue::new(
                clock.clone(),
                condition,
                condition_value_fetcher,
            ))),
            clock,
        }
    }

    pub fn add_owned(&self, id: UniqueId, value: T) {
        self.hot_sender.send((id, value)).unwrap()
    }

    pub async fn take_owned(&self) -> (UniqueId, T) {
        // Always query the new condition value before taking an element.
        // This is to prevent the case where the condition has been updated,
        // but we're not yet aware of it, and the caller calls this in a loop and
        // we keep yielding undesired elements, but the caller keeps throwing them
        // away and we quickly exhaust the available assets.
        self.cold_queue.lock().unwrap().update_condition_value();
        loop {
            let taken = self.cold_queue.lock().unwrap().take();
            match taken {
                ColdQueueTakeResult::Taken(result) => {
                    return result;
                }
                ColdQueueTakeResult::NotTakenButSomeMayBeAvailable => {
                    continue;
                }
                ColdQueueTakeResult::NotTakenAndNoneAvailable => {
                    // If the cold queue is exhausted, wait for a new element that is just produced.
                    // Then, if that element also doesn't satisfy our condition, we put it in the cold
                    // queue and continue.

                    tokio::select! {
                        _ = self.clock.sleep(near_time::Duration::seconds(1)) => {
                            // Don't wait for too long, because the condition could have changed
                            // making a cold queue element eligible.
                            continue;
                        }
                        received = self.hot_receiver.recv_async() => {
                            // can't fail, because self keeps a sender.
                            let (id, value) = received.unwrap();
                            match self.cold_queue.lock().unwrap().add_if_condition_not_satisfied(id, value) {
                                ColdQueueAddIfNotSatisfiedResult::ConditionSatisfied(value) => {
                                    return (id, value);
                                }
                                ColdQueueAddIfNotSatisfiedResult::Enqueued => {
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    pub async fn take_owned_matching(&self, cond_val: CondVal) -> (UniqueId, T) {
        loop {
            {
                let mut cold = self.cold_queue.lock().unwrap();
                // The stored condition value doesn't affect matching (the
                // predicate runs against `cond_val`); refreshed anyway so
                // matching-heavy periods don't leave it stale for
                // `take_owned`/`discard`.
                cold.update_condition_value_if_due();
                while let Some(Ok((id, value))) = self.hot_receiver.recv_async().now_or_never() {
                    cold.ingest(id, value);
                }
                if let Some(taken) = cold.take_first_matching(&cond_val) {
                    return taken;
                }
            }
            tokio::select! {
                _ = self.clock.sleep(near_time::Duration::seconds(1)) => {}
                received = self.hot_receiver.recv_async() => {
                    let (id, value) = received.unwrap();
                    self.cold_queue.lock().unwrap().ingest(id, value);
                }
            }
        }
    }

    /// Process `num_elements_to_process`, removing any that doesn't satisfy condition.
    /// Return ids, that were removed from cold storage.
    pub async fn maybe_discard_owned(&self, mut num_elements_to_process: usize) -> Vec<UniqueId> {
        self.cold_queue.lock().unwrap().update_condition_value();

        let mut removed_from_cold_queue: Vec<UniqueId> = vec![];

        // First process elements in the cold queue
        while num_elements_to_process > 0 {
            let discarded = self.cold_queue.lock().unwrap().discard();
            match discarded {
                ColdQueueDiscardResult::Discarded((id, _)) => {
                    removed_from_cold_queue.push(id);
                    num_elements_to_process -= 1;
                    continue;
                }
                ColdQueueDiscardResult::NotDiscardedButSomeMayBeAvailable => {
                    num_elements_to_process -= 1;
                    continue;
                }
                ColdQueueDiscardResult::NotDiscardedAndNoneAvailable => {
                    break;
                }
            }
        }

        // If the cold queue is exhausted, process elements buffered in the hot queue
        while num_elements_to_process > 0 {
            match self.hot_receiver.recv_async().now_or_never() {
                Some(Ok((id, value))) => {
                    num_elements_to_process -= 1;
                    let _ = self
                        .cold_queue
                        .lock()
                        .unwrap()
                        .add_if_condition_satisfied(id, value);
                }
                _ => {
                    // Nothing waiting in the hot queue
                    break;
                }
            }
        }

        removed_from_cold_queue
    }

    pub fn available(&self) -> usize {
        self.hot_receiver.len() + self.cold_queue.lock().unwrap().cold_available
    }

    pub fn ready(&self) -> usize {
        self.cold_queue.lock().unwrap().cold_ready
    }

    pub fn offline(&self) -> usize {
        let cold_queue = self.cold_queue.lock().unwrap();
        cold_queue.cold_queue.len() - cold_queue.cold_available
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
pub struct DistributedAssetStorage<T>
where
    T: Serialize + DeserializeOwned + Send + 'static,
{
    db: Arc<SecretDB>,
    col: DBCol,
    /// Byte prefix prepended to every key written under `col`. Empty `Vec` means
    /// no prefix (i.e. the original layout where keys were just
    /// `borsh(UniqueId)`).
    prefix: Vec<u8>,
    my_participant_id: ParticipantId,
    owned_queue: DoubleQueue<T, Vec<ParticipantId>>,
    last_id: Mutex<Option<UniqueId>>,
    /// Guards against concurrent `take_unowned` calls for the same ID.
    /// An ID is inserted before the DB read and removed after the delete commits,
    /// so two racing callers cannot both succeed for the same asset.
    unowned_in_flight: Mutex<HashSet<UniqueId>>,
}

/// Iterates over a key range in column `db_col`, determined by
/// [`DistributedAssetStorage::<T>::make_prefix_range(my_participant_id, prefix)`],
/// and stages a delete on `update_writer` for every entry that evaluates `false`
/// for `is_subset_of_active_participants(persistent_participants)`.
///
/// The caller is responsible for committing `update_writer`. Sharing a writer
/// across multiple calls lets a single cleanup pass (per-`t` triple columns +
/// per-domain presignature columns + epoch marker) be committed as one atomic
/// batch.
pub fn clean_db<T>(
    db: &Arc<SecretDB>,
    update_writer: &mut SecretDBUpdate,
    db_col: DBCol,
    persistent_participants: &[ParticipantId],
    my_participant_id: ParticipantId,
    prefix: &[u8],
) -> anyhow::Result<()>
where
    T: Serialize + DeserializeOwned + Send + 'static + HasParticipants,
{
    let (start, end): (Vec<u8>, Vec<u8>) =
        DistributedAssetStorage::<T>::make_prefix_range(my_participant_id, prefix);
    for item in db.iter_range(db_col, &start, &end) {
        let (key, value) = item?;
        let value: T = serde_json::from_slice(&value)?;
        if !value.is_subset_of_active_participants(persistent_participants) {
            update_writer.delete(db_col, &key);
        }
    }
    Ok(())
}

impl<T> DistributedAssetStorage<T>
where
    T: Serialize + DeserializeOwned + Send + 'static,
{
    pub fn new(
        clock: Clock,
        db: Arc<SecretDB>,
        col: DBCol,
        prefix: Vec<u8>,
        my_participant_id: ParticipantId,
        condition: fn(&Vec<ParticipantId>, &T) -> bool,
        alive_participant_ids_query: Arc<dyn Fn() -> Vec<ParticipantId> + Send + Sync>,
    ) -> anyhow::Result<Self> {
        let owned_queue = DoubleQueue::new(clock, condition, alive_participant_ids_query);

        // We're just going to replicate the owned assets to memory. It's not the most efficient,
        // but it's the simplest way to implement a multi-consumer, multi-producer queue that
        // supports asynchronous blocking when an asset isn't available.
        let mut last_id = None;
        let (start, end) = Self::make_prefix_range(my_participant_id, &prefix);
        for item in db.iter_range(col, &start, &end) {
            let (key, value) = item?;
            let id = Self::decode_key(&key, prefix.len())?;
            let value = serde_json::from_slice(&value)?;
            owned_queue.add_owned(id, value);
            last_id = Some(id);
        }

        Ok(Self {
            db,
            col,
            prefix,
            my_participant_id,
            owned_queue,
            last_id: Mutex::new(last_id),
            unowned_in_flight: Mutex::new(HashSet::new()),
        })
    }

    fn make_prefix_range(participant_id: ParticipantId, prefix: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut start = prefix.to_vec();
        let mut end = prefix.to_vec();
        start.extend_from_slice(&UniqueId::prefix_for_participant_id(participant_id));
        end.extend_from_slice(&UniqueId::prefix_for_participant_id(
            ParticipantId::from_raw(participant_id.raw().checked_add(1).unwrap()),
        ));
        (start, end)
    }

    fn make_key(&self, id: UniqueId) -> Vec<u8> {
        let mut key = self.prefix.clone();
        key.extend_from_slice(&borsh::to_vec(&id).unwrap());
        key
    }

    fn decode_key(key: &[u8], prefix_len: usize) -> anyhow::Result<UniqueId> {
        Ok(UniqueId::try_from_slice(&key[prefix_len..])?)
    }

    /// Generates an ID that won't conflict with existing ones, and reserves it
    /// so that the next call to the same function will return a different one.
    /// TODO(#10): This reservation does not persist across restarts, leading to
    /// the assumption that the clock moves forward at least a second across
    /// restarts.
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
    /// Excludes assets which are known to have offline participants.
    pub fn num_owned(&self) -> usize {
        self.owned_queue.available()
    }

    /// Returns the current number of owned assets in the database which
    /// are known to have all participants alive.
    pub fn num_owned_ready(&self) -> usize {
        self.owned_queue.ready()
    }

    /// Returns the current number of owned assets in the database which
    /// are known to have some participant offline.
    pub fn num_owned_offline(&self) -> usize {
        self.owned_queue.offline()
    }

    pub async fn take_owned(&self) -> (UniqueId, T) {
        let (id, asset) = self.owned_queue.take_owned().await;
        let mut update = self.db.update();
        update.delete(self.col, &self.make_key(id));
        update
            .commit()
            .expect("Unrecoverable error writing to database");
        (id, asset)
    }

    /// Takes an owned asset whose participants are all in `active`, waiting for
    /// background generation if none is currently available.
    pub async fn take_owned_matching(&self, active: Vec<ParticipantId>) -> (UniqueId, T) {
        let (id, asset) = self.owned_queue.take_owned_matching(active).await;
        let mut update = self.db.update();
        update.delete(self.col, &self.make_key(id));
        update
            .commit()
            .expect("Unrecoverable error writing to database");
        (id, asset)
    }

    /// Adds an owned asset to the storage.
    pub fn add_owned(&self, id: UniqueId, value: T) {
        let key = self.make_key(id);
        let value_ser = serde_json::to_vec(&value).unwrap();
        let mut update = self.db.update();
        update.put(self.col, &key, &value_ser);
        update
            .commit()
            .expect("Unrecoverable error writing to database");
        // Can't fail, because we keep a receiver alive.
        self.owned_queue.add_owned(id, value);
    }

    /// Examines up to `num_assets_to_process` elements in the storage.
    /// If any are found not to satisfy the current condition, they are discarded.
    /// Otherwise, they are kept aside as ready for immediate use.
    pub async fn maybe_discard_owned(&self, num_assets_to_process: usize) {
        let removed_cold_ids = self
            .owned_queue
            .maybe_discard_owned(num_assets_to_process)
            .await;
        if !removed_cold_ids.is_empty() {
            let mut update = self.db.update();
            for id in removed_cold_ids {
                update.delete(self.col, &self.make_key(id));
            }
            update
                .commit()
                .expect("Unrecoverable error writing to database");
        }
    }

    /// Adds an unowned asset to the storage.
    pub fn add_unowned(&self, id: UniqueId, value: T) {
        let key = self.make_key(id);
        let value_ser = serde_json::to_vec(&value).unwrap();
        let mut update = self.db.update();
        update.put(self.col, &key, &value_ser);
        update
            .commit()
            .expect("Unrecoverable error writing to database");
    }

    /// Removes an unowned asset from the storage and returns it. Returns
    /// an error if we do not have the asset in our database or if a concurrent
    /// call is already taking the same asset.
    pub fn take_unowned(&self, id: UniqueId) -> anyhow::Result<T> {
        // Prevent two concurrent callers from both reading the same asset
        // before either commits the delete (read-then-delete race).
        {
            let mut in_flight = self.unowned_in_flight.lock().unwrap();
            if !in_flight.insert(id) {
                anyhow::bail!(
                    "Unowned {} is already being taken by another task: {:?}",
                    self.col,
                    id
                );
            }
        }
        let result = self.take_unowned_inner(id);
        // Always remove from in-flight, whether the take succeeded or not.
        self.unowned_in_flight.lock().unwrap().remove(&id);
        result
    }

    fn take_unowned_inner(&self, id: UniqueId) -> anyhow::Result<T> {
        let key = self.make_key(id);
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

#[cfg(test)]
mod tests {
    use super::{ColdQueue, DistributedAssetStorage, DoubleQueue, UniqueId};
    use crate::assets::clean_db;
    use crate::async_testing::{MaybeReady, run_future_once};
    use crate::db::DBCol;
    use crate::primitives::ParticipantId;
    use crate::providers::HasParticipants;
    use borsh::BorshDeserialize;
    use futures::FutureExt;
    use mpc_primitives::domain::DomainId;
    use near_time::FakeClock;
    use serde::{Deserialize, Serialize};
    use std::cmp::Eq;
    use std::default::Default;
    use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// Adapter used by tests that previously took `Option<DomainId>` to compose
    /// the equivalent prefix bytes for the generalized `DistributedAssetStorage`.
    fn domain_id_to_prefix(domain_id: Option<DomainId>) -> Vec<u8> {
        match domain_id {
            Some(d) => d.0.to_be_bytes().to_vec(),
            None => Vec::new(),
        }
    }

    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    struct ParticipantsWithI32(pub Vec<ParticipantId>, pub i32);

    impl HasParticipants for ParticipantsWithI32 {
        fn is_subset_of_active_participants(&self, active_participants: &[ParticipantId]) -> bool {
            self.0.iter().all(|p| active_participants.contains(p))
        }
    }

    fn verify_cold_queue_internal_consistency<T, CondVal: Default + Eq>(
        queue: &ColdQueue<T, CondVal>,
        expected_len: usize,
    ) {
        assert!(queue.cold_ready <= queue.cold_available);
        assert!(queue.cold_available <= queue.cold_queue.len());
        assert_eq!(expected_len, queue.cold_queue.len());
        for (i, (_id, val)) in queue.cold_queue.iter().enumerate() {
            let satisfies = (queue.condition)(&queue.last_condition_value, val);
            if i < queue.cold_ready {
                assert!(satisfies);
            }
            if queue.cold_available <= i {
                assert!(!satisfies);
            }
        }
    }

    #[test]
    fn test_cold_queue() {
        let clock = FakeClock::default();
        let cond_value = Arc::new(AtomicI32::new(0));
        let mut queue = ColdQueue::new(clock.clock(), |cond, val| val % 2 == *cond, {
            let cond_value = cond_value.clone();
            Arc::new(move || cond_value.load(Ordering::Relaxed))
        });

        // Operations on empty
        verify_cold_queue_internal_consistency(&queue, 0);
        queue.discard();
        verify_cold_queue_internal_consistency(&queue, 0);
        queue.take();
        verify_cold_queue_internal_consistency(&queue, 0);
        cond_value.store(1, Ordering::Relaxed);
        queue.update_condition_value();
        verify_cold_queue_internal_consistency(&queue, 0);

        let id1 = UniqueId::new(ParticipantId::from_raw(42), 1, 0);
        let id2 = id1.add_to_counter(1).unwrap();

        // Insert and remove
        queue.add_if_condition_not_satisfied(id1, 1);
        verify_cold_queue_internal_consistency(&queue, 0);
        queue.add_if_condition_satisfied(id1, 1);
        verify_cold_queue_internal_consistency(&queue, 1);
        queue.discard();
        verify_cold_queue_internal_consistency(&queue, 1);
        queue.add_if_condition_not_satisfied(id2, 2);
        verify_cold_queue_internal_consistency(&queue, 2);
        queue.take();
        verify_cold_queue_internal_consistency(&queue, 1);
        queue.discard();
        verify_cold_queue_internal_consistency(&queue, 0);

        // Reset then discard
        queue.add_if_condition_satisfied(id1, 1);
        cond_value.store(0, Ordering::Relaxed);
        queue.update_condition_value();
        queue.take();
        verify_cold_queue_internal_consistency(&queue, 1);
        queue.discard();
        verify_cold_queue_internal_consistency(&queue, 0);
        // Reset then take
        queue.add_if_condition_not_satisfied(id1, 1);
        cond_value.store(1, Ordering::Relaxed);
        queue.update_condition_value();
        queue.discard();
        verify_cold_queue_internal_consistency(&queue, 1);
        queue.take();
        verify_cold_queue_internal_consistency(&queue, 0);

        // Take from known satisfying
        queue.add_if_condition_satisfied(id1, 1);
        verify_cold_queue_internal_consistency(&queue, 1);
        queue.take();
        verify_cold_queue_internal_consistency(&queue, 0);
        // Discard from known non-satisfying
        queue.add_if_condition_not_satisfied(id2, 2);
        verify_cold_queue_internal_consistency(&queue, 1);
        queue.discard();
        verify_cold_queue_internal_consistency(&queue, 0);
    }

    #[test]
    fn test_double_queue_discard() {
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

        // Discard should never block, even if the queue is completely empty
        queue.maybe_discard_owned(3).now_or_never().unwrap();

        // Add 3 elements, 2 of which don't match the condition
        let id1 = UniqueId::new(ParticipantId::from_raw(42), 123, 456);
        let id2 = id1.add_to_counter(1).unwrap();
        let id3 = id1.add_to_counter(2).unwrap();
        let id4 = id1.add_to_counter(3).unwrap();
        queue.add_owned(id1, 1);
        queue.add_owned(id2, 2);
        queue.add_owned(id3, 3);
        assert_eq!(queue.available(), 3);

        queue.maybe_discard_owned(1).now_or_never().unwrap();
        assert_eq!(queue.available(), 2);

        assert_eq!(queue.take_owned().now_or_never().unwrap(), (id2, 2));
        assert_eq!(queue.available(), 1);

        queue.maybe_discard_owned(1).now_or_never().unwrap();
        assert_eq!(queue.available(), 0);

        queue.add_owned(id4, 4);
        assert_eq!(queue.available(), 1);

        queue.maybe_discard_owned(1).now_or_never().unwrap();
        assert_eq!(queue.available(), 1);

        assert_eq!(queue.take_owned().now_or_never().unwrap(), (id4, 4));
        assert_eq!(queue.available(), 0);
    }

    #[tokio::test]
    #[expect(non_snake_case)]
    async fn take_owned_matching__should_return_matching_asset_immediately() {
        // Given: a queue holding one non-matching and one matching asset.
        let clock = FakeClock::default();
        let queue = DoubleQueue::new(clock.clock(), |cond, val| val % 2 == *cond, Arc::new(|| 0));
        let id1 = UniqueId::new(ParticipantId::from_raw(42), 123, 456);
        let id2 = id1.add_to_counter(1).unwrap();
        queue.add_owned(id1, 2);
        queue.add_owned(id2, 3);

        // When: taking with a condition value matching only the second asset.
        let taken = queue.take_owned_matching(1).now_or_never();

        // Then
        assert_eq!(taken, Some((id2, 3)));
    }

    #[tokio::test]
    #[expect(non_snake_case)]
    async fn take_owned_matching__should_wait_until_matching_asset_is_added() {
        // Given: a queue holding only a non-matching asset.
        let clock = FakeClock::default();
        let queue = DoubleQueue::new(clock.clock(), |cond, val| val % 2 == *cond, Arc::new(|| 0));
        let id1 = UniqueId::new(ParticipantId::from_raw(42), 123, 456);
        let id2 = id1.add_to_counter(1).unwrap();
        queue.add_owned(id1, 2);

        // When: taking with a condition value nothing matches yet.
        let mut take = Box::pin(queue.take_owned_matching(1));
        assert!((&mut take).now_or_never().is_none());

        // Then: the take completes once a matching asset is generated.
        queue.add_owned(id2, 3);
        assert_eq!(take.await, (id2, 3));
        // And: the non-matching asset is still in the queue.
        assert_eq!(queue.available(), 1);
    }

    #[test]
    #[expect(non_snake_case)]
    fn cold_queue_ingest_and_take_first_matching__should_preserve_barriers() {
        // Given: a ready prefix and a non-satisfying tail (stored condition:
        // even values satisfy condition value 0).
        let clock = FakeClock::default();
        let cond_value = Arc::new(AtomicI32::new(0));
        let mut queue = ColdQueue::new(clock.clock(), |cond, val| val % 2 == *cond, {
            let cond_value = cond_value.clone();
            Arc::new(move || cond_value.load(Ordering::Relaxed))
        });
        let id1 = UniqueId::new(ParticipantId::from_raw(42), 1, 0);
        let id2 = id1.add_to_counter(1).unwrap();
        let id3 = id1.add_to_counter(2).unwrap();
        let id4 = id1.add_to_counter(3).unwrap();
        queue.add_if_condition_satisfied(id1, 2);
        queue.add_if_condition_not_satisfied(id2, 3);
        verify_cold_queue_internal_consistency(&queue, 2);

        // When: ingesting unknowns and taking one by a caller-side condition.
        queue.ingest(id3, 4);
        queue.ingest(id4, 5);
        verify_cold_queue_internal_consistency(&queue, 4);
        let taken = queue.take_first_matching(&1);

        // Then: the matching element is removed, the barriers stay valid, and
        // a regular take still serves the ready prefix.
        assert_eq!(taken, Some((id4, 5)));
        verify_cold_queue_internal_consistency(&queue, 3);
        let super::ColdQueueTakeResult::Taken(pair) = queue.take() else {
            panic!("expected the ready asset to be taken");
        };
        assert_eq!(pair, (id1, 2));
        verify_cold_queue_internal_consistency(&queue, 2);
    }

    #[tokio::test]
    #[expect(non_snake_case)]
    async fn double_queue__should_keep_take_and_discard_working_across_matching_takes() {
        // Given: even values satisfy the stored condition (condition value 0).
        let clock = FakeClock::default();
        let queue = DoubleQueue::new(clock.clock(), |cond, val| val % 2 == *cond, Arc::new(|| 0));
        let id1 = UniqueId::new(ParticipantId::from_raw(42), 123, 456);
        let id2 = id1.add_to_counter(1).unwrap();
        let id3 = id1.add_to_counter(2).unwrap();
        let id4 = id1.add_to_counter(3).unwrap();
        queue.add_owned(id1, 2);
        queue.add_owned(id2, 3);
        queue.add_owned(id3, 4);
        queue.add_owned(id4, 5);

        // When: a matching take (odd values) interleaves with the regular flow.
        assert_eq!(queue.take_owned_matching(1).now_or_never(), Some((id2, 3)));

        // Then: a regular take still yields a condition-satisfying asset,
        assert_eq!(queue.take_owned().now_or_never(), Some((id1, 2)));
        // discard removes exactly the non-satisfying leftover,
        assert_eq!(queue.maybe_discard_owned(2).await, vec![id4]);
        assert_eq!(queue.available(), 1);
        // and the surviving satisfying asset remains takeable.
        assert_eq!(queue.take_owned().now_or_never(), Some((id3, 4)));
    }

    #[tokio::test]
    #[expect(non_snake_case)]
    async fn distributed_store_take_owned_matching__should_delete_taken_asset_from_disk() {
        // Given: two persisted assets; the condition keys on the asset value.
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::SecretDB::new(dir.path(), [1; 16]).unwrap();
        let condition: fn(&Vec<ParticipantId>, &u32) -> bool =
            |eligible, val| eligible.contains(&ParticipantId::from_raw(*val));
        let store = DistributedAssetStorage::<u32>::new(
            FakeClock::default().clock(),
            db.clone(),
            crate::db::DBCol::TripleV2,
            Vec::new(),
            ParticipantId::from_raw(42),
            condition,
            Arc::new(std::vec::Vec::new),
        )
        .unwrap();
        let id1 = store.generate_and_reserve_id();
        let id2 = store.generate_and_reserve_id();
        store.add_owned(id1, 123);
        store.add_owned(id2, 456);

        // When: taking the matching asset, then reopening the store from disk.
        let taken = store
            .take_owned_matching(vec![ParticipantId::from_raw(456)])
            .await;
        drop(store);
        let reopened = DistributedAssetStorage::<u32>::new(
            FakeClock::default().clock(),
            db,
            crate::db::DBCol::TripleV2,
            Vec::new(),
            ParticipantId::from_raw(42),
            condition,
            Arc::new(std::vec::Vec::new),
        )
        .unwrap();

        // Then: only the taken asset was removed from disk.
        assert_eq!(taken, (id2, 456));
        assert_eq!(reopened.num_owned(), 1);
        assert_eq!(
            reopened
                .take_owned_matching(vec![ParticipantId::from_raw(123)])
                .await,
            (id1, 123)
        );
    }

    // This test covers tricky cases around updates to the condition value
    #[test]
    fn test_double_queue_condition_value() {
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
            crate::db::DBCol::TripleV2,
            Vec::new(),
            ParticipantId::from_raw(42),
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
            crate::db::DBCol::TripleV2,
            Vec::new(),
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
            crate::db::DBCol::TripleV2,
            Vec::new(),
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
            crate::db::DBCol::TripleV2,
            Vec::new(),
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
            crate::db::DBCol::TripleV2,
            Vec::new(),
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
        let _ = store
            .take_unowned(id1)
            .expect_err("Should not take an unowned item twice");

        let _ = store
            .take_unowned(id3)
            .expect_err("Missing unowned item should return an error");
        assert_eq!(store.take_unowned(id2).unwrap(), 234);
        let _ = store
            .take_unowned(id2)
            .expect_err("Should not take an unowned item twice");
        let _ = store
            .take_unowned(id1)
            .expect_err("Missing unowned item should return an error");
    }

    #[test]
    fn test_distributed_store_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::SecretDB::new(dir.path(), [1; 16]).unwrap();
        let myself = ParticipantId::from_raw(42);
        let store = DistributedAssetStorage::<u32>::new(
            FakeClock::default().clock(),
            db.clone(),
            crate::db::DBCol::TripleV2,
            Vec::new(),
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
            crate::db::DBCol::TripleV2,
            Vec::new(),
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
            crate::db::DBCol::TripleV2,
            Vec::new(),
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
            crate::db::DBCol::TripleV2,
            Vec::new(),
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
                domain_id_to_prefix(domain_id),
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
                domain_id_to_prefix(domain_id),
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

    #[test]
    fn test_distributed_assets_storage_cleanup() {
        let clock = FakeClock::default();
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::SecretDB::new(dir.path(), [1; 16]).unwrap();
        let all_participants = vec![
            ParticipantId::from_raw(0),
            ParticipantId::from_raw(1),
            ParticipantId::from_raw(2),
            ParticipantId::from_raw(3),
        ];
        let participant_subset_a = vec![
            ParticipantId::from_raw(0),
            ParticipantId::from_raw(1),
            ParticipantId::from_raw(2),
        ];
        let participant_subset_b = vec![
            ParticipantId::from_raw(1),
            ParticipantId::from_raw(2),
            ParticipantId::from_raw(3),
        ];
        let participant_subset_c = vec![ParticipantId::from_raw(1), ParticipantId::from_raw(2)];
        let my_participant_id = ParticipantId::from_raw(42);
        let alive_participants = Arc::new(Mutex::new(all_participants.clone()));
        let new_store_from_db = |db_col: DBCol,
                                 domain_id: Option<DomainId>|
         -> DistributedAssetStorage<ParticipantsWithI32> {
            DistributedAssetStorage::<ParticipantsWithI32>::new(
                clock.clock(),
                db.clone(),
                db_col,
                domain_id_to_prefix(domain_id),
                my_participant_id,
                |cond, val| val.is_subset_of_active_participants(cond),
                {
                    let alive_participants = alive_participants.clone();
                    Arc::new(move || alive_participants.lock().unwrap().clone())
                },
            )
            .unwrap()
        };
        let assert_db_num_owned = |db_col: DBCol, domain_id: Option<DomainId>, expected: usize| {
            let store = new_store_from_db(db_col, domain_id);
            assert_eq!(store.num_owned(), expected);
        };
        for domain_id in [None, Some(DomainId(0)), Some(DomainId(1))] {
            for db_col in [crate::db::DBCol::Presignature, crate::db::DBCol::TripleV2] {
                assert_db_num_owned(db_col, domain_id, 0);
                {
                    // populate the database
                    let all_1 = ParticipantsWithI32(all_participants.clone(), 456);
                    let subset_a_1 = ParticipantsWithI32(participant_subset_a.clone(), 789);
                    let subset_b_1 = ParticipantsWithI32(participant_subset_b.clone(), 789);
                    let subset_c_1 = ParticipantsWithI32(participant_subset_c.clone(), 789);
                    let store = new_store_from_db(db_col, domain_id);
                    for p in [all_1, subset_a_1, subset_b_1, subset_c_1] {
                        let id = store.generate_and_reserve_id();
                        store.add_owned(id, p);
                    }
                }
                assert_db_num_owned(db_col, domain_id, 4);
                let mut writer = db.update();
                clean_db::<ParticipantsWithI32>(
                    &db,
                    &mut writer,
                    db_col,
                    &all_participants,
                    my_participant_id,
                    &domain_id_to_prefix(domain_id),
                )
                .unwrap();
                writer.commit().unwrap();
                assert_db_num_owned(db_col, domain_id, 4);
                let mut writer = db.update();
                clean_db::<ParticipantsWithI32>(
                    &db,
                    &mut writer,
                    db_col,
                    &participant_subset_a,
                    my_participant_id,
                    &domain_id_to_prefix(domain_id),
                )
                .unwrap();
                writer.commit().unwrap();
                assert_db_num_owned(db_col, domain_id, 2);

                let mut writer = db.update();
                clean_db::<ParticipantsWithI32>(
                    &db,
                    &mut writer,
                    db_col,
                    &participant_subset_b,
                    my_participant_id,
                    &domain_id_to_prefix(domain_id),
                )
                .unwrap();
                writer.commit().unwrap();
                assert_db_num_owned(db_col, domain_id, 1);
            }
        }
    }
}
