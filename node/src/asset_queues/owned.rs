use super::queue::{AssetQueues, AssetQueuesDBOperation};
use super::types::{AssetQueueKey, ParticipantsWithSerials};
use super::AssetPrefix;
use crate::assets::UniqueId;
use crate::config::MpcConfig;
use crate::db::{DBCol, SecretDB};
use crate::metrics;
use crate::primitives::ParticipantId;
use borsh::BorshDeserialize;
use near_time::Clock;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::sync::MutexGuard;

pub type OnlineParticipantsQuery = Arc<dyn Fn() -> ParticipantsWithSerials + Send + Sync>;

pub struct OwnedAssetStorage<T: Clone + Serialize + DeserializeOwned + Send + 'static> {
    clock: Clock,
    db: Arc<SecretDB>,
    asset_prefix: AssetPrefix,
    my_participant_id: ParticipantId,
    online_participants_query: OnlineParticipantsQuery,

    queues: Arc<tokio::sync::Mutex<AssetQueues<T>>>,
    last_id: Mutex<Option<UniqueId>>,

    waiter: tokio::sync::watch::Receiver<()>,
    notifier: tokio::sync::watch::Sender<()>,
}

impl<T: Clone + Serialize + DeserializeOwned + Send + 'static> OwnedAssetStorage<T> {
    pub fn new(
        clock: Clock,
        config: &MpcConfig,
        db: Arc<SecretDB>,
        asset_prefix: AssetPrefix,
        online_participants_query: Arc<dyn Fn() -> ParticipantsWithSerials + Send + Sync>,
    ) -> anyhow::Result<Self> {
        let (tx, rx) = tokio::sync::watch::channel(());
        let mut queues = AssetQueues::new(config);

        // Read all queues from the DB.
        let (queue_key_start, queue_key_end) = all_asset_queue_key_range();
        let mut last_id: Option<UniqueId> = None;
        for item in db.iter_range(DBCol::AssetQueue, &queue_key_start, &queue_key_end) {
            let (key, value) = item?;
            let queue_key = decode_asset_queue_key(&key)?;
            let participants: ParticipantsWithSerials = borsh::from_slice(&value)?;

            let mut assets = VecDeque::new();
            let (asset_start, asset_end) = assets_key_range(asset_prefix, &queue_key);
            for asset_item in db.iter_range(DBCol::OwnedAsset, &asset_start, &asset_end) {
                let (key, value) = asset_item?;
                let asset_id = decode_asset_key(asset_prefix, &queue_key, &key)?;
                let asset_value: T = serde_json::from_slice(&value)?;
                assets.push_back((asset_id, asset_value));
                if last_id.is_none_or(|last_id| last_id < asset_id) {
                    last_id = Some(asset_id);
                }
            }
            queues.add_queue_from_db(participants, assets);
        }

        Ok(Self {
            clock,
            db,
            asset_prefix,
            my_participant_id: config.my_participant_id,
            online_participants_query,
            queues: Arc::new(tokio::sync::Mutex::new(queues)),
            last_id: Mutex::new(last_id),
            waiter: rx,
            notifier: tx,
        })
    }

    async fn transact(&self, refresh_online_participants: bool) -> QueuesTransaction<'_, T> {
        let mut transaction =
            QueuesTransaction::new(&self.queues, self.db.clone(), self.asset_prefix).await;
        if refresh_online_participants {
            let online_participants = (self.online_participants_query)();
            transaction
                .queues
                .set_online_participants(&online_participants, &mut transaction.db_ops);
        }
        transaction
    }

    pub async fn refresh_and_return_num_online_assets(&self) -> usize {
        let transaction = self.transact(true).await;
        let online = transaction.queues.num_online_assets();
        let desirable = transaction.queues.num_desirable_assets();
        let offline = transaction.queues.num_offline_assets();
        drop(transaction);
        // Take this opportunity to export stats.
        metrics::MPC_OWNED_ASSETS_ONLINE
            .with_label_values(&[&format!("{:?}", self.asset_prefix)])
            .set(online as i64);
        metrics::MPC_OWNED_ASSETS_DESIRABLE
            .with_label_values(&[&format!("{:?}", self.asset_prefix)])
            .set(desirable as i64);
        metrics::MPC_OWNED_ASSETS_OFFLINE
            .with_label_values(&[&format!("{:?}", self.asset_prefix)])
            .set(offline as i64);
        online
    }

    /// Picks a queue for generation, returning the queue key, and list of participants to generate
    /// the asset with.
    ///
    /// It's possible for the call to fail if there are not enough online participants to generate
    /// any assets.
    pub async fn pick_queue(&self) -> anyhow::Result<(AssetQueueKey, Vec<ParticipantId>)> {
        let transaction = self.transact(false).await;
        let Some((queue_key, participants)) = transaction.queues.pick_queue_for_generation() else {
            anyhow::bail!("Cannot generate asset, not enough participants online");
        };

        Ok((queue_key, participants))
    }

    /// Multiple calls to this function will return non-overlapping ranges of UniqueIds.
    pub async fn reserve_asset_ids(&self, num_ids_to_reserve: u32) -> UniqueId {
        assert!(num_ids_to_reserve > 0);
        let mut last_id = self.last_id.lock().unwrap();
        let start = match *last_id {
            Some(last_id) => last_id.pick_new_after(),
            None => UniqueId::generate(self.my_participant_id),
        };
        let end = start.add_to_counter(num_ids_to_reserve - 1).unwrap();
        *last_id = Some(end);
        start
    }

    pub async fn add_asset(
        &self,
        queue_key: AssetQueueKey,
        id: UniqueId,
        asset: T,
    ) -> anyhow::Result<()> {
        {
            let mut transaction = self.transact(false).await;
            if !transaction
                .queues
                .add_asset(queue_key, id, asset, &mut transaction.db_ops)
            {
                anyhow::bail!("Generated asset belongs to a queue that no longer exists, ignoring");
            }
        }
        self.notifier.send(()).ok();
        Ok(())
    }

    pub async fn consume_asset(&self) -> anyhow::Result<(UniqueId, T)> {
        loop {
            let mut waiter = self.waiter.clone();
            waiter.mark_unchanged();
            {
                // When consuming assets, always keep the online participants fresh.
                //
                // Why that, instead of just doing some periodic refresh? Because if we don't refresh it
                // every time, the following sequence of events may happen:
                //  - The networking layer realizes a node is offline.
                //  - Some loop somewhere (such as presignature generation) starts calling `consume_asset`
                //    to get an asset for a computation. That call returns an asset that is no longer
                //    online - because we didn't refresh.
                //  - That computation immediately fails at the networking layer because one of the
                //    participants is offline.
                //  - The loop calls `consume_asset` again, again returning an asset that is not online.
                //    This continues to drain assets really quickly in a busy loop.
                //
                // Therefore, by refreshing every time, we ensure that we can at most be out of sync
                // from the networking layer for one query, losing at most one asset per network state
                // change.
                let mut transaction = self.transact(true).await;
                if let Some(asset) = transaction
                    .queues
                    .try_consume_asset(&mut transaction.db_ops)
                {
                    return Ok(asset);
                }
            }
            // There is no asset, so wait for one to become available.
            // But give it a time bound, because the online nodes may change which causes some
            // assets to be available.
            tokio::select! {
                res = waiter.changed() => {
                    res?;
                }
                _ = self.clock.sleep(near_time::Duration::seconds(1)) => {
                }
            }
        }
    }
}

fn make_asset_queue_key(key: AssetQueueKey) -> Vec<u8> {
    let mut key_bytes = Vec::new();
    // Prefix all queue keys with a single zero byte so that it's easier for us to do
    // range queries.
    key_bytes.push(0);
    key_bytes.extend_from_slice(key.as_bytes());
    key_bytes
}

fn all_asset_queue_key_range() -> (Vec<u8>, Vec<u8>) {
    (vec![0], vec![1])
}

fn decode_asset_queue_key(key: &[u8]) -> anyhow::Result<AssetQueueKey> {
    if key.len() != 1 + size_of::<AssetQueueKey>() || key[0] != 0 {
        return Err(anyhow::anyhow!("Invalid asset queue key"));
    }
    let key = &key[1..];
    Ok(AssetQueueKey::try_from_slice(key)?)
}

fn assets_key_range(asset_prefix: AssetPrefix, queue: &AssetQueueKey) -> (Vec<u8>, Vec<u8>) {
    let mut key_start = borsh::to_vec(&asset_prefix).unwrap();
    key_start.extend_from_slice(queue.as_bytes());
    // Increment key end, as a big endian integer, by 1.
    // The asset queue key is a CryptoHash which we assume is not 2^256 - 1,
    // so this would always work.
    let mut key_end = key_start.clone();
    for byte in key_end.iter_mut().rev() {
        if *byte == 0xff {
            *byte == 0;
        } else {
            *byte += 1;
            break;
        }
    }
    (key_start, key_end)
}

fn make_asset_key(asset_prefix: AssetPrefix, queue: &AssetQueueKey, id: UniqueId) -> Vec<u8> {
    let mut key = borsh::to_vec(&asset_prefix).unwrap();
    key.extend_from_slice(queue.as_bytes());
    key.extend_from_slice(&borsh::to_vec(&id).unwrap());
    key
}

fn decode_asset_key(
    asset_prefix: AssetPrefix,
    queue_key: &AssetQueueKey,
    key: &[u8],
) -> anyhow::Result<UniqueId> {
    let asset_prefix = borsh::to_vec(&asset_prefix).unwrap();
    if key.len() != asset_prefix.len() + size_of::<AssetQueueKey>() + size_of::<UniqueId>() {
        return Err(anyhow::anyhow!("Invalid asset key length"));
    }
    if &key[..asset_prefix.len()] != asset_prefix {
        return Err(anyhow::anyhow!("Invalid asset key (wrong prefix)"));
    }
    let key_part = &key[asset_prefix.len()..];
    let decoded_queue_key = AssetQueueKey::try_from_slice(&key_part[..size_of::<AssetQueueKey>()])?;
    if decoded_queue_key != *queue_key {
        return Err(anyhow::anyhow!("Invalid asset key (wrong queue key)"));
    }
    let key_part = &key_part[size_of::<AssetQueueKey>()..];
    let id = UniqueId::try_from_slice(key_part)?;
    Ok(id)
}

struct QueuesTransaction<'a, T: Serialize> {
    queues: MutexGuard<'a, AssetQueues<T>>,
    asset_prefix: AssetPrefix,
    db: Arc<SecretDB>,
    db_ops: Vec<AssetQueuesDBOperation<T>>,
}

impl<'a, T: Serialize> QueuesTransaction<'a, T> {
    async fn new(
        queues: &'a tokio::sync::Mutex<AssetQueues<T>>,
        db: Arc<SecretDB>,
        asset_prefix: AssetPrefix,
    ) -> Self {
        let queues = queues.lock().await;
        let db_ops = Vec::new();
        Self {
            queues,
            asset_prefix,
            db,
            db_ops,
        }
    }

    fn commit(&mut self) {
        if self.db_ops.is_empty() {
            return;
        }
        let mut db_update = self.db.update();
        for op in self.db_ops.drain(..) {
            match op {
                AssetQueuesDBOperation::CreateQueue { key, participants } => {
                    db_update.put(
                        DBCol::AssetQueue,
                        &make_asset_queue_key(key),
                        &borsh::to_vec(&participants).unwrap(),
                    );
                }
                AssetQueuesDBOperation::DeleteQueue { key } => {
                    db_update.delete(DBCol::AssetQueue, &make_asset_queue_key(key));
                }
                AssetQueuesDBOperation::DeleteAsset {
                    queue_key,
                    asset_id,
                } => {
                    let asset_key = make_asset_key(self.asset_prefix, &queue_key, asset_id);
                    db_update.delete(DBCol::OwnedAsset, &asset_key);
                }
                AssetQueuesDBOperation::AddAsset {
                    queue_key,
                    asset_id,
                    asset,
                } => {
                    let asset_key = make_asset_key(self.asset_prefix, &queue_key, asset_id);
                    db_update.put(
                        DBCol::OwnedAsset,
                        &asset_key,
                        &serde_json::to_vec(&asset).unwrap(),
                    );
                }
            }
        }

        // DB operation errors are unrecoverable, just crash.
        db_update.commit().expect("DB operation failed");
    }
}

impl<'a, T: Serialize> Drop for QueuesTransaction<'a, T> {
    fn drop(&mut self) {
        self.commit();
    }
}
