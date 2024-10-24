use std::sync::Arc;

use anyhow::Ok;
use near_sdk::AccountId;
use redis::{Commands, Connection, FromRedisValue, RedisWrite, ToRedisArgs};
use tokio::sync::RwLock;
use url::Url;

use crate::protocol::presignature::{Presignature, PresignatureId};

type PresigResult<T> = std::result::Result<T, anyhow::Error>;
pub type LockPresignatureRedisStorage = Arc<RwLock<PresignatureRedisStorage>>;

// Can be used to "clear" redis storage in case of a breaking change
const PRESIGNATURE_STORAGE_VERSION: &str = "v1";

pub fn init(redis_url: Url, node_account_id: &AccountId) -> PresignatureRedisStorage {
    PresignatureRedisStorage::new(redis_url, node_account_id)
}

pub struct PresignatureRedisStorage {
    redis_connection: Connection,
    node_account_id: AccountId,
}

impl PresignatureRedisStorage {
    fn new(redis_url: Url, node_account_id: &AccountId) -> Self {
        Self {
            redis_connection: redis::Client::open(redis_url.as_str())
                .expect("Failed to connect to Redis")
                .get_connection()
                .expect("Failed to get Redis connection"),
            node_account_id: node_account_id.clone(),
        }
    }
}

impl PresignatureRedisStorage {
    pub fn insert(&mut self, presignature: Presignature) -> PresigResult<()> {
        self.redis_connection
            .hset::<&str, PresignatureId, Presignature, ()>(
                &self.presignature_key(),
                presignature.id,
                presignature,
            )?;
        Ok(())
    }

    pub fn insert_mine(&mut self, presignature: Presignature) -> PresigResult<()> {
        self.redis_connection
            .sadd::<&str, PresignatureId, ()>(&self.mine_key(), presignature.id)?;
        self.insert(presignature)?;
        Ok(())
    }

    pub fn contains(&mut self, id: &PresignatureId) -> PresigResult<bool> {
        let result: bool = self.redis_connection.hexists(self.presignature_key(), id)?;
        Ok(result)
    }

    pub fn contains_mine(&mut self, id: &PresignatureId) -> PresigResult<bool> {
        let result: bool = self.redis_connection.sismember(self.mine_key(), id)?;
        Ok(result)
    }

    pub fn take(&mut self, id: &PresignatureId) -> PresigResult<Option<Presignature>> {
        if self.contains_mine(id)? {
            tracing::error!("Can not take mine presignature as foreign: {:?}", id);
            return Ok(None);
        }
        let result: Option<Presignature> =
            self.redis_connection.hget(self.presignature_key(), id)?;
        match result {
            Some(presignature) => {
                self.redis_connection
                    .hdel::<&str, PresignatureId, ()>(&self.presignature_key(), *id)?;
                Ok(Some(presignature))
            }
            None => Ok(None),
        }
    }

    pub fn take_mine(&mut self) -> PresigResult<Option<Presignature>> {
        let id: Option<PresignatureId> = self.redis_connection.spop(self.mine_key())?;
        match id {
            Some(id) => self.take(&id),
            None => Ok(None),
        }
    }

    pub fn count_all(&mut self) -> PresigResult<usize> {
        let result: usize = self.redis_connection.hlen(self.presignature_key())?;
        Ok(result)
    }

    pub fn count_mine(&mut self) -> PresigResult<usize> {
        let result: usize = self.redis_connection.scard(self.mine_key())?;
        Ok(result)
    }

    pub fn clear(&mut self) -> PresigResult<()> {
        self.redis_connection
            .del::<&str, ()>(&self.presignature_key())?;
        self.redis_connection.del::<&str, ()>(&self.mine_key())?;
        Ok(())
    }

    fn presignature_key(&self) -> String {
        format!(
            "presignatures:{}:{}",
            PRESIGNATURE_STORAGE_VERSION, self.node_account_id
        )
    }

    fn mine_key(&self) -> String {
        format!(
            "presignatures_mine:{}:{}",
            PRESIGNATURE_STORAGE_VERSION, self.node_account_id
        )
    }
}

impl ToRedisArgs for Presignature {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        match serde_json::to_string(self) {
            std::result::Result::Ok(json) => out.write_arg(json.as_bytes()),
            Err(e) => {
                tracing::error!("Failed to serialize Presignature: {}", e);
                out.write_arg("failed_to_serialize".as_bytes())
            }
        }
    }
}

impl FromRedisValue for Presignature {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let json: String = String::from_redis_value(v)?;

        serde_json::from_str(&json).map_err(|e| {
            redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to deserialize Presignature",
                e.to_string(),
            ))
        })
    }
}
