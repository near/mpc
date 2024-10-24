use crate::protocol::triple::{Triple, TripleId};
use std::sync::Arc;

use redis::{Commands, Connection, FromRedisValue, RedisWrite, ToRedisArgs};
use tokio::sync::RwLock;

use near_account_id::AccountId;
use url::Url;

pub type LockTripleRedisStorage = Arc<RwLock<TripleRedisStorage>>;
type TripleResult<T> = std::result::Result<T, anyhow::Error>;

// Can be used to "clear" redis storage in case of a breaking change
const TRIPLE_STORAGE_VERSION: &str = "v1";

pub fn init(redis_url: Url, account_id: &AccountId) -> TripleRedisStorage {
    TripleRedisStorage::new(redis_url, account_id)
}

pub struct TripleRedisStorage {
    redis_connection: Connection,
    node_account_id: AccountId,
}

impl TripleRedisStorage {
    fn new(redis_url: Url, account_id: &AccountId) -> Self {
        Self {
            redis_connection: redis::Client::open(redis_url.as_str())
                .expect("Failed to connect to Redis")
                .get_connection()
                .expect("Failed to get Redis connection"),
            node_account_id: account_id.clone(),
        }
    }

    pub fn insert(&mut self, triple: Triple) -> TripleResult<()> {
        self.redis_connection.hset::<&str, TripleId, Triple, ()>(
            &self.triple_key(),
            triple.id,
            triple,
        )?;
        Ok(())
    }

    pub fn insert_mine(&mut self, triple: Triple) -> TripleResult<()> {
        self.redis_connection
            .sadd::<&str, TripleId, ()>(&self.mine_key(), triple.id)?;
        self.insert(triple)?;
        Ok(())
    }

    pub fn contains(&mut self, id: &TripleId) -> TripleResult<bool> {
        let result: bool = self.redis_connection.hexists(self.triple_key(), id)?;
        Ok(result)
    }

    pub fn contains_mine(&mut self, id: &TripleId) -> TripleResult<bool> {
        let result: bool = self.redis_connection.sismember(self.mine_key(), id)?;
        Ok(result)
    }

    pub fn take(&mut self, id: &TripleId) -> TripleResult<Option<Triple>> {
        if self.contains_mine(id)? {
            tracing::error!("Can not take mine triple as foreign: {:?}", id);
            return Ok(None);
        }
        let result: Option<Triple> = self.redis_connection.hget(self.triple_key(), id)?;
        match result {
            Some(triple) => {
                self.redis_connection
                    .hdel::<&str, TripleId, ()>(&self.triple_key(), *id)?;
                Ok(Some(triple))
            }
            None => Ok(None),
        }
    }

    pub fn take_mine(&mut self) -> TripleResult<Option<Triple>> {
        let id: Option<TripleId> = self.redis_connection.spop(self.mine_key())?;
        match id {
            Some(id) => self.take(&id),
            None => Ok(None),
        }
    }

    pub fn count_all(&mut self) -> TripleResult<usize> {
        let result: usize = self.redis_connection.hlen(self.triple_key())?;
        Ok(result)
    }

    pub fn count_mine(&mut self) -> TripleResult<usize> {
        let result: usize = self.redis_connection.scard(self.mine_key())?;
        Ok(result)
    }

    pub fn clear(&mut self) -> TripleResult<()> {
        self.redis_connection.del::<&str, ()>(&self.triple_key())?;
        self.redis_connection.del::<&str, ()>(&self.mine_key())?;
        Ok(())
    }

    fn triple_key(&self) -> String {
        format!(
            "triples:{}:{}",
            TRIPLE_STORAGE_VERSION, self.node_account_id
        )
    }

    fn mine_key(&self) -> String {
        format!(
            "triples_mine:{}:{}",
            TRIPLE_STORAGE_VERSION, self.node_account_id
        )
    }
}

impl ToRedisArgs for Triple {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        match serde_json::to_string(self) {
            std::result::Result::Ok(json) => out.write_arg(json.as_bytes()),
            Err(e) => {
                tracing::error!("Failed to serialize Triple: {}", e);
                out.write_arg("failed_to_serialize".as_bytes())
            }
        }
    }
}

impl FromRedisValue for Triple {
    fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
        let json: String = String::from_redis_value(v)?;

        serde_json::from_str(&json).map_err(|e| {
            redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "Failed to deserialize Triple",
                e.to_string(),
            ))
        })
    }
}
