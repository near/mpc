pub mod configs;
pub mod handler;
pub mod lib;
pub mod participants;
pub mod response;
pub mod stats;
pub mod transaction;

use near_indexer_primitives::types::Nonce;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

const RECENT_NONCES_CACHE_SIZE: usize = 10000;

pub struct IndexerState {
    /// Nonces observed in on-chain transactions signed with
    /// the local mpc node's near account access key
    pub my_nonces: Mutex<lru::LruCache<Nonce, ()>>,
}

impl IndexerState {
    pub fn new() -> Self {
        Self {
            my_nonces: Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(RECENT_NONCES_CACHE_SIZE).unwrap(),
            )),
        }
    }

    pub fn insert_nonce(self: &Arc<Self>, nonce: Nonce) {
        let mut cache = self.my_nonces.lock().expect("poisoned lock");
        cache.put(nonce, ());
    }

    pub fn has_nonce(self, nonce: Nonce) -> bool {
        let cache = self.my_nonces.lock().expect("poisoned lock");
        cache.contains(&nonce)
    }
}
