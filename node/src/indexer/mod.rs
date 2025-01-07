pub mod configs;
pub mod handler;
pub mod lib;
pub mod participants;
pub mod response;
pub mod stats;
pub mod transaction;

use near_indexer_primitives::types::AccountId;
use near_indexer_primitives::types::Nonce;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

const RECENT_NONCES_CACHE_SIZE: usize = 10000;

pub(crate) struct IndexerState {
    /// ViewClientActor address
    view_client: actix::Addr<near_client::ViewClientActor>,
    /// ClientActor address
    client: actix::Addr<near_client::ClientActor>,
    /// AccountId for the mpc contract
    mpc_contract_id: AccountId,
    /// Nonces observed in on-chain transactions signed with
    /// the local mpc node's near account access key
    pub my_nonces: Mutex<lru::LruCache<Nonce, ()>>,
}

impl IndexerState {
    pub fn new(
        view_client: actix::Addr<near_client::ViewClientActor>,
        client: actix::Addr<near_client::ClientActor>,
        mpc_contract_id: AccountId,
    ) -> Self {
        Self {
            view_client,
            client,
            mpc_contract_id,
            my_nonces: Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(RECENT_NONCES_CACHE_SIZE).unwrap(),
            )),
        }
    }

    pub fn insert_nonce(self: &Arc<Self>, nonce: Nonce) {
        let mut cache = self.my_nonces.lock().expect("poisoned lock");
        cache.put(nonce, ());
    }

    pub fn has_nonce(self: &Arc<Self>, nonce: Nonce) -> bool {
        let cache = self.my_nonces.lock().expect("poisoned lock");
        cache.contains(&nonce)
    }
}
