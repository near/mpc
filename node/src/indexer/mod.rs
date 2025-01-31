pub mod configs;
#[cfg(test)]
pub mod fake;
pub mod handler;
pub mod lib;
pub mod participants;
pub mod real;
pub mod stats;
pub mod tx_sender;
pub mod tx_signer;
pub mod types;

use handler::ChainSignatureRequest;
use near_indexer_primitives::types::AccountId;
use near_indexer_primitives::types::Nonce;
use participants::ContractState;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, watch};
use types::ChainSendTransactionRequest;

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

/// API to interact with the indexer. Can be replaced by a dummy implementation.
/// The MPC node implementation needs this and only this to be able to interact
/// with the indexer.
/// TODO(#155): This would be the interface to abstract away having an indexer
/// running in a separate process.
pub struct IndexerAPI {
    /// Provides the current contract state as well as updates to it.
    pub contract_state_receiver: watch::Receiver<ContractState>,
    /// Provides signature requests. It is in a mutex, because the logical
    /// "owner" of this receiver can change over time (specifically, when we
    /// transition from the Running state to a Resharing state to the Running
    /// state again, two different tasks would successively "own" the receiver).
    /// We do not want to re-create the channel, because while resharing is
    /// happening we want to buffer the signature requests.
    pub sign_request_receiver:
        Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<ChainSignatureRequest>>>,
    /// Sender to request transactions be signed (by a TransactionSigner that
    /// the indexer is initialized with) and sent to the chain.
    pub txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
}
