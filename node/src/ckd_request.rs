use crate::db::{DBCol, SecretDB};
use crate::metrics;
use mpc_contract::primitives::domain::DomainId;
use mpc_contract::primitives::signature::Payload;
use near_indexer_primitives::CryptoHash;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;


pub type CKDId = CryptoHash;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CKDRequest {
    pub id: CKDId,
    pub receipt_id: CryptoHash,
    pub payload: Payload,
    pub entropy: [u8; 32],
    pub timestamp_nanosec: u64,
    pub domain: DomainId,
}

pub struct CKDRequestStorage {
    db: Arc<SecretDB>,
    add_sender: broadcast::Sender<CKDId>,
}

impl CKDRequestStorage {
    pub fn new(db: Arc<SecretDB>) -> anyhow::Result<Self> {
        let (tx, _) = tokio::sync::broadcast::channel(500);
        Ok(Self { db, add_sender: tx })
    }
}