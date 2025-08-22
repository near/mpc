use crate::db::{DBCol, SecretDB};
use crate::metrics;
use mpc_contract::primitives::domain::DomainId;
use near_indexer_primitives::CryptoHash;
use near_sdk::{AccountId, PublicKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;

pub type CKDId = CryptoHash;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CKDRequest {
    /// The unique ID that identifies the ckd, and can also uniquely identify the response.
    pub id: CKDId,
    /// The receipt that generated the ckd request, which can be used to look up on chain.
    pub receipt_id: CryptoHash,
    pub app_public_key: PublicKey,
    pub app_id: AccountId,
    pub domain_id: DomainId,
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

    /// If given request is already in the database, returns false.
    /// Otherwise, inserts the request and returns true.
    pub fn add(&self, request: &CKDRequest) -> bool {
        let key = borsh::to_vec(&request.id).unwrap();
        if self
            .db
            .get(DBCol::CKDRequest, &key)
            .expect("Unrecoverable error reading from database")
            .is_some()
        {
            return false;
        }
        let value_ser = serde_json::to_vec(&request).unwrap();
        let mut update = self.db.update();
        update.put(DBCol::CKDRequest, &key, &value_ser);
        update
            .commit()
            .expect("Unrecoverable error writing to database");
        let _ = self.add_sender.send(request.id);
        true
    }

    /// Blocks until a ckd request with given id is present, then returns it.
    /// This behavior is necessary because a peer might initiate computation for a ckd
    /// request before our indexer has caught up to the request. We need proof of the request
    /// from on-chain in order to participate in the computation.
    pub async fn get(&self, id: CKDId) -> Result<CKDRequest, anyhow::Error> {
        let key = borsh::to_vec(&id)?;
        let mut rx = self.add_sender.subscribe();
        if let Some(request_ser) = self.db.get(DBCol::CKDRequest, &key)? {
            return Ok(serde_json::from_slice(&request_ser)?);
        }
        loop {
            let added_id = match rx.recv().await {
                Ok(added_id) => added_id,
                Err(e) => {
                    metrics::CKD_REQUEST_CHANNEL_FAILED.inc();
                    return Err(anyhow::anyhow!("Error in ckd_request channel recv, {}", e));
                }
            };
            if added_id == id {
                break;
            }
        }
        let request_ser = self.db.get(DBCol::CKDRequest, &key)?.unwrap();
        Ok(serde_json::from_slice(&request_ser)?)
    }
}
