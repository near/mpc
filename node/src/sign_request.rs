use crate::config::MpcConfig;
use crate::db::{DBCol, SecretDB};
use crate::primitives::ParticipantId;

use k256::sha2::{Digest, Sha256};
use k256::Scalar;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;

pub type SignatureId = [u8; 32];

#[derive(Serialize, Deserialize)]
pub struct SignatureRequest {
    pub id: SignatureId,
    pub msg_hash: Scalar,
    pub tweak: Scalar,
    pub entropy: [u8; 32],
    pub timestamp_nanosec: u64,
}

pub struct SignRequestStorage {
    db: Arc<SecretDB>,
    add_sender: broadcast::Sender<SignatureId>,
}

impl SignRequestStorage {
    pub fn new(db: Arc<SecretDB>) -> anyhow::Result<Self> {
        let (tx, _) = tokio::sync::broadcast::channel(10);
        Ok(Self { db, add_sender: tx })
    }

    /// If given request is already in the database, returns false.
    /// Otherwise, inserts the request and returns true.
    pub fn add(&self, request: &SignatureRequest) -> bool {
        let key = borsh::to_vec(&request.id).unwrap();
        if self
            .db
            .get(DBCol::SignRequest, &key)
            .expect("Unrecoverable error reading from database")
            .is_some()
        {
            return false;
        }
        let value_ser = serde_json::to_vec(&request).unwrap();
        let mut update = self.db.update();
        update.put(DBCol::SignRequest, &key, &value_ser);
        update
            .commit()
            .expect("Unrecoverable error writing to database");
        let _ = self.add_sender.send(request.id);
        true
    }

    /// Blocks until a signature request with given id is present, then returns it.
    /// This behavior is necessary because a peer might initiate computation for a signature
    /// request before our indexer has caught up to the request. We need proof of the request
    /// from on-chain in order to participate in the computation.
    pub async fn get(&self, id: SignatureId) -> Result<SignatureRequest, anyhow::Error> {
        let key = borsh::to_vec(&id)?;
        let mut rx = self.add_sender.subscribe();
        if let Some(request_ser) = self.db.get(DBCol::SignRequest, &key)? {
            return Ok(serde_json::from_slice(&request_ser)?);
        }
        while let Ok(added_id) = rx.recv().await {
            if added_id == id {
                break;
            }
        }
        let request_ser = self.db.get(DBCol::SignRequest, &key)?.unwrap();
        Ok(serde_json::from_slice(&request_ser)?)
    }
}

fn compute_hash(participant_id: &ParticipantId, signature_request_id: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(participant_id.raw().to_le_bytes());
    h.update(signature_request_id);
    h.finalize().into()
}

// A simple strategy for picking exactly one leader per request.
// Note that if the chosen leader is offline the request will not be served.
pub fn local_node_is_leader(config: &MpcConfig, request: &SignatureRequest) -> bool {
    let my_hash = compute_hash(&config.my_participant_id, &request.id);
    for participant in &config.participants.participants {
        if compute_hash(&participant.id, &request.id) < my_hash {
            return false;
        }
    }
    true
}
