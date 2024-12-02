use crate::db::{DBCol, SecretDB};
use k256::Scalar;

use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
pub struct SignatureRequest {
    pub id: [u8; 32],
    pub msg_hash: Scalar,
    pub tweak: Scalar,
    pub entropy: [u8; 32],
    pub timestamp_nanosec: u64,
}

pub struct SignRequestStorage {
    db: Arc<SecretDB>,
}

impl SignRequestStorage {
    pub fn new(db: Arc<SecretDB>) -> anyhow::Result<Self> {
        Ok(Self { db })
    }

    /// If given request is already in the database, returns false.
    /// Otherwise, inserts the request and returns true.
    pub fn add(&self, request: SignatureRequest) -> bool {
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
        return true;
    }
}
